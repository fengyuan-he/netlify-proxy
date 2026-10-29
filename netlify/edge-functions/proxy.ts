// Netlify Edge Function —— React Router v8 SSR 反向代理（源站 Cloudflare Workers）
// 部署方式不变：环境变量 TARGET_URL=https://xn--fpr224a.mom，路由仍由 netlify.toml 的
// [[edge_functions]] 指定（本文件故意不再 export config，避免和现有配置打架）。
//
// ── 关键决策（每条一句话理由）───────────────────────────────────────────────
// 1. 目标地址只来自环境变量并校验成 URL：请求路径永远拼在 host 之后，天然堵死开放代理与 SSRF。
// 2. 缓存键只拆三个维度（主题 / 老内核 / 规范化 path+query）：这三者才是会让源站吐出不同 HTML 的维度，多拆只会掉命中率。
// 3. 可缓存请求一律强制 accept-encoding: gzip：匿名 HTML 只有一种编码，彻底消灭「br 条目发给只认 gzip 的客户端」的串味。
// 4. 不接受 gzip 的客户端不进缓存：否则它照样会命中 gzip 条目，第 3 条就白做了。
// 5. 带 utm_* 等跟踪参数的请求「可读不可写」：链接上的参数源站看得见，不拦就会把带参数的渲染结果写成规范条目。
// 6. SWR 刷新回源用规范化 URL：写回的条目必须和 key 完全同源，不能受「触发这次刷新的那个请求」影响。
// 7. 匿名桶不收带 cookie / authorization / range / upgrade 的请求：匿名缓存不允许靠近任何可能带登录态的内容。
//    （带 zhuge_session 的 GET 只可能走用户桶，两档键空间不相交，见第 25 条。）
// 8. 响应带 Set-Cookie 时一律不写缓存：这是「本次响应有状态」的最强信号（用户桶同样适用）。
// 9. 源站 private, no-cache 仍然可存：匿名 HTML 固定这么返回，拒绝它等于没有缓存；匿名性由第 5/7/8 条保证。
// 10. 写缓存/命中路径都删掉 content-length：body 过了 tee、存、再取，任何 framing 变化都不该让旧长度生效。
// 11. cache.put 失败立刻 cancel 掉 tee 的另一半：不消费的分支会把客户端分支一起反压住并涨内存。
// 12. 条目 TTL(18min) 必须大于 stale-if-error 窗口(15min)：否则最需要兜底的那一刻条目正好过期。
// 13. 超出兜底窗口也不马上 cancel 旧条目：先当 5xx/超时的最后副本，确认拿到新响应后再取消。
// 14. 请求和响应都删逐跳头：connection / transfer-encoding 这类头再发一次会破坏 framing。
// 15. Location 先 URL 解析再比对 host 才改写：相对、绝对、协议相对 //、http 方案全覆盖，且不会把 .evil.com 当自己人。
// 16. Set-Cookie 统一剥掉 Domain：不剥浏览器会因为域不匹配拒写，或者把 cookie 带到错误的域上。
// 17. Origin/Referer 只在「指向代理自己」时改写：满足 .data POST 的同源校验，又不把 Origin: null 洗白成合法来源。
// 18. 回源只做 15s 的「响应头超时」，拿到头就清定时器：慢源站不能让用户无限等，超时也不该把正常流砍断。
// 19. POST body 继续用 arrayBuffer()：Netlify/Deno 上流式 body + duplex 未验证，整包读入是已验证路径。
// 20. redirect: "manual" 继续保留：3xx 必须原样交给浏览器，Location 由我们自己改写。
// 21. 带哈希的静态资源加 immutable 长缓存：换入口的意义就是让浏览器下次根本不再经过这个函数。
// 22. waitUntil 外面包 try：本地 netlify dev 或老运行时没有 waitUntil 时不能因此 500。
// 23. 缓存名带版本号 v4：本次键/编码语义变了，不换名会读到旧 br 条目（用户名保持 anon 前缀只为不动线上条目，两档靠键空间隔离）。
// 24. 表单/认证/API 路径进黑名单：内嵌 CSRF token 或一次性 nonce 的页面被缓存会把全员 token 冻在旧值上。
//
// ── 第三档（成员级缓存）─────────────────────────────────────────────────────
// 25. 三档分流只在 classifyTier 一处判定：请求自己能决定的（方法 / cookie / accept）在回源前定档，
//     只有「响应能不能进用户桶」必须等源站响应头，所以两档流程不同，别混。
// 26. 用户桶的入桶资格只由源站 X-Zhuge-Cache-Tier: user 决定，且必须严格相等：
//     代理不做任何登录态推断，源站说不是就不是（bypass）。
//     读缓存可以先行（否则 hit-user/stale-user 这条观测永远不可能出现），但「写」必须等看到响应头。
// 27. 用户桶键里的 epoch 在回源前读一次就冻结：回源期间若发生写操作，旧 HTML 只会写进旧 epoch，不会污染新 epoch。
// 28. 任何非 GET 成功（status < 400）都先 await 递增 epoch 再返回响应：否则浏览器紧接着的 GET 会读到写之前的旧 epoch。
// 29. epoch 条目 TTL(7d) 远大于页面 TTL：epoch 条目若被淘汰会回落到 0，页面条目必须先于它消失（页面 12min 就过期）。
// 30. 用户桶同样强制 accept-encoding: gzip 且要求客户端接受 gzip：桶里只有一种编码，否则同一用户会拿到 br 条目。
// 31. 用户桶 TTL(12min) 必须大于 hard-stale 窗口(10min)：理由同第 12 条。
// 32. 用户桶键里的 uidHash 只是 sha256(cookie 值) 前 16 位、不验签不解析：代理没有 SESSION_SECRET，也不需要。
// 33. X-Zhuge-Cache-Tier 只做内部信号，回浏览器前删干净；对外只暴露 x-proxy-cache / x-proxy-user(8 位) / x-proxy-epoch。
//     注意：源站另有一个 X-Zhuge-Cache（值为 hit，表示 Workers 边缘缓存命中），那是它自己的观测头，本文件不碰、也不据此判档。
// 34. 用户桶命中时照旧回放源站原始 cache-control（通常 private, no-cache）：浏览器与 CDN 不得二次共享这份 HTML。
// 35. Server-Timing 只在「本次真的回源」时透传源站段：缓存回放里的旧 d1/ssr/app 是上一次回源的数，
//     透传等于把旧数冒充本次；本代理的 proxy;dur 每次都追加（缓存命中 = 整个函数耗时）。
//
// ── 三路竞速 + cacheMs 打点（2026-10-29）────────────────────────────────────
// 36. GET 一律「缓存 + 两路回源」三路竞速，谁先成功用谁：慢的那一路（尤其卡住的 Cache API）不再拖住用户，
//     同时 cacheMs 把「进函数 → 缓存查询结束」单独报出来，回溯 11s 到底卡在缓存还是建连。
// 37. 非 GET 一律不竞速：写操作翻倍且无法取消，只能原样单路。
// 38. 缓存命中时也照样白跑两路回源（发起后立刻 abort）：这是站主明确接受的代价，换来的是「缓存慢也不慢」。
// ────────────────────────────────────────────────────────────────────────────

import type { Context } from "@netlify/edge-functions";

const TARGET_RAW: string = (Deno.env.get("TARGET_URL") ?? "").trim();

let TARGET_URL: URL | null = null;
try {
  if (TARGET_RAW.length > 0) TARGET_URL = new URL(TARGET_RAW);
} catch {
  TARGET_URL = null;
}

const TARGET_ORIGIN: string = TARGET_URL ? TARGET_URL.origin : "";
const TARGET_HOST: string = TARGET_URL ? TARGET_URL.host : "";
const TARGET_BASE: string = TARGET_URL
  ? `${TARGET_URL.origin}${TARGET_URL.pathname.replace(/\/+$/, "")}`
  : "";

const CACHE_VERSION = "v4";
const CACHE_NAME = `zhuge-anon-${CACHE_VERSION}-${Deno.env.get("BUILD_ID") ?? "static"}`;

// 匿名档窗口（2026-10-29 放大：批量探测 305 节点并发要能落在同一个热条目上）
// 注意：这组常量是**匿名档专属**，成员档用下面独立的 USER_* 一组，改这里不影响成员档。
const FRESH_MS = 300_000; // 5min：命中即回，不再回源
const SWR_MS = 600_000; // 10min：命中旧副本 + 后台刷新
const HARD_STALE_MS = 900_000; // 15min：只在源站 5xx/超时时才肯拿出来的最旧副本
const STORE_TTL_S = 1_080; // 18min：必须 > HARD_STALE_MS，否则兜底时条目已经没了

// 用户桶窗口：更宽松，但失效靠 epoch 而不是靠时间
const USER_FRESH_MS = 120_000; // 120s
const USER_SWR_MS = 300_000; // 300s
const USER_HARD_STALE_MS = 600_000; // 600s
const USER_STORE_TTL_S = 720; // 必须 > USER_HARD_STALE_MS
const EPOCH_TTL_S = 7 * 24 * 3_600; // epoch 条目必须活得比任何页面条目都久

const ORIGIN_TIMEOUT_MS = 15_000; // 只卡响应头
const MAX_QUERY_PARAMS = 6; // 防随机参数把缓存打爆
const OLD_CHROME_BELOW = 88; // 必须与源站阈值一致
const DEFAULT_CC = "private, no-cache";

// 用户桶：cookie 名、hash 长度、对外暴露的 uid 前缀长度
const SESSION_COOKIE = "zhuge_session";
const UID_HASH_HEX_LEN = 16; // sha256 前 16 个十六进制字符（64bit），足够区分用户
const USER_TAG_LEN = 8; // 只对外露出 8 位，绝不出完整 hash / 完整 cookie

const BORN = "x-proxy-born";
const ORIGIN_CC = "x-proxy-origin-cc";
const CACHE_STATE = "x-proxy-cache";
const CACHE_AGE = "x-proxy-age";
const USER_STATE = "x-proxy-user";
const EPOCH_STATE = "x-proxy-epoch";

// 源站用来声明「这份 HTML 可以按用户缓存」的响应头，只做内部信号，绝不回传浏览器。
// 注意与源站原有的 X-Zhuge-Cache（值 hit = Workers 边缘缓存命中）区分：那个头我们既不读也不删。
const ORIGIN_USER_MARK = "x-zhuge-cache-tier";

// 注意：这两个正则都没有 g 标志，.test() 无状态，可以反复调用。
const TRACKING_PARAMS = /^(?:utm_[a-z0-9_]*|fbclid|gclid|dclid|msclkid|yclid|spm|scm|igshid|_ga)$/i;
const SENSITIVE_PARAMS =
  /^(?:token|key|code|email|sig|signature|session|auth|password|reset|invite|secret|state)$/i;

const PRIVATE_PATH_PREFIXES: readonly string[] = [
  "/api",
  "/admin",
  "/account",
  "/checkout",
  "/cart",
  "/settings",
  "/orders",
  "/login",
  "/logout",
  "/signin",
  "/signup",
  "/register",
];

const HOP_BY_HOP: readonly string[] = [
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
];

// 这些请求头由我们重算，绝不透传客户端伪造值。
const REQUEST_HEADERS_TO_REBUILD: readonly string[] = [
  "content-length",
  "expect",
  "forwarded",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
];

const NULL_BODY_STATUS: ReadonlySet<number> = new Set([204, 205, 304]);

const IMMUTABLE_ASSET =
  /^\/assets\/[^/]*-[A-Za-z0-9_-]{8,}\.(?:js|mjs|css|map|woff2?|ttf|otf|png|jpe?g|gif|svg|webp|avif|ico)$/i;

const refreshing = new Set<string>();

/** 三档：匿名桶 / 用户桶 / 直连。 */
type CacheTier = "anon" | "user" | "bypass";

type StaleHit = { res: Response; ageMs: number };
type OriginOutput = { response: Response; stored?: Promise<void> };

/** 一份响应要写进哪一档缓存：TTL、是否需要源站打标、写入时的观测值都由它带过去。 */
type StorePlan = {
  cache: Cache;
  key: Request;
  ttlSeconds: number;
  /** 用户桶：必须看到源站 X-Zhuge-Cache-Tier: user 才允许写；匿名桶为 false。 */
  requireUserMark: boolean;
  /** 真正写入时 x-proxy-cache 的取值（miss / miss-user）。 */
  missState: string;
};

/** 只用于观测的请求上下文（用户桶）：绝不包含完整 cookie 或完整 hash。 */
type Observe = { user?: string; epoch?: number };

/**
 * 链路追踪打点（2026-10-29）：只记时间，不改任何现有逻辑。
 * 目的：定位「到底哪一段慢」—— 代理是唯一同时看得见「查缓存」与「回源」两段时间的地方。
 *   · t0      进 handler
 *   · tCache  缓存查询结束（三档都要有；直连档没有缓存查询，取 t0）
 *   · tUp     回源响应头到达（fetch 返回那一刻）
 *   · tEnd    返回响应前（在 handler 里算）
 * 上报是 fire-and-forget（ctx.waitUntil + fetch().catch），绝不 await，失败完全静默。
 */
type Trace = {
  t0: number;
  /** 缓存查询结束；直连档没有缓存查询，取 t0。 */
  tCache?: number;
  /** 发起回源 fetch 的时刻；没有回源（缓存命中）时为空。 */
  tFetch?: number;
  /** 回源响应头到达（fetch 返回那一刻）；竞速时 = 赢家那一路的耗时。 */
  tUp?: number;
  /** 回源响应头 cf-ray 的后缀（`a51a…-HKG` → `HKG`），拿不到就是 `?`。 */
  colo?: string;
  /** 三路竞速的赢家；没竞速（非 GET）时是 `none`。 */
  race?: "cache" | "origin1" | "origin2" | "none";
  /** 缓存查询最终完成（即使响应已经返回）：回源先赢时用它补报真实的 cacheMs。 */
  cacheSettled?: Promise<void>;
};

/** 慢请求判定阈值：上游 > 800ms 或 总时长 > 2000ms 必报；其余按 2% 随机采样对照。 */
const TRACE_UP_SLOW_MS = 800;
const TRACE_TOTAL_SLOW_MS = 2_000;
const TRACE_SAMPLE_RATE = 0.02;

/**
 * path 归一化（**必须与源站 `app/routes/api.trace.tsx` 的 normalizeTracePath 逐字一致**）：
 * 代理先做一次，源站再兜一次，防漏。规则：
 *   ① 只保留 pathname（`?query` / `#hash` 丢掉）；② 去空白与控制字符；
 *   ③ 含数字的段 → `*`；④ 实体前缀下的第一段动态位 → `*`（`/character/abc` → `/character/*`）；
 *   ⑤ `/`、`/messages` 这类静态段原样保留；重复斜杠折叠；最长 120 字。
 */
const TRACE_ENTITY_ROOTS: ReadonlySet<string> = new Set([
  "post",
  "character",
  "user",
  "space",
  "u",
  "tag",
]);

function normalizeTracePath(raw: string): string {
  let value = String(raw ?? "").slice(0, 2048);
  const cut = value.search(/[?#]/);
  if (cut >= 0) value = value.slice(0, cut);
  value = value.replace(/[\s\u0000-\u001f\u007f]+/g, "");
  if (!value.startsWith("/")) value = `/${value}`;

  const segments = value.split("/");
  // segments[0] 是空串、segments[1] 是根段，所以动态位从 2 开始。
  for (let i = 2; i < segments.length; i += 1) {
    const segment = segments[i] ?? "";
    if (segment.length === 0) continue;
    if (/\d/.test(segment)) segments[i] = "*";
    else if (i === 2 && TRACE_ENTITY_ROOTS.has(segments[1] ?? "")) segments[i] = "*";
  }

  const out = segments.join("/").replace(/\/{2,}/g, "/");
  return out.slice(0, 120) || "/";
}

/** 只发源站白名单里的六种档位；stale-error 归 stale，没有状态头（502）记 `?`。 */
function traceCacheState(raw: string | null): string {
  const value = (raw ?? "").trim();
  if (
    value === "hit" ||
    value === "stale" ||
    value === "miss" ||
    value === "bypass" ||
    value === "hit-user" ||
    value === "miss-user"
  ) {
    return value;
  }
  return value.startsWith("stale") ? "stale" : "?";
}

/** 从回源响应头 `cf-ray`（形如 `a51a…-HKG`）取机房后缀；拿不到 / 不合格式都回 `?`。 */
function traceColo(res: Response): string {
  const match = /-([A-Z]{3})$/.exec((res.headers.get("cf-ray") ?? "").trim());
  return match !== null && match[1] !== undefined ? match[1] : "?";
}

/** fire-and-forget 上报：绝不 await、绝不改响应、失败完全静默（第 4 条）。 */
function reportTrace(
  ctx: Context,
  trace: Trace,
  requestUrl: URL,
  cache: string,
  upstreamMs: number,
  totalMs: number,
  proxyMs: number,
  cacheMs: number,
  race: string,
): void {
  if (TARGET_BASE.length === 0) return;
  try {
    const path = normalizeTracePath(requestUrl.pathname);
    const body = JSON.stringify({
      path,
      cache,
      upstreamMs,
      totalMs,
      // 2026-10-29：本代理自身耗时（Server-Timing 的 proxy;dur 同源），
      // 源站 /api/trace 只是多收一个字段（它容忍多余字段），用来按天看趋势。
      proxyMs,
      // 2026-10-29：进函数 → 缓存查询结束（含 caches.open / match，用户档还含 epoch 读取）。
      // 直连档没有缓存查询，恒为 0。
      cacheMs,
      // 2026-10-29：三路竞速的赢家（cache / origin1 / origin2）；非 GET 没竞速，记 none。
      race,
      colo: trace.colo ?? "?",
    });
    // 一行结构化日志：Netlify 函数日志里 grep `[trace]` 就能直接看出慢在哪一段。
    console.log(
      `[trace] cache=${cache} up=${upstreamMs}ms total=${totalMs}ms proxy=${proxyMs}ms cacheMs=${cacheMs}ms colo=${trace.colo ?? "?"} path=${path}`,
    );
    // 先把请求发出去，再尝试挂到 waitUntil 上：补报（响应已经交出后才上报）时
    // waitUntil 窗口可能已经关了，此时请求至少已经发出，不会被这段 try 吞掉。
    const send = fetch(`${TARGET_BASE}/api/trace`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    }).catch(() => {});
    try {
      ctx.waitUntil(send);
    } catch {
      // 窗口已关：send 已经在飞，能到就到
    }
  } catch {
    // 没有 waitUntil 的运行时 / fetch 同步抛错：埋点失败绝不影响用户响应
  }
}

type RefreshJob = {
  request: Request;
  url: URL;
  key: Request;
  plan: StorePlan;
  observe?: Observe;
};

/* ── 小工具 ─────────────────────────────────────────────────────────────── */

function text(status: number, message: string): Response {
  return new Response(message, {
    status,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}

async function discard(res: Response | null | undefined): Promise<void> {
  try {
    await res?.body?.cancel();
  } catch {
    // 已经 cancel 过 / 已被锁定：重复取消会 reject，这里吞掉即可。
  }
}

function waitUntil(ctx: Context, promise: Promise<unknown>): void {
  // 统一收敛成 Promise<void>：兼容 Context.waitUntil 的两种签名（Promise<void> / Promise<unknown>）。
  const guarded: Promise<void> = Promise.resolve(promise)
    .then(() => undefined)
    .catch(() => {});
  try {
    ctx.waitUntil(guarded);
  } catch {
    // 没有 waitUntil 的运行时：任务照样跑，只是不再延长函数生命周期。
  }
}

function applyObserve(headers: Headers, observe: Observe | undefined): void {
  if (observe === undefined) return;
  if (observe.user !== undefined) headers.set(USER_STATE, observe.user);
  if (observe.epoch !== undefined) headers.set(EPOCH_STATE, String(observe.epoch));
}

/* ── 请求判定 / 缓存键 ───────────────────────────────────────────────────── */

function acceptsGzip(header: string): boolean {
  if (header.trim().length === 0) return false;
  for (const part of header.split(",")) {
    const segments = part.split(";");
    const coding = (segments[0] ?? "").trim().toLowerCase();
    if (coding !== "gzip" && coding !== "*") continue;
    let rejected = false;
    for (let i = 1; i < segments.length; i += 1) {
      const pair = (segments[i] ?? "").split("=");
      if ((pair[0] ?? "").trim().toLowerCase() === "q" && Number(pair[1]) === 0) rejected = true;
    }
    if (!rejected) return true;
  }
  return false;
}

function isOldEngine(userAgent: string): boolean {
  if (/\b(?:Trident|MSIE)\b/.test(userAgent)) return true;
  const match = /\b(?:Chrome|Chromium|CriOS)\/(\d+)/.exec(userAgent);
  if (match !== null) return Number(match[1]) < OLD_CHROME_BELOW;
  return false;
}

function canonicalQuery(url: URL): string {
  const pairs: Array<[string, string]> = [];
  url.searchParams.forEach((value, name) => {
    if (!TRACKING_PARAMS.test(name)) pairs.push([name, value]);
  });
  pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)); // sort 稳定，重复键保持原顺序
  return new URLSearchParams(pairs).toString();
}

function hasTrackingParams(url: URL): boolean {
  let found = false;
  url.searchParams.forEach((_value, name) => {
    if (TRACKING_PARAMS.test(name)) found = true;
  });
  return found;
}

function canonicalUrl(url: URL): URL {
  const next = new URL(url.href);
  const qs = canonicalQuery(url);
  next.search = qs.length > 0 ? `?${qs}` : "";
  return next;
}

/** 只从 cookie 头里取 zhuge_session 的值：不解析、不验签、不 urlDecode。 */
function readSessionCookie(request: Request): string | null {
  const raw = request.headers.get("cookie");
  if (raw === null || raw.length === 0) return null;
  for (const part of raw.split(";")) {
    const segment = part.trim();
    if (segment.length === 0) continue;
    const eq = segment.indexOf("=");
    if (eq < 0) continue;
    if (segment.slice(0, eq).trim() !== SESSION_COOKIE) continue;
    // base64 值里可能自带 "="，所以只切第一个。
    const value = segment.slice(eq + 1).trim();
    return value.length > 0 ? value : null;
  }
  return null;
}

/** 路径 / 查询参数层面「允不允许进缓存」：两档共用同一套黑名单。 */
function isCacheableTarget(url: URL): boolean {
  const path = url.pathname;
  if (path.endsWith(".data") || path.endsWith(".rsc")) return false;
  if (path.startsWith("/assets/") || path.startsWith("/img/") || path.startsWith("/cdn-cgi/")) return false;
  for (const prefix of PRIVATE_PATH_PREFIXES) {
    if (path === prefix || path.startsWith(`${prefix}/`)) return false;
  }

  const params = [...url.searchParams];
  if (params.some(([name]) => SENSITIVE_PARAMS.test(name))) return false;

  let canonicalCount = 0;
  for (const [name] of params) {
    if (!TRACKING_PARAMS.test(name)) canonicalCount += 1;
  }
  if (canonicalCount > MAX_QUERY_PARAMS) return false;

  return true;
}

/**
 * 请求是否在「要页面」：`Accept` 含 `text/html` **或** 含通配媒体类型（星号/星号）都算。
 *
 * 为什么允许通配（2026-10-29 放宽，只放宽这一条）：通配是探测工具（itdog 这类 305 节点
 * 并发的批量探活）、爬虫、curl 的默认 Accept，它们本来就不带 cookie、也拿不到任何个性化内容，
 * 却因为「没写 text/html」被判成非页面请求而全部 bypass —— 305 个节点于是各自付一次冷启动。
 * 安全性不靠这条判据兜底：带 cookie / authorization / range / upgrade 的请求在 isCacheable 里
 * 仍然硬拒绝、永远进不了匿名桶，路径黑名单也不动，所以真实用户的登录态与个性化 HTML 绝不会
 * 被共享条目命中；带 Set-Cookie 的响应同样一律不写缓存（第 8 条）。
 */
function acceptsHtml(header: string): boolean {
  const value = header.trim().toLowerCase();
  if (value.length === 0) return false;
  return value.includes("text/html") || value.includes("*/*");
}

function isCacheable(request: Request, url: URL): boolean {
  if (request.method !== "GET") return false;

  const headers = request.headers;
  if (headers.has("cookie") || headers.has("authorization") || headers.has("range") || headers.has("upgrade")) {
    return false;
  }
  // `text/html` 或 `*/*` 都算页面请求（见 acceptsHtml 里的安全说明）。
  if (!acceptsHtml(headers.get("accept") ?? "")) return false;
  // 缓存条目固定 gzip，只服务能解 gzip 的客户端。
  if (!acceptsGzip(headers.get("accept-encoding") ?? "")) return false;

  return isCacheableTarget(url);
}

/**
 * 用户桶的「请求侧」资格：cookie 里必须有 zhuge_session（由 classifyTier 先看），
 * 且同样只收 gzip（桶里只有一种编码）、同样避开私密路径与带 token 的 URL。
 * 是否真的入桶还要等源站响应头，见 processOrigin 的 requireUserMark。
 */
function isMemberCacheable(request: Request, url: URL): boolean {
  if (request.method !== "GET") return false;
  const headers = request.headers;
  if (headers.has("authorization") || headers.has("range") || headers.has("upgrade")) return false;
  if (!acceptsGzip(headers.get("accept-encoding") ?? "")) return false;
  return isCacheableTarget(url);
}

/**
 * 三档分流的唯一入口。
 * anon：GET + 无 cookie + Accept 含 text/html 或通配媒体类型（安全说明见 acceptsHtml）+ 接受 gzip
 * user：GET + 带 zhuge_session（是否入桶由源站 X-Zhuge-Cache-Tier 决定）
 * bypass：其余全部
 */
function classifyTier(request: Request, url: URL): CacheTier {
  if (request.method !== "GET") return "bypass";
  if (readSessionCookie(request) !== null) {
    return isMemberCacheable(request, url) ? "user" : "bypass";
  }
  return isCacheable(request, url) ? "anon" : "bypass";
}

function bucketDimensions(request: Request): { theme: string; engine: string } {
  const theme = request.headers.get("sec-ch-prefers-color-scheme") === "dark" ? "dark" : "light";
  const engine = isOldEngine(request.headers.get("user-agent") ?? "") ? "old" : "new";
  return { theme, engine };
}

function cacheIdPath(url: URL): string {
  const qs = canonicalQuery(url);
  // pathname 来自 new URL()，已是百分号编码，所以键与原路径一一对应，不会撞车。
  return `${url.pathname}${qs.length > 0 ? `?${qs}` : ""}`;
}

function buildCacheKey(request: Request, url: URL): Request {
  const { theme, engine } = bucketDimensions(request);
  const id = `https://cache.invalid/${theme}/${engine}${cacheIdPath(url)}`;
  return new Request(id, { method: "GET" });
}

/**
 * 用户桶键：https://cache.invalid/{uidHash}/{epoch}/{theme}/{engine}{path}?query
 * 第一段是 16 位十六进制，匿名键第一段是 light/dark，两个键空间不会撞。
 */
function buildUserCacheKey(request: Request, url: URL, uidHash: string, epoch: number): Request {
  const { theme, engine } = bucketDimensions(request);
  const id = `https://cache.invalid/${uidHash}/${epoch}/${theme}/${engine}${cacheIdPath(url)}`;
  return new Request(id, { method: "GET" });
}

/** epoch 条目键：https://cache.invalid/ep/{uidHash}（"ep" 不是 16 进制，天然不与页面键冲突） */
function buildEpochKey(uidHash: string): Request {
  return new Request(`https://cache.invalid/ep/${uidHash}`, { method: "GET" });
}

/* ── 用户身份 hash / epoch ──────────────────────────────────────────────── */

async function sha256Hex(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  let hex = "";
  for (const byte of new Uint8Array(digest)) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

async function uidHashOf(sessionValue: string): Promise<string> {
  return (await sha256Hex(sessionValue)).slice(0, UID_HASH_HEX_LEN);
}

/** 读 epoch：键缺失 / 内容不是十进制数 / 缓存炸了 一律当 0。 */
async function readEpoch(cache: Cache, uidHash: string): Promise<number> {
  try {
    const hit = await cache.match(buildEpochKey(uidHash));
    if (hit === undefined || hit === null) return 0;
    const raw = (await hit.text()).trim();
    const value = Number.parseInt(raw, 10);
    return Number.isFinite(value) && value >= 0 ? value : 0;
  } catch {
    return 0;
  }
}

/** epoch + 1 写回。失败只影响这次失效，绝不影响写请求本身。 */
async function bumpEpoch(cache: Cache, uidHash: string): Promise<void> {
  try {
    const next = (await readEpoch(cache, uidHash)) + 1;
    const body = new Response(String(next), {
      status: 200,
      headers: {
        "content-type": "text/plain; charset=utf-8",
        "cache-control": `public, max-age=${EPOCH_TTL_S}`,
      },
    });
    await cache.put(buildEpochKey(uidHash), body);
  } catch {
    // 缓存不可用时这次失效落空，但页面 TTL 会把陈旧窗口限制在 12min 内
  }
}

/** 写操作成功后调用：拿请求上的 session 算用户，再把该用户 epoch 推一格。 */
async function bumpEpochForRequest(request: Request): Promise<void> {
  const session = readSessionCookie(request);
  if (session === null) return;
  try {
    const uidHash = await uidHashOf(session);
    const cache = await caches.open(CACHE_NAME);
    await bumpEpoch(cache, uidHash);
  } catch {
    // 抓不到缓存 / 没有 crypto：写请求照常成功，只是这次失效没生效
  }
}

/* ── 回源 ───────────────────────────────────────────────────────────────── */

type OriginOptions = {
  /** 强制 accept-encoding: gzip（缓存档必须，保证桶里只有一种编码）。 */
  forceGzip: boolean;
  /** 用「自身地址」做 referer：确定性，避免把别处的来源写进缓存。 */
  canonicalReferer: boolean;
  /** 竞速时由每一路自己的 controller 提供：外部 abort 会连带 abort 这里 15s 的超时定时器。 */
  signal?: AbortSignal;
};

async function fetchOrigin(request: Request, url: URL, options: OriginOptions): Promise<Response> {
  const proxyOrigin = new URL(request.url).origin;

  const headers = new Headers();
  request.headers.forEach((value, name) => {
    const key = name.toLowerCase();
    if (HOP_BY_HOP.includes(key)) return;
    if (REQUEST_HEADERS_TO_REBUILD.includes(key)) return;
    if (key === "host") return;
    headers.append(key, value);
  });

  // Host 不显式设置：我们 fetch 的 URL 就是目标域，Host 由运行时按 URL 生成；
  // 手动 set 在某些运行时会被当非法头拒绝，而这一行本来也没有额外收益。
  // （客户端传来的 host 已经在上面被跳过，不会被带过去。）

  if (options.forceGzip) {
    headers.set("accept-encoding", "gzip");
    headers.delete("if-none-match");
    headers.delete("if-modified-since");
    headers.delete("if-range");
  }

  const origin = request.headers.get("origin");
  if (origin !== null && origin === proxyOrigin) headers.set("origin", TARGET_ORIGIN);

  const referer = headers.get("referer");
  if (referer !== null) {
    if (options.canonicalReferer) {
      headers.set("referer", `${TARGET_ORIGIN}${url.pathname}${url.search}`);
    } else if (referer === proxyOrigin || referer.startsWith(`${proxyOrigin}/`)) {
      headers.set("referer", `${TARGET_ORIGIN}${referer.slice(proxyOrigin.length)}`);
    }
  }

  const clientIp = request.headers.get("x-nf-client-connection-ip");
  if (clientIp !== null && clientIp.length > 0) headers.set("x-forwarded-for", clientIp);
  headers.set("x-forwarded-host", TARGET_HOST);
  headers.set("x-forwarded-proto", "https");

  const target = `${TARGET_BASE}${url.pathname}${url.search}`;
  const hasBody = request.method !== "GET" && request.method !== "HEAD";
  const payload = hasBody ? await request.arrayBuffer() : undefined;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ORIGIN_TIMEOUT_MS);
  // 竞速时外面那一个 controller 也要能立刻掐断这一路；两边的 abort 合流到同一个 controller。
  const external = options.signal;
  const onExternalAbort = (): void => controller.abort();
  if (external !== undefined) {
    if (external.aborted) controller.abort();
    else external.addEventListener("abort", onExternalAbort, { once: true });
  }
  try {
    return await fetch(target, {
      method: request.method,
      headers,
      body: payload,
      redirect: "manual",
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer); // 只做响应头超时，body 继续正常流式读取
    external?.removeEventListener("abort", onExternalAbort);
  }
}

/* ── 三路竞速：缓存 + 两路回源（2026-10-29）─────────────────────────────── */

type OriginWinner = { res: Response; label: "origin1" | "origin2"; ms: number };

type OriginRace = {
  /** 第一路成功返回的回源（含它自己的耗时）；两路都失败时 reject，错误原样交给调用方。 */
  winner: Promise<OriginWinner>;
  /** 缓存先赢 / 已经不用回源：立刻 abort 两路里还没回来的那些（缓存本身没法 abort，忽略即可）。 */
  abort: () => void;
};

/**
 * 启动两路回源竞速（只给 GET 用）：
 *   o1 = fetchOrigin(req)
 *   o2 = fetchOrigin(req.clone())
 * 谁先成功用谁，赢家一出现立刻 abort 另外一路。
 * 失败不在这里吞：两路都 reject 时 winner 也 reject，调用方照旧走 502 / stale 错误路径。
 */
function startOriginRace(request: Request, url: URL, options: OriginOptions): OriginRace {
  const labels = ["origin1", "origin2"] as const;
  const controllers: AbortController[] = [new AbortController(), new AbortController()];
  let decided = false;
  let abandoned = false;
  let settledWinner: OriginWinner | null = null;

  const legs: Array<Promise<OriginWinner>> = controllers.map((controller, index) => {
    // 第二路用 clone：两路各消费自己的 body（GET 没有 body，这里照样 clone，
    // 免得以后被复用到带 body 的方法上时两路互相锁死）。
    const attempt = index === 0 ? request : request.clone();
    const startedAt = Date.now();
    return fetchOrigin(attempt, url, { ...options, signal: controller.signal }).then((res) => {
      const value: OriginWinner = {
        res,
        label: labels[index] as "origin1" | "origin2",
        ms: Math.max(0, Date.now() - startedAt),
      };
      if (decided) {
        // 已经有人赢了：这一路白跑，body 立刻取消，别留一条没人读的流。
        void discard(res);
      } else {
        decided = true;
        // 赢家出现 → 立刻 abort 另一路；缓存那一路没法 abort，忽略。
        for (let i = 0; i < controllers.length; i += 1) {
          if (i !== index) controllers[i]?.abort();
        }
      }
      return value;
    });
  });

  const winner = Promise.any(legs);
  // 缓存先赢时两路都会被 abort（两路都 reject）：这里先挂处理器，避免 unhandled rejection。
  void winner.then(
    (value) => {
      settledWinner = value;
      if (abandoned) void discard(value.res);
    },
    () => undefined,
  );

  return {
    winner,
    abort: () => {
      abandoned = true;
      for (const controller of controllers) controller.abort();
      if (settledWinner !== null) void discard(settledWinner.res);
    },
  };
}

type CacheHit = { res: Response; state: string; ageMs: number };

type CacheProbe = {
  /** 命中且能直接回放（fresh / SWR）：缓存赢。 */
  hit?: CacheHit;
  /** 硬过期窗口内的旧副本：不赢，只在回源出错时兜底。 */
  stale?: StaleHit;
  /** 写缓存计划；null = 本次不写（打不开缓存 / 带跟踪参数 / 缓存还没就绪）。 */
  plan: StorePlan | null;
  /** 用户桶的 x-proxy-user / x-proxy-epoch 观测值（匿名档为 undefined）。 */
  observe?: Observe;
};

type RaceDecision =
  | { kind: "cache"; hit: CacheHit; probe: CacheProbe }
  | { kind: "origin"; winner: OriginWinner; probe: CacheProbe | null }
  | { kind: "origin-failed"; probe: CacheProbe | null };

/** 竞速里用不到的缓存探测结果：把 body 放掉，别留两条没人读的流。 */
function discardProbe(probe: CacheProbe): void {
  if (probe.hit !== undefined) void discard(probe.hit.res);
  if (probe.stale !== undefined) void discard(probe.stale.res);
}

/**
 * 三路竞速的判定：缓存（probeP）与两路回源（race.winner）谁先给出可用结果。
 *   · 缓存先赢（有可回放的命中）→ abort 两路回源，交给调用方回放；
 *   · 回源先赢 → 另一路在 startOriginRace 里已经 abort；缓存没法 abort，忽略即可；
 *   · 两路回源都失败 → 交给调用方走原来的错误路径。
 */
async function decideRace(race: OriginRace, probeP: Promise<CacheProbe>): Promise<RaceDecision> {
  // 先挂快照：下面竞速用的 .then 挂得比它晚，所以 probe 先落地时快照一定已经有值。
  let snapshot: CacheProbe | null = null;
  const tracked = probeP.then((probe) => {
    snapshot = probe;
    return probe;
  });

  const first = await Promise.race([
    tracked.then((probe) => ({ kind: "probe" as const, probe })),
    race.winner.then(
      (winner) => ({ kind: "origin" as const, winner }),
      () => ({ kind: "failed" as const }),
    ),
  ]);

  if (first.kind === "probe") {
    if (first.probe.hit !== undefined) {
      race.abort(); // 缓存先赢：两路回源立刻 abort
      return { kind: "cache", hit: first.probe.hit, probe: first.probe };
    }
    // 没有可回放的命中（miss / 只有 stale 兜底）→ 等回源。
    try {
      return { kind: "origin", winner: await race.winner, probe: first.probe };
    } catch {
      return { kind: "origin-failed", probe: first.probe };
    }
  }

  if (first.kind === "origin") {
    if (snapshot === null) {
      // 缓存那一路还在跑：本次已经用不到它的命中，跑完把 body 放掉。
      void probeP.then(discardProbe, () => undefined);
    }
    return { kind: "origin", winner: first.winner, probe: snapshot };
  }

  return { kind: "origin-failed", probe: snapshot };
}

type OriginFinishing =
  | { kind: "response"; response: Response; stored?: Promise<void> }
  | { kind: "stale"; stale: StaleHit };

/** 回源赢家的统一收尾：stale 兜底判定 + processOrigin（写缓存逻辑原样复用）。 */
async function finishOriginRace(
  winner: OriginWinner,
  probe: CacheProbe | null,
  requestUrl: URL,
  proxyOrigin: string,
  method: string,
  observe: Observe | undefined,
  trace: Trace,
  /** probe 还没就绪时的档位状态（miss / miss-user），见 processOrigin 的参数说明。 */
  unstoredState?: string,
): Promise<OriginFinishing> {
  // up = 赢家那一路的实际耗时（从它自己发起 fetch 算起）。
  trace.tUp = (trace.tFetch ?? Date.now()) + winner.ms;
  trace.colo = traceColo(winner.res);
  trace.race = winner.label;

  if (isOriginError(winner.res.status) && probe?.stale !== undefined) {
    await discard(winner.res);
    return { kind: "stale", stale: probe.stale };
  }
  if (probe?.stale !== undefined) await discard(probe.stale.res);
  if (probe?.hit !== undefined) await discard(probe.hit.res); // 缓存后到，本次已经用回源

  const { response, stored } = processOrigin(
    winner.res,
    requestUrl,
    proxyOrigin,
    probe?.plan ?? null,
    method,
    observe,
    unstoredState,
  );
  return { kind: "response", response, stored };
}

/* ── 响应处理 ───────────────────────────────────────────────────────────── */

function getSetCookies(headers: Headers): string[] {
  const maybe = headers as unknown as { getSetCookie?: () => string[] };
  if (typeof maybe.getSetCookie === "function") {
    try {
      const list = maybe.getSetCookie();
      if (Array.isArray(list) && list.length > 0) {
        return list.filter((value) => typeof value === "string" && value.length > 0);
      }
    } catch {
      // 退回逐条收集
    }
  }
  const collected: string[] = [];
  headers.forEach((value, name) => {
    if (name.toLowerCase() === "set-cookie") collected.push(value);
  });
  if (collected.length === 0) {
    const single = headers.get("set-cookie");
    if (single !== null && single.length > 0) collected.push(single);
  }
  return collected;
}

/**
 * 源站是否声明「这份 HTML 可以按用户缓存」。
 * 严格相等：只认 "user"。绝不能退化成「有这个头就算成员」——
 * 源站另一个头 X-Zhuge-Cache 的取值是 hit（边缘缓存命中），存在即成员会把匿名响应塞进用户桶。
 * 归一化（trim/lowercase）只抹平头值两端的空白与大小写，不会让 hit 之类的值通过。
 */
function isUserMarked(headers: Headers): boolean {
  const raw = headers.get(ORIGIN_USER_MARK);
  if (raw === null) return false;
  return raw.trim().toLowerCase() === "user";
}

function isStorable(headers: Headers): boolean {
  const contentType = (headers.get("content-type") ?? "").toLowerCase();
  if (!contentType.includes("text/html")) return false;
  const cacheControl = (headers.get("cache-control") ?? "").toLowerCase();
  if (cacheControl.includes("no-store")) return false; // 只有 no-store 是硬拒绝，private/no-cache 放行
  if ((headers.get("vary") ?? "").trim() === "*") return false;
  const encoding = (headers.get("content-encoding") ?? "").trim().toLowerCase();
  if (encoding.length > 0 && encoding !== "gzip" && encoding !== "identity") return false;
  return true;
}

function rewriteLocation(headers: Headers, proxyOrigin: string): void {
  const raw = headers.get("location");
  if (raw === null) return;
  const value = raw.trim();
  if (value.length === 0) return;

  const absolute = /^[a-z][a-z0-9+.-]*:/i.test(value);
  const protocolRelative = value.startsWith("//");
  if (!absolute && !protocolRelative) return; // 相对路径由浏览器按代理域名解析，本来就正确

  try {
    const parsed = new URL(protocolRelative ? `https:${value}` : value);
    if (parsed.host !== TARGET_HOST) return; // 精确比对 host，杜绝 xn--xxx.mom.evil.com 这类前缀伪装
    headers.set("location", `${proxyOrigin}${parsed.pathname}${parsed.search}${parsed.hash}`);
  } catch {
    // 解析不了就原样放行
  }
}

function rewriteCors(headers: Headers, proxyOrigin: string): void {
  const allowOrigin = headers.get("access-control-allow-origin");
  if (allowOrigin !== null && allowOrigin === TARGET_ORIGIN) {
    headers.set("access-control-allow-origin", proxyOrigin);
  }
}

function buildResponseHeaders(res: Response, requestUrl: URL, method: string): Headers {
  const out = new Headers(res.headers);
  for (const header of HOP_BY_HOP) out.delete(header);
  out.delete(BORN);
  out.delete(ORIGIN_CC);
  out.delete(CACHE_STATE);
  out.delete(CACHE_AGE);
  out.delete(USER_STATE);
  out.delete(EPOCH_STATE);
  // 源站内部信号，绝不回传浏览器（第 33 条）
  out.delete(ORIGIN_USER_MARK);

  // 内容寻址的哈希资源可以放心 immutable：文件名变了 URL 就变了。
  if (method === "GET" && res.status === 200 && IMMUTABLE_ASSET.test(requestUrl.pathname)) {
    out.set("cache-control", "public, max-age=31536000, immutable");
  }
  return out;
}

function withBody(res: Response, headers: Headers): Response {
  if (NULL_BODY_STATUS.has(res.status)) {
    return new Response(null, { status: res.status, statusText: res.statusText, headers });
  }
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
}

/**
 * ── Server-Timing（2026-10-29）──────────────────────────────────────────────
 *
 * 目标：让一次请求能拼出完整的分段表 ——
 *   浏览器 DNS/TCP/TLS/TTFB（netcheck 已有，本文件不管）
 *   → 反代内部 `proxy;dur`（本文件）
 *   → 反代→Worker 往返（trace 的 `up`，已有）
 *   → Worker 内部 `d1` / `ssr` / `app`（源站 Server-Timing，本文件透传）。
 *
 * `proxy;dur` = 「进 handler → 拿到回源响应头」减去 `up`（回源往返），即纯代理开销：
 *   开缓存 / 算缓存键 / 算 uidHash / 收 POST body / 改 Location·Set-Cookie / tee body …
 * 没有回源（缓存命中）时 = 整个函数耗时（那时全是代理开销）。
 *
 * `total;dur` = `tEnd - t0`：**反代视角的整段服务时长**（收到请求 → 交出首字节前）。
 * 客户端拿它才能把「用户 → 反代」那段减出来：
 *   `responseStart - requestStart - total`（上行 + 排队），以及 `total - proxy` ≈ 回源往返。
 * 缓存命中 / 回源失败（502）/ 302 / 直连档都走 handler 末尾同一个出口，所以一律有值。
 *
 * 合并按 RFC 8941 的列表语义：源站指标在前，逗号 + `proxy;dur` + `total;dur` 追加在后；
 * 源站一个都没有时只输出 `proxy;dur, total;dur`（补位，不是覆盖）。上限 5 个指标：
 * 源站固定 3 个（d1/ssr/app）+ 代理 2 个（proxy/total）= 5 个，正好顶格；
 * 万一源站以后加指标，这里会把多出来的截掉（只留源站前 3 个），保证不超限。
 *
 * ⚠️ 只有**本次真的回源了**才透传源站的段（`inherit=false` 时丢掉）：
 * 缓存条目里存着「当初那次回源」的 d1/ssr/app，回放时那不是本次的耗时，留着就是把旧数冒充本次。
 * 判据用现成的 `x-proxy-cache` 档位（hit / stale* 都是回放；miss / bypass 才是新回源），
 * 这样不用碰缓存回放逻辑（fromCache）。
 *
 * 整个函数包在 try 里：计时/改头任何异常都原样返回响应 —— 计时绝不能影响响应。
 */
const MAX_SERVER_TIMING_METRICS = 5;

/** 按逗号切 Server-Timing，但**不切引号内**的逗号（`desc="a,b"` 是合法写法）。 */
function splitServerTiming(raw: string): string[] {
  const parts: string[] = [];
  let start = 0;
  let quoted = false;
  for (let i = 0; i < raw.length; i += 1) {
    const ch = raw.charAt(i);
    if (ch === '"') {
      quoted = !quoted;
      continue;
    }
    if (quoted || ch !== ",") continue;
    parts.push(raw.slice(start, i));
    start = i + 1;
  }
  parts.push(raw.slice(start));
  return parts.map((part) => part.trim()).filter((part) => part.length > 0);
}

function withServerTiming(
  res: Response,
  proxyMs: number,
  totalMs: number,
  inheritOriginTiming: boolean,
): Response {
  try {
    const headers = new Headers(res.headers);
    const inherited = inheritOriginTiming
      // 给 proxy / total 留两个位：源站最多留 3 条（d1/ssr/app）。
      ? splitServerTiming(headers.get("server-timing") ?? "").slice(0, MAX_SERVER_TIMING_METRICS - 2)
      : [];
    inherited.push(`proxy;dur=${Math.max(0, Math.round(proxyMs))}`);
    // 反代视角整段：收到请求 → 交出首字节。与 proxy 的差就是回源往返（up）。
    inherited.push(`total;dur=${Math.max(0, Math.round(totalMs))}`);
    headers.set("server-timing", inherited.join(", "));
    return withBody(res, headers);
  } catch {
    return res;
  }
}

/** 命中缓存时回放：cache-control 用源站原值，绝不让这份 HTML 被浏览器/CDN 二次共享。 */
function fromCache(hit: Response, state: string, ageMs: number, observe?: Observe): Response {
  const headers = new Headers(hit.headers);
  const originCacheControl = headers.get(ORIGIN_CC);
  headers.delete(ORIGIN_CC);
  headers.delete(BORN);
  headers.delete(ORIGIN_USER_MARK);
  headers.set("cache-control", originCacheControl !== null && originCacheControl.length > 0 ? originCacheControl : DEFAULT_CC);
  headers.set(CACHE_STATE, state);
  headers.set(CACHE_AGE, String(Math.max(0, Math.round(ageMs / 1000))));
  applyObserve(headers, observe);
  return withBody(hit, headers);
}

function entryAge(hit: Response): number {
  const born = Number(hit.headers.get(BORN));
  const ageMs = Number.isFinite(born) && born > 0 ? Date.now() - born : Number.POSITIVE_INFINITY;
  return ageMs < 0 ? 0 : ageMs; // 时钟回拨时不把条目当永久新鲜
}

function anonStorePlan(cache: Cache, key: Request): StorePlan {
  return { cache, key, ttlSeconds: STORE_TTL_S, requireUserMark: false, missState: "miss" };
}

function userStorePlan(cache: Cache, key: Request): StorePlan {
  return { cache, key, ttlSeconds: USER_STORE_TTL_S, requireUserMark: true, missState: "miss-user" };
}

function processOrigin(
  res: Response,
  requestUrl: URL,
  proxyOrigin: string,
  plan: StorePlan | null,
  method: string,
  observe?: Observe,
  /** plan 为空但有明确档位时（缓存还没就绪）用来如实标 miss / miss-user，而不是笼统的 bypass。 */
  unstoredState?: string,
): OriginOutput {
  const out = buildResponseHeaders(res, requestUrl, method);

  const cookies = getSetCookies(res.headers);
  if (cookies.length > 0) {
    out.delete("set-cookie");
    for (const cookie of cookies) {
      out.append("set-cookie", cookie.replace(/;\s*domain=[^;]*/gi, ""));
    }
  }

  rewriteLocation(out, proxyOrigin);
  rewriteCors(out, proxyOrigin);
  applyObserve(out, observe);

  const storable =
    plan !== null &&
    method === "GET" &&
    res.status === 200 &&
    res.body !== null &&
    cookies.length === 0 &&
    isStorable(res.headers) &&
    // 用户桶：源站没打 X-Zhuge-Cache-Tier: user 就不许写（匿名桶 requireUserMark=false，不受影响）
    (!plan.requireUserMark || isUserMarked(res.headers));

  if (plan === null || !storable) {
    out.set(CACHE_STATE, plan === null && unstoredState !== undefined ? unstoredState : "bypass");
    return { response: withBody(res, out) };
  }

  const [toClient, toCache] = res.body!.tee();
  out.delete("content-length"); // 不再让旧长度约束这条被 tee 过的流
  out.set(CACHE_STATE, plan.missState);

  const storeHeaders = new Headers(out);
  storeHeaders.set(ORIGIN_CC, out.get("cache-control") ?? "");
  storeHeaders.set("cache-control", `public, max-age=${plan.ttlSeconds}`);
  storeHeaders.set(BORN, String(Date.now()));
  storeHeaders.delete(CACHE_STATE);
  storeHeaders.delete(CACHE_AGE);
  storeHeaders.delete(USER_STATE);
  storeHeaders.delete(EPOCH_STATE);

  let stored: Promise<void> | undefined;
  try {
    stored = plan.cache
      .put(plan.key, new Response(toCache, { status: 200, statusText: res.statusText, headers: storeHeaders }))
      .catch(() => {
        // put 失败后没人读 toCache，必须主动取消，否则客户端分支会被反压拖住。
        void toCache.cancel().catch(() => {});
      });
  } catch {
    void toCache.cancel().catch(() => {});
  }

  return {
    response: new Response(toClient, { status: 200, statusText: res.statusText, headers: out }),
    stored,
  };
}

async function refresh(job: RefreshJob): Promise<void> {
  const id = job.key.url;
  if (refreshing.has(id)) return;
  refreshing.add(id);
  try {
    const proxyOrigin = new URL(job.request.url).origin;
    const target = canonicalUrl(job.url); // 与 key 对齐，避免把带跟踪参数的渲染结果写回规范条目
    const res = await fetchOrigin(job.request, target, { forceGzip: true, canonicalReferer: true });
    const { response, stored } = processOrigin(res, target, proxyOrigin, job.plan, "GET", job.observe);
    await discard(response); // 后台刷新没有人消费客户端分支
    if (stored !== undefined) await stored;
  } catch {
    // 刷新失败就保留旧条目，别把好好的 stale 删了
  } finally {
    refreshing.delete(id);
  }
}

function isOriginError(status: number): boolean {
  return status === 408 || status === 429 || status >= 500;
}

function tagged(res: Response, observe: Observe): Response {
  const headers = new Headers(res.headers);
  applyObserve(headers, observe);
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
}

/* ── 档位一：匿名桶（缓存与两路回源同时开跑，谁先成功用谁）────────────────── */

/** 匿名档的缓存探测：打不开 / match 抛错一律降级为「这一档没有缓存」，绝不 5xx。 */
async function probeAnonymous(request: Request, url: URL, ctx: Context, trace: Trace): Promise<CacheProbe> {
  let cache: Cache | null = null;
  let key: Request | null = null;
  let stale: StaleHit | undefined;
  let hit: CacheHit | undefined;

  try {
    const openedCache = await caches.open(CACHE_NAME);
    const cacheKey = buildCacheKey(request, url);
    cache = openedCache;
    key = cacheKey;

    const matched = await openedCache.match(cacheKey);
    trace.tCache = Date.now(); // 缓存查询结束（命中与未命中都在这一刻）
    if (matched) {
      // 命中时没有回源，但条目里存的就是当初的源站响应头（cf-ray 也在），
      // 所以 colo 照样能取到；取不到就保持 "?"。已经由回源赢家写过就不覆盖。
      if (trace.colo === undefined) trace.colo = traceColo(matched);
      const ageMs = entryAge(matched);

      if (ageMs < FRESH_MS) hit = { res: matched, state: "hit", ageMs };
      else if (ageMs < SWR_MS) {
        waitUntil(ctx, refresh({ request, url, key: cacheKey, plan: anonStorePlan(openedCache, cacheKey) }));
        hit = { res: matched, state: "stale", ageMs };
      } else if (ageMs < HARD_STALE_MS) stale = { res: matched, ageMs }; // 先留着当兜底
      else {
        // 彻底过期：取消 body 顺手删条目，避免平台不执行 max-age 时缓存无限膨胀。
        await discard(matched);
        waitUntil(ctx, openedCache.delete(cacheKey).catch(() => false));
      }
    }
  } catch {
    cache = null;
    key = null; // 缓存故障：本次不回写，绝不让缓存故障变成 5xx
  }
  if (trace.tCache === undefined) trace.tCache = Date.now(); // 缓存打不开 / 提前失败：查询也结束了

  // 跟踪参数请求只读不写：写进去的就是带参数的渲染结果。
  const writable = cache !== null && key !== null && !hasTrackingParams(url);
  return { hit, stale, plan: writable ? anonStorePlan(cache!, key!) : null };
}

async function serveAnonymous(request: Request, url: URL, ctx: Context, trace: Trace): Promise<Response> {
  const proxyOrigin = url.origin;

  // ① 两路回源立刻出发：缓存查询（②）与它们并行，谁先给出可用结果谁赢。
  //    能走到本档的一定是 GET（classifyTier 拦掉了其他方法），所以这里不用再判方法。
  trace.tFetch = Date.now();
  const race = startOriginRace(request, url, { forceGzip: true, canonicalReferer: true });

  // ② 缓存查询与它并行；probe 兜成永不 reject（任何意外都退化成「这一档没缓存」）。
  const probeP: Promise<CacheProbe> = probeAnonymous(request, url, ctx, trace).catch(
    (): CacheProbe => ({ plan: null }),
  );
  trace.cacheSettled = probeP.then(
    () => undefined,
    () => undefined,
  );

  const decision = await decideRace(race, probeP);

  // 结果一：缓存先赢 → 用缓存条目，两路回源在 decideRace 里已经 abort。
  if (decision.kind === "cache") {
    trace.race = "cache";
    trace.tFetch = undefined; // 没有用上回源：up 记 0，proxy 退回整段函数耗时
    trace.tUp = undefined;
    return fromCache(decision.hit.res, decision.hit.state, decision.hit.ageMs);
  }

  // 结果二：两路回源都抛 → 走原来的错误路径（先等缓存那一路跑完，它可能正好有命中 / 旧副本）。
  if (decision.kind === "origin-failed") {
    const probe = decision.probe ?? (await probeP);
    if (probe.hit !== undefined) {
      trace.race = "cache";
      trace.tFetch = undefined;
      trace.tUp = undefined;
      return fromCache(probe.hit.res, probe.hit.state, probe.hit.ageMs);
    }
    trace.race = "none";
    if (probe.stale !== undefined) return fromCache(probe.stale.res, "stale-error", probe.stale.ageMs);
    return text(502, "Bad Gateway");
  }

  // 结果三：回源先赢（正常的缓存未命中也是这条）→ 赢家响应原样返回，另一路已被 abort。
  if (decision.probe === null) {
    // 缓存那一路还在跑：本次已经用不上它的命中，跑完把 body 放掉（缓存没法 abort）。
    void probeP.then(discardProbe, () => undefined);
  }
  const finishing = await finishOriginRace(
    decision.winner,
    decision.probe,
    url,
    proxyOrigin,
    "GET",
    undefined,
    trace,
    // 缓存还没就绪就输给了回源：如实标 miss，别退化成 bypass（本档是匿名桶）。
    decision.probe === null ? "miss" : undefined,
  );
  if (finishing.kind === "stale") return fromCache(finishing.stale.res, "stale-error", finishing.stale.ageMs);
  if (finishing.stored !== undefined) waitUntil(ctx, finishing.stored);
  return finishing.response;
}

/* ── 档位二：用户桶（epoch 读完后与两路回源竞速；写不写照旧看响应头）──────── */

/** 用户档的缓存探测：epoch 只读一次，之后写缓存全程用同一个值（第 27 条）。 */
async function probeMember(
  request: Request,
  url: URL,
  ctx: Context,
  trace: Trace,
  uidHash: string,
  tag: string,
): Promise<CacheProbe> {
  let cache: Cache | null = null;
  let key: Request | null = null;
  let stale: StaleHit | undefined;
  let hit: CacheHit | undefined;
  let observe: Observe = { user: tag };

  try {
    const openedCache = await caches.open(CACHE_NAME);
    // epoch 只在这里读一次，之后回源、写缓存全程用同一个值：
    // 回源期间发生的写操作只会让新内容落到新 epoch，不会把旧 HTML 写进当前 epoch。
    const epoch = await readEpoch(openedCache, uidHash);
    const cacheKey = buildUserCacheKey(request, url, uidHash, epoch);
    cache = openedCache;
    key = cacheKey;
    observe = { user: tag, epoch };

    const matched = await openedCache.match(cacheKey);
    trace.tCache = Date.now(); // 缓存查询结束（命中与未命中都在这一刻）
    if (matched) {
      // 同匿名档：命中条目里存着当初的源站响应头，cf-ray 可用。回源已经写过 colo 就不覆盖。
      if (trace.colo === undefined) trace.colo = traceColo(matched);
      const ageMs = entryAge(matched);

      if (ageMs < USER_FRESH_MS) hit = { res: matched, state: "hit-user", ageMs };
      else if (ageMs < USER_SWR_MS) {
        waitUntil(
          ctx,
          refresh({ request, url, key: cacheKey, plan: userStorePlan(openedCache, cacheKey), observe }),
        );
        hit = { res: matched, state: "stale-user", ageMs };
      } else if (ageMs < USER_HARD_STALE_MS) stale = { res: matched, ageMs };
      else {
        await discard(matched);
        waitUntil(ctx, openedCache.delete(cacheKey).catch(() => false));
      }
    }
  } catch {
    cache = null;
    key = null;
    stale = undefined; // 缓存故障时不留半截兜底：直连源站即可，绝不 5xx
  }
  if (trace.tCache === undefined) trace.tCache = Date.now(); // 缓存打不开 / 提前失败：查询也结束了

  const writable = cache !== null && key !== null && !hasTrackingParams(url);
  return { hit, stale, plan: writable ? userStorePlan(cache!, key!) : null, observe };
}

async function serveMember(request: Request, url: URL, ctx: Context, trace: Trace): Promise<Response> {
  const proxyOrigin = url.origin;
  const session = readSessionCookie(request);
  if (session === null) return serveDirect(request, url, trace); // classifyTier 已保证非空，这里再兜一次

  let uidHash: string;
  try {
    uidHash = await uidHashOf(session);
  } catch {
    return serveDirect(request, url, trace); // 没有 crypto.subtle：降级直连，绝不 5xx
  }

  const tag = uidHash.slice(0, USER_TAG_LEN);

  // ① 两路回源立刻出发（uidHash 只是缓存键的一部分，回源不需要它）。
  trace.tFetch = Date.now();
  const race = startOriginRace(request, url, { forceGzip: true, canonicalReferer: true });

  // ② 缓存查询与它并行；probe 兜成永不 reject（任何意外都退化成「这一档没缓存」）。
  const probeP: Promise<CacheProbe> = probeMember(request, url, ctx, trace, uidHash, tag).catch(
    (): CacheProbe => ({ plan: null, observe: { user: tag } }),
  );
  trace.cacheSettled = probeP.then(
    () => undefined,
    () => undefined,
  );

  const decision = await decideRace(race, probeP);
  // 观测头：缓存那一路若还没跑完，只能先给 user、没有 epoch（不为了这个头拖响应）。
  const observe: Observe = decision.probe?.observe ?? { user: tag };

  // 结果一：缓存先赢 → 用缓存条目，两路回源在 decideRace 里已经 abort。
  if (decision.kind === "cache") {
    trace.race = "cache";
    trace.tFetch = undefined; // 没有用上回源：up 记 0，proxy 退回整段函数耗时
    trace.tUp = undefined;
    return fromCache(decision.hit.res, decision.hit.state, decision.hit.ageMs, observe);
  }

  // 结果二：两路回源都抛 → 走原来的错误路径（先等缓存那一路跑完，它可能正好有命中 / 旧副本）。
  if (decision.kind === "origin-failed") {
    const probe = decision.probe ?? (await probeP);
    const fallbackObserve = probe.observe ?? observe;
    if (probe.hit !== undefined) {
      trace.race = "cache";
      trace.tFetch = undefined;
      trace.tUp = undefined;
      return fromCache(probe.hit.res, probe.hit.state, probe.hit.ageMs, fallbackObserve);
    }
    trace.race = "none";
    if (probe.stale !== undefined) {
      return fromCache(probe.stale.res, "stale-error-user", probe.stale.ageMs, fallbackObserve);
    }
    return tagged(text(502, "Bad Gateway"), fallbackObserve);
  }

  // 结果三：回源先赢（正常的缓存未命中也是这条）→ 赢家响应原样返回，另一路已被 abort。
  if (decision.probe === null) {
    // 缓存那一路还在跑：本次已经用不上它的命中，跑完把 body 放掉（缓存没法 abort）。
    void probeP.then(discardProbe, () => undefined);
  }
  const finishing = await finishOriginRace(
    decision.winner,
    decision.probe,
    url,
    proxyOrigin,
    "GET",
    observe,
    trace,
    // 缓存还没就绪就输给了回源：如实标 miss-user，别退化成 bypass（本档是用户桶）。
    decision.probe === null ? "miss-user" : undefined,
  );
  if (finishing.kind === "stale") {
    return fromCache(finishing.stale.res, "stale-error-user", finishing.stale.ageMs, observe);
  }
  if (finishing.stored !== undefined) waitUntil(ctx, finishing.stored);
  return finishing.response;
}

/* ── 档位三：直连（bypass；非 GET 同时负责写操作的 epoch 推进）────────────── */

async function serveDirect(request: Request, url: URL, trace: Trace): Promise<Response> {
  const proxyOrigin = url.origin;
  if (trace.tCache === undefined) trace.tCache = trace.t0; // 这一档没有缓存查询 → cacheMs 恒为 0

  // 非 GET 一律不竞速：写操作翻倍且无法取消，只能原样单路回源。
  if (request.method !== "GET") {
    trace.race = "none";
    let originRes: Response;
    try {
      trace.tFetch = Date.now();
      originRes = await fetchOrigin(request, url, { forceGzip: false, canonicalReferer: false });
      trace.tUp = Date.now(); // 回源响应头到达
      trace.colo = traceColo(originRes);
    } catch {
      return text(502, "Bad Gateway");
    }

    // 任何非 GET 成功（status < 400）都推进该用户 epoch。
    // 这里 await 而不是 waitUntil：响应一返回，浏览器就会紧接着发下一个 GET，
    // 那一发必须已经能读到新 epoch，否则「回帖后仍看到旧页面」的原问题会重新出现。
    if (originRes.status < 400) {
      await bumpEpochForRequest(request);
    }

    const { response } = processOrigin(originRes, url, proxyOrigin, null, request.method);
    return response;
  }

  // GET（bypass 档）：没有缓存可查，但两路回源照样竞速 —— 慢的那一路不再拖住用户。
  trace.tFetch = Date.now();
  const race = startOriginRace(request, url, { forceGzip: false, canonicalReferer: false });
  let winner: OriginWinner;
  try {
    winner = await race.winner;
  } catch {
    return text(502, "Bad Gateway"); // 两路都抛：原来的错误路径
  }
  const finishing = await finishOriginRace(winner, null, url, proxyOrigin, "GET", undefined, trace);
  // 这一档没有缓存（probe 恒为 null），所以不会走到 stale 兜底。
  return finishing.kind === "response" ? finishing.response : text(502, "Bad Gateway");
}

/* ── 入口 ───────────────────────────────────────────────────────────────── */

export default async function handler(request: Request, ctx: Context): Promise<Response> {
  const t0 = Date.now(); // 链路追踪：进函数（2026-10-29）
  if (TARGET_URL === null || TARGET_ORIGIN.length === 0) {
    return text(500, "TARGET_URL environment variable is missing or invalid");
  }

  const url = new URL(request.url);
  const trace: Trace = { t0 };
  let response: Response;

  // 三档分流只在 classifyTier 一处判定，handler 只负责转派。
  switch (classifyTier(request, url)) {
    case "anon":
      response = await serveAnonymous(request, url, ctx, trace);
      break;
    case "user":
      response = await serveMember(request, url, ctx, trace);
      break;
    default:
      // 直连档没有缓存查询：tCache = t0（在 serveDirect 里补）
      response = await serveDirect(request, url, trace);
  }

  // ── 链路追踪上报 + 分段计时（tEnd 在这里：返回响应前）────────────────────
  // 追踪上报只读时间与响应头（x-proxy-cache / cf-ray），绝不改响应、失败完全静默；
  // Server-Timing 是唯一会写响应头的东西（withServerTiming，内部全 try/catch）。
  const tEnd = Date.now();
  const totalMs = Math.max(0, tEnd - t0);
  // up = 赢家那一路「发起 fetch → 拿到响应头」的实际耗时；赢家是缓存时为 0。
  const upstreamMs = trace.tFetch === undefined ? 0 : Math.max(0, (trace.tUp ?? tEnd) - trace.tFetch);
  // proxy = 进函数 → 发起回源（tFetch - t0）。竞速后回源在 handler 一进来就发，
  // 所以它现在只剩「进函数 → 开始回源」的那点开销；缓存那一段单独由 cacheMs 表示。
  // 没有回源（缓存命中）= 整个函数耗时。
  const proxyMs = trace.tFetch === undefined ? totalMs : Math.max(0, trace.tFetch - t0);
  // cacheMs = 进函数 → 缓存查询结束（caches.open + match，用户档还含 epoch 读取）。
  // 直连档没有缓存查询：tCache 在 serveDirect 里取了 t0，恒为 0。
  const cacheMsNow = trace.tCache === undefined ? undefined : Math.max(0, trace.tCache - t0);
  const raceName = trace.race ?? "none";
  const cacheState = traceCacheState(response.headers.get(CACHE_STATE));
  // 只有本次真的回源（miss / miss-user / bypass）才透传源站的 d1/ssr/app；
  // 缓存回放（hit / stale*）里那份是「当初那次」的数，透传会把旧数冒充本次。
  const originFresh = cacheState === "miss" || cacheState === "miss-user" || cacheState === "bypass";
  try {
    const sample = Math.random() < TRACE_SAMPLE_RATE;
    // 缓存慢本身也算「慢请求」：竞速后回源会抢跑，这类请求的 total/up 都很漂亮，
    // 只有 cacheMs 能把「缓存卡了 11s」暴露出来，否则它们只会落在 2% 采样里。
    const report = (cacheMs: number): void => {
      const slow = upstreamMs > TRACE_UP_SLOW_MS || totalMs > TRACE_TOTAL_SLOW_MS || cacheMs > TRACE_UP_SLOW_MS;
      if (slow || sample) {
        reportTrace(ctx, trace, url, cacheState, upstreamMs, totalMs, proxyMs, cacheMs, raceName);
      }
    };
    if (cacheMsNow !== undefined) {
      report(cacheMsNow);
    } else {
      // 缓存查询到交响应时都还没结束（这次它被回源抢跑了）：等它跑完再报，
      // cacheMs 才是真实值。上报本来就是 fire-and-forget，这里只是把「报」推迟。
      const settle = trace.cacheSettled;
      const later = (): void => report(Math.max(0, (trace.tCache ?? Date.now()) - t0));
      if (settle === undefined) later();
      else waitUntil(ctx, settle.then(later));
    }
  } catch {
    // 埋点自身任何异常一律吞掉：响应保持不变
  }
  // Server-Timing：透传源站的 d1/ssr/app，追加本代理的 proxy;dur 与 total;dur。
  // total 用的是上面这一刻的 tEnd（返回响应前），所以包含到「交出首字节」为止的全部反代时间。
  return withServerTiming(response, proxyMs, totalMs, originFresh);
}
