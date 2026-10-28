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
// 7. 带 cookie / authorization / range / upgrade 的请求完全不碰缓存：匿名缓存不允许靠近任何可能带登录态的内容。
// 8. 响应带 Set-Cookie 时一律不写缓存：这是「本次响应有状态」的最强信号。
// 9. 源站 private, no-cache 仍然可存：匿名 HTML 固定这么返回，拒绝它等于没有缓存；匿名性由第 5/7/8 条保证。
// 10. 写缓存/命中路径都删掉 content-length：body 过了 tee、存、再取，任何 framing 变化都不该让旧长度生效。
// 11. cache.put 失败立刻 cancel 掉 tee 的另一半：不消费的分支会把客户端分支一起反压住并涨内存。
// 12. 条目 TTL(6min) 必须大于 stale-if-error 窗口(5min)：否则最需要兜底的那一刻条目正好过期。
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
// 23. 缓存名带版本号 v4：本次键/编码语义变了，不换名会读到旧 br 条目。
// 24. 表单/认证/API 路径进黑名单：内嵌 CSRF token 或一次性 nonce 的页面被缓存会把全员 token 冻在旧值上。
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

const FRESH_MS = 30_000; // 命中即回，不再回源
const SWR_MS = 60_000; // 命中旧副本 + 后台刷新
const HARD_STALE_MS = 5 * 60_000; // 只在源站 5xx/超时时才肯拿出来的最旧副本
const STORE_TTL_S = 360; // 必须 > HARD_STALE_MS，否则兜底时条目已经没了
const ORIGIN_TIMEOUT_MS = 15_000; // 只卡响应头
const MAX_QUERY_PARAMS = 6; // 防随机参数把缓存打爆
const OLD_CHROME_BELOW = 88; // 必须与源站阈值一致
const DEFAULT_CC = "private, no-cache";

const BORN = "x-proxy-born";
const ORIGIN_CC = "x-proxy-origin-cc";
const CACHE_STATE = "x-proxy-cache";
const CACHE_AGE = "x-proxy-age";

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

type StaleHit = { res: Response; ageMs: number };
type OriginOutput = { response: Response; stored?: Promise<void> };

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

function isCacheable(request: Request, url: URL): boolean {
  if (request.method !== "GET") return false;

  const headers = request.headers;
  if (headers.has("cookie") || headers.has("authorization") || headers.has("range") || headers.has("upgrade")) {
    return false;
  }
  if (!(headers.get("accept") ?? "").includes("text/html")) return false;
  // 缓存条目固定 gzip，只服务能解 gzip 的客户端。
  if (!acceptsGzip(headers.get("accept-encoding") ?? "")) return false;

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

function buildCacheKey(request: Request, url: URL): Request {
  const theme = request.headers.get("sec-ch-prefers-color-scheme") === "dark" ? "dark" : "light";
  const engine = isOldEngine(request.headers.get("user-agent") ?? "") ? "old" : "new";
  const qs = canonicalQuery(url);
  // pathname 来自 new URL()，已是百分号编码，所以键与原路径一一对应，不会撞车。
  const id = `https://cache.invalid/${theme}/${engine}${url.pathname}${qs.length > 0 ? `?${qs}` : ""}`;
  return new Request(id, { method: "GET" });
}

/* ── 回源 ───────────────────────────────────────────────────────────────── */

async function fetchOrigin(request: Request, url: URL, cacheable: boolean): Promise<Response> {
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

  if (cacheable) {
    headers.set("accept-encoding", "gzip");
    headers.delete("if-none-match");
    headers.delete("if-modified-since");
    headers.delete("if-range");
  }

  const origin = request.headers.get("origin");
  if (origin !== null && origin === proxyOrigin) headers.set("origin", TARGET_ORIGIN);

  const referer = headers.get("referer");
  if (referer !== null) {
    if (cacheable) {
      // 可缓存请求用「自身地址」做 referer：确定性，避免把别处的来源写进缓存。
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
  }
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

function fromCache(hit: Response, state: string, ageMs: number): Response {
  const headers = new Headers(hit.headers);
  const originCacheControl = headers.get(ORIGIN_CC);
  headers.delete(ORIGIN_CC);
  headers.delete(BORN);
  headers.set("cache-control", originCacheControl !== null && originCacheControl.length > 0 ? originCacheControl : DEFAULT_CC);
  headers.set(CACHE_STATE, state);
  headers.set(CACHE_AGE, String(Math.max(0, Math.round(ageMs / 1000))));
  return withBody(hit, headers);
}

function processOrigin(
  res: Response,
  requestUrl: URL,
  proxyOrigin: string,
  cache: Cache | null,
  key: Request | null,
  method: string,
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

  const storable =
    cache !== null &&
    key !== null &&
    method === "GET" &&
    res.status === 200 &&
    res.body !== null &&
    cookies.length === 0 &&
    isStorable(res.headers);

  if (!storable) {
    out.set(CACHE_STATE, "bypass");
    return { response: withBody(res, out) };
  }

  const [toClient, toCache] = res.body!.tee();
  out.delete("content-length"); // 不再让旧长度约束这条被 tee 过的流
  out.set(CACHE_STATE, "miss");

  const storeHeaders = new Headers(out);
  storeHeaders.set(ORIGIN_CC, out.get("cache-control") ?? "");
  storeHeaders.set("cache-control", `public, max-age=${STORE_TTL_S}`);
  storeHeaders.set(BORN, String(Date.now()));
  storeHeaders.delete(CACHE_STATE);
  storeHeaders.delete(CACHE_AGE);

  let stored: Promise<void> | undefined;
  try {
    stored = cache!.put(
      key!,
      new Response(toCache, { status: 200, statusText: res.statusText, headers: storeHeaders }),
    ).catch(() => {
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

async function refresh(request: Request, url: URL, cache: Cache, key: Request): Promise<void> {
  const id = key.url;
  if (refreshing.has(id)) return;
  refreshing.add(id);
  try {
    const proxyOrigin = new URL(request.url).origin;
    const target = canonicalUrl(url); // 与 key 对齐，避免把带跟踪参数的渲染结果写回规范条目
    const res = await fetchOrigin(request, target, true);
    const { response, stored } = processOrigin(res, target, proxyOrigin, cache, key, "GET");
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

/* ── 入口 ───────────────────────────────────────────────────────────────── */

export default async function handler(request: Request, ctx: Context): Promise<Response> {
  if (TARGET_URL === null || TARGET_ORIGIN.length === 0) {
    return text(500, "TARGET_URL environment variable is missing or invalid");
  }

  const url = new URL(request.url);
  const proxyOrigin = url.origin;
  const cacheable = isCacheable(request, url);

  let cache: Cache | null = null;
  let key: Request | null = null;
  let stale: StaleHit | null = null;

  if (cacheable) {
    try {
      const openedCache = await caches.open(CACHE_NAME);
      const cacheKey = buildCacheKey(request, url);
      cache = openedCache;
      key = cacheKey;

      const hit = await openedCache.match(cacheKey);
      if (hit) {
        const born = Number(hit.headers.get(BORN));
        let ageMs = Number.isFinite(born) && born > 0 ? Date.now() - born : Number.POSITIVE_INFINITY;
        if (ageMs < 0) ageMs = 0; // 时钟回拨时不把条目当永久新鲜

        if (ageMs < FRESH_MS) return fromCache(hit, "hit", ageMs);
        if (ageMs < SWR_MS) {
          waitUntil(ctx, refresh(request, url, openedCache, cacheKey));
          return fromCache(hit, "stale", ageMs);
        }
        if (ageMs < HARD_STALE_MS) stale = { res: hit, ageMs }; // 先留着当兜底
        else {
          // 彻底过期：取消 body 顺手删条目，避免平台不执行 max-age 时缓存无限膨胀。
          await discard(hit);
          waitUntil(ctx, openedCache.delete(cacheKey).catch(() => false));
        }
      }
    } catch {
      cache = null;
      key = null; // 拿不到缓存就降级为直连，绝不让缓存故障变成 5xx
    }
  }

  // 跟踪参数请求只读不写：写进去的就是带参数的渲染结果。
  const writable = cache !== null && key !== null && !hasTrackingParams(url);
  const storeCache: Cache | null = writable ? cache : null;
  const storeKey: Request | null = writable ? key : null;

  let originRes: Response;
  try {
    originRes = await fetchOrigin(request, url, cacheable);
  } catch {
    if (stale !== null) return fromCache(stale.res, "stale-error", stale.ageMs);
    return text(502, "Bad Gateway");
  }

  if (isOriginError(originRes.status) && stale !== null) {
    await discard(originRes);
    return fromCache(stale.res, "stale-error", stale.ageMs);
  }
  if (stale !== null) await discard(stale.res);

  const { response, stored } = processOrigin(originRes, url, proxyOrigin, storeCache, storeKey, request.method);
  if (stored !== undefined) waitUntil(ctx, stored);
  return response;
}
