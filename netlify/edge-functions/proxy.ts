// Netlify Edge Function —— React Router v8 SSR 反向代理（源站 Cloudflare Workers）
// 部署方式不变：环境变量 TARGET_URL=https://xn--fpr224a.mom，路由仍由 netlify.toml 的
// [[edge_functions]] 指定（本文件故意不再 export config，避免和现有配置打架）。
//
// ── 关键决策（每条一句话理由）───────────────────────────────────────────────
// 1. 目标地址只来自环境变量并校验成 URL：请求路径永远拼在 host 之后，天然堵死开放代理与 SSRF。
// 2. **函数内不再有任何缓存**：没有 Cache API、没有内存镜像、没有 epoch。缓存整段交给 Netlify CDN
//    （理由见第 54 条）；CDN 命中时函数根本不执行，函数只负责「回源 + 改写 + 给 CDN 下指令」。
// 3. GET 一律多路回源竞速（配了几个目标就打几路，1~3）：慢的那一路不再拖住用户，谁先给出响应头用谁。
// 4. 非 GET 一律不竞速：写操作翻倍且无法取消，只能原样单路。
// 5. 匿名档 = GET + 无 cookie / authorization / range / upgrade + Accept 要页面 + 路径与参数不在黑名单里。
//    登录态请求永远进不了匿名档，所以 CDN 上存的匿名 HTML 一定来自「没有登录态」的请求。
// 6. 带 utm_* 等跟踪参数的请求「可读不可缓存」：链接上的参数会被按 URL 缓存，等于给每条分享链接造一份副本。
// 7. 表单 / 认证 / API 路径进黑名单：内嵌 CSRF token 或一次性 nonce 的页面被 CDN 缓存会把全员 token 冻在旧值上。
// 8. 请求和响应都删逐跳头：connection / transfer-encoding 这类头再发一次会破坏 framing。
// 9. Location 先 URL 解析再比对 host 才改写：相对、绝对、协议相对 //、http 方案全覆盖，且不会把 .evil.com 当自己人。
// 10. Set-Cookie 统一剥掉 Domain：不剥浏览器会因为域不匹配拒写，或者把 cookie 带到错误的域上。
// 11. Origin/Referer 只在「指向代理自己」时改写：满足 .data POST 的同源校验，又不把 Origin: null 洗白成合法来源。
// 12. 回源只做 15s 的「响应头超时」，拿到头就清定时器：慢源站不能让用户无限等，超时也不该把正常流砍断。
// 13. POST body 继续用 arrayBuffer()：Netlify/Deno 上流式 body + duplex 未验证，整包读入是已验证路径。
// 14. redirect: "manual" 继续保留：3xx 必须原样交给浏览器，Location 由我们自己改写。
// 15. 带哈希的静态资源加 immutable 长缓存：换入口的意义就是让浏览器下次根本不再经过这个函数。
// 16. 静态档（/img /assets /frames /splash-*.png）只走**一路**回源、不竞速：图片多跑一次只是一次 R2 读、零 D1。
// 17. 长轮询（/api/device-wait）不参与 trace 上报：它设计上就挂 15 秒，会把真正的卡顿淹掉。
// 18. waitUntil 外面包 try（见 reportTrace）：本地 netlify dev 或老运行时没有 waitUntil 时不能因此 500。
//
// ── 给 CDN 下指令（这是本文件现在唯一的「缓存」）───────────────────────────
// 19. 可缓存的匿名 HTML：`Netlify-CDN-Cache-Control: public, max-age=<ANON_TTL>, stale-while-revalidate=<SWR>`。
//     不设 durable —— 站主要的就是边缘缓存，不是对象存储。
// 20. 不可缓存的响应（登录态 / POST / 带 Set-Cookie / 非 200 / 带跟踪参数）：
//     `Netlify-CDN-Cache-Control: private, no-store`。
// 21. 登录态与匿名共用 URL，靠 `Netlify-Vary: cookie=zhuge_session` 分开缓存键 —— 防串号的**硬前置**
//     （没有这一行，登录用户会拿到匿名 HTML，看起来像「掉登录」）。
//     **一致性铁律（已查实，见第 54 条）**：同一个 URL 的**每一个**响应必须发**完全相同**的那一行
//     Vary，第一份被缓存的响应说了算、后面的会被直接忽略。由此两条：
//       · 除静态资源外的**所有**响应都发这一行 —— 包括登录态、包括 private/no-store、包括 POST 与错误页；
//       · 静态资源（/img /assets /frames /splash-*.png）**一律不发**（那是另一批 key，按 cookie 分键
//         只会把图片命中率打碎）；「一律」也包含它们偶尔返回的 no-store，这批 URL 同样前后一致。
//     判据只看 pathname（isStaticPath），**不看**方法 / 状态码 / content-type —— 否则同一个 URL 会
//     时而发时而不发，而第一份响应已经把这个 URL 的键定死了。
// 22. 匿名 HTML 回源强制 accept-encoding: identity：CDN 存下的那一份必须谁都能解，压缩交给 CDN 现场做。
// 23. 环境变量 `CDN_CACHE=off` ⇒ 一个 CDN 头都不加（每次穿透源站），用于出问题时一键止血；默认开启。
// 24. 档位判定只在 classifyTier 一处 + applyCdnPolicy 一处：前者决定「走哪条回源路径」，
//     后者决定「给 CDN 什么指令」，两者都不散落在各个分支里。
//
// ── trace（region / up / total / proxy / race / colo / path）───────────────
// 25. 只记时间与档位，fire-and-forget（ctx.waitUntil + fetch().catch），绝不 await、失败完全静默。
// 26. `cdn` 字段取代了原来的 cacheMs / open / match / put 四段：函数里已经没有缓存可分段计时，
//     现在只报「这次让 CDN 存不存、存多久」。Server-Timing 的 proxy;dur / total;dur 口径不变。
//     同时仍发一个 `cache` 兼容字段（匿名 public → miss，其余 → bypass）：源站 /api/trace 只认那
//     六种档位、且它的白名单里没有 cdn，不发的话站主现有的「按 cache 分组」会全变成 `cache=?`。
//     响应头 `x-proxy-cache` 也按同一折算保留（对应值见 CACHE_STATE 的注释），
//     只是为了让 `sample-proxy-cache.mjs` 这类按它分组的脚本继续能跑；`hit` 不会再出现。
//
// ── 已知取舍（不修，但必须知道）────────────────────────────────────────────
// 27. **主题 / 内核维度随缓存键一起消失**：原来的 Cache API 键里有 sec-ch-prefers-color-scheme 与
//     老内核判定，CDN 键只有 URL + cookie。于是 dark 主题的匿名用户可能拿到 light 版 HTML。
//     要补回来只能给 public 响应再加 `Netlify-Vary: header=sec-ch-prefers-color-scheme`
//     （这条指令本次没有查证，且加维度会改变已有 URL 的 Vary —— 改之前必须先确认一致性规则怎么算）。
//
// ── 第 54 条：为什么放弃 Cache API、改用 Netlify CDN（2026-10-29）──────────
// （编号沿用改前那一版：28~53 属于已删除的 Cache API 时代，54 是本条新决策，便于和旧日志对照。）
// 54. 站主实测（trace 分组，同一批请求）：
//       · Cache API **命中**：189~951ms（光 match 本身就是 0.19~0.94s）
//       · Cache API **未命中**：1200~2200ms
//     而 Netlify 的 durable / object storage 层本质是「存储」，不是低延迟 KV：把 Cache API 当缓存读，
//     每一次命中都要付一次跨网络读，函数自己的缓存永远比 CDN 慢一个数量级。
//     反过来，**CDN 命中时函数根本不执行** —— 没有冷启动、没有回源、没有 Cache API 读，
//     那 189~951ms 整段都不存在。所以结论不是「优化 Cache API」，而是「不要 Cache API」：
//     函数只负责回源，然后告诉 CDN「这份 HTML 能存多久」。
//     · CDN 层我们**无法主动失效**（没有 bumpEpoch 这样的入口，写操作后也不能推一格），
//       失效只能靠 max-age 到期；因此匿名档 TTL 沿用原来的 FRESH_MS（5min），SWR 取它的 2 倍（10min）。
//     · **串号是这套方案唯一的致命风险**：CDN 的缓存键默认只有 URL，而登录态与匿名共用同一批 URL。
//       若某个 URL 下存了匿名 HTML，登录用户请求同一 URL 时 CDN 会直接把匿名版本给他。
//       所以**同一 URL 空间里的每一个响应**（不只是 public 的那份）都必须发同一行
//       `Netlify-Vary: cookie=zhuge_session`，让「带 session cookie」的请求落到另一个缓存键上
//       （那些请求一律 private, no-store，不会存）。**这是硬前置，不能省，也不能只发一半。**
//     · `Netlify-Vary` 的写法与规则（2026-10-29 站主核对 Netlify 官方 caching 文档后**已查实**）：
//         写法   `Netlify-Vary: query=item_id|page, country=es+de|us, cookie=ab_test|is_logged_in`
//         语义   `cookie=ab_test|is_logged_in` 只按**点名的那几个 cookie** 分键，不是整个 Cookie 头；
//                所以 `cookie=zhuge_session` 可用。
//         铁律   "a URL must return the same `Netlify-Vary` on every response. The first cached
//                response's instructions win and later ones are ignored."
//       这条铁律正是本方案最容易踩死的地方：若登录态的 `private, no-store` 响应**不发** Vary，
//       只要登录用户先访问过某个 URL 一次，这个 URL 的缓存键就被定成「只看 URL」；之后匿名档再发
//       `cookie=…` 也会被忽略，匿名副本照样按「只看 URL」存进去 —— 下一个登录用户请求同一 URL
//       直接命中它 ⇒ 串号。这不是概率问题，是**必然**（只要登录用户先到过一次）。
//       所以 Vary 的判据只跟 pathname 走（静态资源那批一律不发，其余一律发），与档位 / 状态码 /
//       方法 / content-type 全部无关，保证同一个 URL 永远只发出同一行。
//
//     · 退路：若哪天发现 `Netlify-Vary` 被平台调整（或实测不生效），给**同一批**响应加
//       `Vary: Cookie`（最坏是把命中率打到 0，绝不会把匿名副本发给登录用户），而不是让 public 头裸奔。
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

/**
 * 竞速第二路的目标（2026-10-29）——**只从环境变量读，代码里不写死任何域名**。
 *
 * 为什么不写死：本文件其它目标（TARGET_URL）都走环境变量，写死一个域名会让
 * "换域名"变成改代码；而且一旦那个域名的 DNS/证书出问题，第二路会静默失败。
 *
 * 配置：Netlify 站点设置里加环境变量
 *   TARGET_URL_ALT = https://master.xn--cnqs3e5vdw9icjz2q1eaa.xyz
 * 不设置（或设为空）⇒ 第二路回退到与第一路相同的目标 ⇒ 行为与本改动前完全一致，
 * 不会有任何副作用。
 *
 * 原理：两个域名分属不同 zone，CF 宣告的是**不同 anycast IP 段**，
 * BGP 可能落到不同机房（实测同一台机器：apex→NRT、master→LHR）。
 * 而同域名两路的目标 IP 相同 ⇒ 同一条路 ⇒ 竞速只能拿到"两次同样的慢"
 * （实测竞速前后 1456ms → 1533ms，无收益）。
 */
const TARGET_URL_ALT: URL | null = (() => {
  try {
    const raw = Deno.env.get("TARGET_URL_ALT");
    if (raw === undefined || raw.trim() === "") return null;
    return new URL(raw.trim());
  } catch {
    return null;
  }
})();
const TARGET_BASE_ALT: string = TARGET_URL_ALT
  ? `${TARGET_URL_ALT.origin}${TARGET_URL_ALT.pathname.replace(/\/+$/, "")}`
  : "";
const TARGET_HOST_ALT: string = TARGET_URL_ALT ? TARGET_URL_ALT.host : "";
const TARGET_ORIGIN_ALT: string = TARGET_URL_ALT ? TARGET_URL_ALT.origin : "";

/**
 * 竞速第三路的目标（2026-10-29）——同样只从环境变量读。
 *
 * 配置：`TARGET_URL_ALT2 = https://zhuge-v2.bishojoism.workers.dev`
 *
 * 为什么值得加第三路：实测把第二路换成 master 域后，胜率从 50/50 变成 **76/24**
 * ——证明"不同 zone 的域名 → 不同 anycast 段 → 不同 BGP 路径"这条推断成立。
 * 但 master 大部分时候更远，平均只捞到 −80ms。
 * 既然换域名真的能换路，那再加一条**完全不同基础设施**的路（workers.dev 不走自定义域的
 * anycast 段），就多一次"落近处"的机会。
 *
 * 不设置 ⇒ 第三路不存在，行为与只有两路时完全一致。
 */
const TARGET_URL_ALT2: URL | null = (() => {
  try {
    const raw = Deno.env.get("TARGET_URL_ALT2");
    if (raw === undefined || raw.trim() === "") return null;
    return new URL(raw.trim());
  } catch {
    return null;
  }
})();
const TARGET_BASE_ALT2: string = TARGET_URL_ALT2
  ? `${TARGET_URL_ALT2.origin}${TARGET_URL_ALT2.pathname.replace(/\/+$/, "")}`
  : "";
const TARGET_HOST_ALT2: string = TARGET_URL_ALT2 ? TARGET_URL_ALT2.host : "";
const TARGET_ORIGIN_ALT2: string = TARGET_URL_ALT2 ? TARGET_URL_ALT2.origin : "";

/**
 * 竞速目标列表：第 0 项永远是主目标；备用目标按配置依次加入。
 * 竞速的腿数 = 这个数组的长度（1~3），所以"不配环境变量"就等于"只有一条腿"，
 * 不会出现"打到一个不存在的目标"的情况。
 */
type OriginTarget = { base: string; origin: string; host: string };
const ORIGIN_TARGETS: readonly OriginTarget[] = [
  { base: TARGET_BASE, origin: TARGET_ORIGIN, host: TARGET_HOST },
  ...(TARGET_BASE_ALT.length > 0
    ? [{ base: TARGET_BASE_ALT, origin: TARGET_ORIGIN_ALT, host: TARGET_HOST_ALT }]
    : []),
  ...(TARGET_BASE_ALT2.length > 0
    ? [{ base: TARGET_BASE_ALT2, origin: TARGET_ORIGIN_ALT2, host: TARGET_HOST_ALT2 }]
    : []),
];
/** 竞速的腿数（1~3）。第二路只在有备用目标时才存在。 */
const RACE_LEGS = ORIGIN_TARGETS.length;

const ORIGIN_TIMEOUT_MS = 15_000; // 只卡响应头
const MAX_QUERY_PARAMS = 6; // 防随机参数把 CDN 撑爆（每个参数组合都会被存成一份独立对象）

/* ── 匿名档：CDN 缓存窗口（第 19 条 / 第 54 条）───────────────────────────── */

// 执行者从「函数内的 Cache API」换成了 CDN，但新鲜度语义原样保留：
//   · max-age                = FRESH_MS（5min）  → 这段时间内 CDN 直接回放，函数根本不执行
//   · stale-while-revalidate = 2 × max-age（10min）→ 过期后 CDN 先回旧的，同时后台回来取新的
// CDN 层**无法主动失效**（第 54 条），所以这个窗口就是内容陈旧的唯一上界，别随意放大。
const FRESH_MS = 300_000; // 5min：改前匿名档的「命中即回」窗口，语义不变
const ANON_TTL_S = Math.round(FRESH_MS / 1000); // 300s：Netlify-CDN-Cache-Control 的 max-age
const ANON_SWR_S = ANON_TTL_S * 2; // 600s：站主要求取 max-age 的 2~4 倍，这里取 2 倍

/* ── 静态档：CDN 缓存窗口 ────────────────────────────────────────────────── */

// 源站对这些资源本来就发 immutable 一年；30 天只是给 CDN 一个确定的淘汰点，不需要我们删条目。
const STATIC_TTL_S = 30 * 24 * 3_600; // 30 天

/**
 * 总开关（第 23 条）：`CDN_CACHE=off` ⇒ **一个 CDN 头都不加**。
 * 等于退回「每次请求都穿透到源站」，用于 CDN 缓存出问题（串号 / 脏内容）时一键止血。
 *
 * 只认精确的 "off"（去两端空白后比较，兼顾手滑多打一个空格）；其余一切值（未设置 / 空串 /
 * 拼错 / env 读取抛错）都按**默认开启**处理 —— 关掉缓存会让源站直接吃满全部流量，
 * 绝不能因为一个字母拼错就发生。危险方向必须默认关闭。
 */
const CDN_CACHE_ENABLED: boolean = (() => {
  try {
    const env = (globalThis as { Deno?: { env?: { get(k: string): string | undefined } } }).Deno?.env;
    return (env?.get("CDN_CACHE") ?? "").trim() !== "off";
  } catch {
    return true;
  }
})();

/* ── trace 用：本 isolate 的标识与请求序号（第 25 条）─────────────────────── */

/**
 * 本 isolate 的随机标识：只用于把 trace 日志按 isolate 分组，**绝不进响应头**（避免泄漏部署细节）。
 */
const ISOLATE_ID = Math.random().toString(36).slice(2, 8);

/**
 * 本 isolate 内的请求序号：handler 入口 +1 后记进本次 trace。
 * 与 iso 一起读日志就能分清「同一个 isolate 上排队」和「请求换了 isolate」。
 */
let REQ_SEQ = 0;

// 站点登录 cookie 的**确切名字**。
// 两个用途：① classifyTier 判断「这份请求带不带登录态」；② `Netlify-Vary: cookie=<这个名字>`
// （第 21 条，除静态资源外**每个**响应都发）—— 防串号就靠它，名字错一个字母等于没有隔离。
// 只按名字取值判断，不解析、不验签、不看内容。
const SESSION_COOKIE = "zhuge_session";

/** 本次给 CDN 下的指令类别，唯一作用是观测（不进任何缓存判定）。 */
const CDN_STATE = "x-proxy-cdn";

/**
 * 兼容头：`x-proxy-cache`（第 26 条）。
 * 现有工具（如 `sample-proxy-cache.mjs`）按它分组采样，所以第 54 条之后**仍然保留**它，
 * 值由 CDN 指令折算（见 applyCdnPolicy）：
 *   匿名 public / 静态 public（这一份是回源取的、会交给 CDN 存）→ `miss`
 *   其余（private / no-store / 开关关闭）                          → `bypass`
 * 注意函数里已经没有缓存了，所以 `hit` 永远发不出来 —— CDN 命中时函数根本不执行，
 * 采样脚本的 `hit` 组今后会一直是空的，这是预期行为，不是回归。
 */
const CACHE_STATE = "x-proxy-cache";

// 源站用来声明「这份 HTML 可以按用户缓存」的响应头。本文件已经不做用户级缓存（第 54 条），
// 但它仍然属于源站内部信号，回浏览器前必须删干净（见 buildResponseHeaders）。
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

/**
 * 四档分流：匿名（可以让 CDN 缓存）/ 登录（绝不进 CDN）/ 直连（bypass）/ 静态资源。
 * 「静态」不是 classifyTier 的返回值，而是 handler 在分流前单独判出来的一档（isStaticRequest）。
 */
type Tier = "anon" | "user" | "bypass" | "static";

/** 本次响应给 CDN 下的指令（第 19/20 条）：只用于 trace 与 x-proxy-cdn 观测头。 */
type CdnPolicy = "anon" | "private" | "static" | "off";

/**
 * 链路追踪打点：只记时间与档位，不含任何缓存状态。
 *
 * 第 54 条之后函数内没有缓存了，原来那套 cacheMs / openMs / matchMs / putMs 全部作废：
 * 现在能报的只有「回源花了多久」和「给 CDN 下了什么指令」，后者就是 `cdn` 字段。
 *   · t0      进 handler
 *   · tFetch  发起回源
 *   · tUp     回源响应头到达（= 赢家那一路自己的耗时）
 *   · cdn     本次给 CDN 的指令（anon / private / static / off）
 * 上报是 fire-and-forget（ctx.waitUntil + fetch().catch），绝不 await，失败完全静默。
 */
type Trace = {
  t0: number;
  /** 本 isolate 的随机标识：只进 trace 日志，绝不进响应头。 */
  iso: string;
  /** 本 isolate 内的请求序号：只进 trace 日志，用来区分排队与换 isolate。 */
  seq: number;
  /** 发起回源 fetch 的时刻。 */
  tFetch?: number;
  /** 回源响应头到达（fetch 返回那一刻）；竞速时 = 赢家那一路的耗时。 */
  tUp?: number;
  /** 回源响应头 cf-ray 的后缀（`a51a…-HKG` → `HKG`），拿不到就是 `?`。 */
  colo?: string;
  /**
   * 竞速的赢家；非 GET 没有竞速记 `none`。
   * 静态档只有一路回源，赢家记 `static`，不占用 origin1 / origin2 的语义。
   */
  race?: "origin1" | "origin2" | "origin3" | "static" | "none";
  /** 静态资源档：命中/未命中都**不上报** trace（第 16 条）。只是标记位，不参与任何响应决策。 */
  static?: true;
  /** 本次给 CDN 下的指令（第 19/20/23 条）：anon / private / static / off。 */
  cdn?: CdnPolicy;
};

/** 慢请求判定阈值：上游 > 800ms 或 总时长 > 2000ms 必报；其余按 2% 随机采样对照。 */
const TRACE_UP_SLOW_MS = 800;
const TRACE_TOTAL_SLOW_MS = 2_000;
const TRACE_SAMPLE_RATE = 0.02;

/**
 * 设计上就慢、但**不是问题**的端点：不参与 trace 上报（2026-10-29）。
 *
 * `/api/device-wait` 是长轮询（挂 15 秒等推送），每次都会越过所有慢阈值。
 * 结果：Netlify 日志和 ip_logs 里堆满 `up=15002ms` 的假"慢请求"，
 * 真正的卡顿反而被淹掉。
 */
const LONG_POLL_PATHS: ReadonlySet<string> = new Set(["/api/device-wait"]);

/**
 * 本边缘函数当前跑在哪个区域（2026-10-29）。
 *
 * 站主的疑问是"同一用户为什么一会儿快一会儿慢"，而日志里的 `colo` 是 **CF 的机房**，
 * 不是 Netlify 把函数调度到了哪里。Netlify Edge 基于 Deno Deploy 系运行时，
 * 因此先取 `DENO_REGION`；再兜底几个常见环境变量。全都取不到就返回 "?"，
 * 那样日志里至少能看出"这个字段拿不到"，而不是猜一个值。
 */
function edgeRegion(): string {
  try {
    const env = (globalThis as { Deno?: { env?: { get(k: string): string | undefined } } }).Deno?.env;
    const v =
      env?.get("DENO_REGION") ??
      env?.get("DENO_DEPLOYMENT_ID_REGION") ??
      env?.get("AWS_REGION") ??
      (globalThis as { Netlify?: { context?: { server?: { region?: string } } } }).Netlify?.context
        ?.server?.region;
    return typeof v === "string" && v.length > 0 ? v : "?";
  } catch {
    return "?";
  }
}

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

/** 从回源响应头 `cf-ray`（形如 `a51a…-HKG`）取机房后缀；拿不到 / 不合格式都回 `?`。 */
function traceColo(res: Response): string {
  const match = /-([A-Z]{3})$/.exec((res.headers.get("cf-ray") ?? "").trim());
  return match !== null && match[1] !== undefined ? match[1] : "?";
}

/**
 * fire-and-forget 上报：绝不 await、绝不改响应、失败完全静默（第 25 条）。
 *
 * `cdn` 取代了原来紧跟在 proxy 后面的 cacheMs / open / match / put 四段（第 26 条）：
 * 函数里已经没有缓存可分段计时，现在只报「这次让 CDN 存不存、存多久」。
 * 日志字段顺序固定，方便正则切：
 *   /region=(\S+) cdn=(\S+) up=(\d+)ms total=(\d+)ms proxy=(\d+)ms race=(\S+) colo=(\S+) path=(\S+)/
 */
function reportTrace(
  ctx: Context,
  trace: Trace,
  requestUrl: URL,
  cdn: CdnPolicy,
  upstreamMs: number,
  totalMs: number,
  proxyMs: number,
  race: string,
): void {
  if (TARGET_BASE.length === 0) return;
  try {
    const path = normalizeTracePath(requestUrl.pathname);
    /**
     * 兼容字段 `cache`：源站 `app/routes/api.trace.tsx` 只认六种档位（hit / stale / miss /
     * bypass / hit-user / miss-user），而且它的字段白名单里**没有** cdn —— 所以 `cdn` 目前
     * 只进本函数的控制台日志，不落库。为了不让站主现有的「按 cache 分组」查询突然全变成
     * `cache=?`，这里把 CDN 指令映射回它认识的档位：
     *   匿名 public（这一份是回源取的、且交给 CDN 存）→ miss
     *   其余（private / 静态 / 开关关闭）              → bypass
     * 等源站加上 cdn 字段后，这段映射就可以删掉。
     */
    const cacheState = cdn === "anon" ? "miss" : "bypass";
    const body = JSON.stringify({
      path,
      // 2026-10-29（第 54 条）：这次给 CDN 下的指令（源站目前不落库，见上）。
      cdn,
      cache: cacheState,
      upstreamMs,
      totalMs,
      // 本代理自身耗时（Server-Timing 的 proxy;dur 同源），源站 /api/trace 只是多收一个字段。
      proxyMs,
      // 多路竞速的赢家（origin1 / origin2 / origin3 / static）；非 GET 没竞速，记 none。
      race,
      colo: trace.colo ?? "?",
      // **本函数自己跑在哪个区域**（不是 CF 的 colo）。站主反馈"一会儿快一会儿慢"的根因就是它：
      // Netlify 每次请求可能把函数调度到新加坡（出口 3.1.x → CF SIN）或美东（54.x → CF EWR）。
      // Deno Deploy 系运行时通过 DENO_REGION 暴露所在区域；取不到就记 "?"。
      region: edgeRegion(),
    });
    const colo = trace.colo ?? "?";
    // 一行结构化日志：Netlify 函数日志里 grep `[trace]` 就能直接看出慢在哪一段。
    // region = 本函数跑在哪个区域（Netlify 调度结果）；colo = CF 服务源站的那个机房。
    console.log(
      `[trace] region=${edgeRegion()} cdn=${cdn} cache=${cacheState} up=${upstreamMs}ms total=${totalMs}ms proxy=${proxyMs}ms race=${race} colo=${colo} path=${path} iso=${trace.iso} seq=${trace.seq}`,
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

/* ── 请求判定 ───────────────────────────────────────────────────────────── */

/** URL 上是否带 utm_* 之类的跟踪参数：带跟踪参数的响应绝不进 CDN（第 6 条）。 */
function hasTrackingParams(url: URL): boolean {
  let found = false;
  url.searchParams.forEach((_value, name) => {
    if (TRACKING_PARAMS.test(name)) found = true;
  });
  return found;
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

/** 路径 / 查询参数层面「允不允许交给 CDN 存」：两档共用同一套黑名单。 */
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

/* ── 静态资源档：识别 / content-type 白名单 ─────────────────────────────── */

/**
 * 静态档路径判定：**只看 pathname**。
 *   · /img/      站内图片（R2，key 内容寻址）
 *   · /assets/   React Router 构建产物（带哈希，IMMUTABLE_ASSET 那一套）
 *   · /frames/   头像框 SVG
 *   · /splash-*  根目录 iOS 启动图（只认 .png）
 *
 * query 不参与判定：同一张图带 `?r=3`（客户端破自己缓存）仍然是同一份资源。
 */
function isStaticPath(pathname: string): boolean {
  if (pathname.startsWith("/img/")) return true;
  if (pathname.startsWith("/assets/")) return true;
  if (pathname.startsWith("/frames/")) return true;
  return pathname.startsWith("/splash-") && pathname.toLowerCase().endsWith(".png");
}

/**
 * 静态档的请求资格：GET + 静态前缀 + **不带 Range**。
 * Range 请求（视频 / 断点续传要的是 206 + Content-Range）不接管，原样落回三档分流。
 */
function isStaticRequest(request: Request, url: URL): boolean {
  if (request.method !== "GET") return false;
  if (request.headers.has("range")) return false;
  return isStaticPath(url.pathname);
}

// content-type 白名单（比较时取分号前的主体、小写）：
// 图片 / SVG（image/*）、字体（font/*）、以及下面这些 JS / CSS / 老字体类型。
// **不包含** application/octet-stream、text/html、application/json：类型说不清就不交给 CDN 存，
// 否则一个「/assets/xxx 返回 200 + HTML 错误页」会被 CDN 固化 30 天。
const STATIC_CT_PREFIXES: readonly string[] = ["image/", "font/"];
const STATIC_CT_EXACT: readonly string[] = [
  "application/font-woff",
  "application/x-font-woff",
  "application/font-sfnt",
  "application/vnd.ms-fontobject",
  "application/svg+xml",
  "text/css",
  "text/javascript",
  "text/ecmascript",
  "application/javascript",
  "application/x-javascript",
  "application/ecmascript",
];

function isStaticContentType(headers: Headers): boolean {
  const base = ((headers.get("content-type") ?? "").split(";")[0] ?? "").trim().toLowerCase();
  if (base.length === 0) return false;
  for (const prefix of STATIC_CT_PREFIXES) {
    if (base.startsWith(prefix)) return true;
  }
  return STATIC_CT_EXACT.includes(base);
}

/**
 * 请求是否在「要页面」：`Accept` 含 `text/html` **或** 含通配媒体类型（星号/星号）都算。
 *
 * 为什么允许通配：通配是探测工具（itdog 这类 305 节点并发的批量探活）、爬虫、curl 的默认 Accept，
 * 它们本来就不带 cookie、也拿不到任何个性化内容。安全性不靠这条判据兜底：带 cookie /
 * authorization / range / upgrade 的请求在 isCacheable 里仍然硬拒绝，永远进不了匿名档，
 * 所以登录态与个性化 HTML 绝不会被「public 的那一份」覆盖。
 */
function acceptsHtml(header: string): boolean {
  const value = header.trim().toLowerCase();
  if (value.length === 0) return false;
  return value.includes("text/html") || value.includes("*/*");
}

/**
 * 匿名档的请求侧资格（第 5/6/7 条）：
 *   GET + 无 cookie / authorization / range / upgrade + Accept 要页面 + 路径与参数不在黑名单里。
 *
 * 第 54 条之后不再要求客户端支持 gzip：回源强制 identity（第 22 条），CDN 存下的那一份
 * 谁都能解，所以「能不能解压」不再是能不能进缓存的前提。
 */
function isCacheable(request: Request, url: URL): boolean {
  if (request.method !== "GET") return false;

  const headers = request.headers;
  if (headers.has("cookie") || headers.has("authorization") || headers.has("range") || headers.has("upgrade")) {
    return false;
  }
  // `text/html` 或 `*/*` 都算页面请求（见 acceptsHtml 里的安全说明）。
  if (!acceptsHtml(headers.get("accept") ?? "")) return false;

  return isCacheableTarget(url);
}

/**
 * 登录态的请求侧资格：cookie 里必须有 zhuge_session（由 classifyTier 先看），
 * 且同样避开私密路径与带 token 的 URL。
 *
 * 这一档**不会**被 CDN 缓存（响应固定 private, no-store），所以这里的判据只决定
 * 它走「竞速回源」还是「单路直连」——不再有任何编码 / 可存性条件。
 */
function isMemberCacheable(request: Request, url: URL): boolean {
  if (request.method !== "GET") return false;
  const headers = request.headers;
  if (headers.has("authorization") || headers.has("range") || headers.has("upgrade")) return false;
  return isCacheableTarget(url);
}

/**
 * 档位分流的唯一入口（静态档在 handler 里先判过，这里只返回另外三档）。
 * anon：GET + 无 cookie + Accept 含 text/html 或通配媒体类型（安全说明见 acceptsHtml）
 * user：GET + 带 zhuge_session
 * bypass：其余全部
 */
function classifyTier(request: Request, url: URL): Tier {
  if (request.method !== "GET") return "bypass";
  if (readSessionCookie(request) !== null) {
    return isMemberCacheable(request, url) ? "user" : "bypass";
  }
  return isCacheable(request, url) ? "anon" : "bypass";
}

/* ── 回源 ───────────────────────────────────────────────────────────────── */

type OriginOptions = {
  /**
   * 用 ORIGIN_TARGETS 里的第几项作为目标。
   * 竞速让每一腿打不同的域名，好让 BGP 可能选到不同机房。不传 = 第 0 项（主目标）。
   */
  targetIndex?: number;
  /**
   * 强制 accept-encoding: identity（匿名档必须，见第 22 条）。
   * CDN 会把这一份存下来发给任何人，所以只允许存「谁都能解」的原始字节；
   * 压缩交给 CDN 按客户端能力现场做。顺手删掉条件请求头：源站回 304（没有 body）时
   * 那份响应不能被 CDN 当成完整对象存下来。
   */
  forceIdentity?: boolean;
  /** 用「自身地址」做 referer：确定性，避免把别处的来源写进 CDN 存的那一份。 */
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

  if (options.forceIdentity === true) {
    // 匿名档 / 静态档：只要原始字节（第 22 条）。压缩交给外层 CDN 按客户端的 Accept-Encoding
    // 现场做 —— 缓存里绝不出现第二套编码，否则迟早把压缩体发给不认它的客户端。
    headers.set("accept-encoding", "identity");
    headers.delete("if-none-match");
    headers.delete("if-modified-since");
    headers.delete("if-range");
  }

  // 换目标（竞速每一腿打不同域名）：base / origin / host 都跟着这一腿走，
  // 否则源站看到的 Host 与实际目标不符，会按旧 Host 拼绝对地址或判错来源。
  const leg = ORIGIN_TARGETS[options.targetIndex ?? 0] ?? ORIGIN_TARGETS[0]!;
  const legOrigin = leg.origin;
  const legHost = leg.host;
  const base = leg.base;

  const origin = request.headers.get("origin");
  if (origin !== null && origin === proxyOrigin) headers.set("origin", legOrigin);

  const referer = headers.get("referer");
  if (referer !== null) {
    if (options.canonicalReferer) {
      headers.set("referer", `${legOrigin}${url.pathname}${url.search}`);
    } else if (referer === proxyOrigin || referer.startsWith(`${proxyOrigin}/`)) {
      headers.set("referer", `${legOrigin}${referer.slice(proxyOrigin.length)}`);
    }
  }

  const clientIp = request.headers.get("x-nf-client-connection-ip");
  if (clientIp !== null && clientIp.length > 0) headers.set("x-forwarded-for", clientIp);
  headers.set("x-forwarded-host", legHost);
  headers.set("x-forwarded-proto", "https");

  const target = `${base}${url.pathname}${url.search}`;
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

/* ── 多路回源竞速（2026-10-29）───────────────────────────────────────────── */

/**
 * 竞速赢家。`label` 除了三路回源，还允许 `static`：静态档只有一路回源，
 * 它的赢家记 `static`，不占用 origin1 / origin2 的语义（第 16 条）。
 */
type OriginWinner = {
  res: Response;
  label: "origin1" | "origin2" | "origin3" | "static";
  ms: number;
};

type OriginRace = {
  /** 第一路成功返回的回源（含它自己的耗时）；所有腿都失败时 reject，错误原样交给调用方。 */
  winner: Promise<OriginWinner>;
  /** 已经不需要回源（目前没有调用点）：立刻 abort 所有还没回来的腿。 */
  abort: () => void;
};

/**
 * 启动多路回源竞速（只给 GET 用）：
 *   o1 = fetchOrigin(req)
 *   o2 = fetchOrigin(req.clone())
 * 谁先成功用谁，赢家一出现立刻 abort 剩下的腿。
 * 失败不在这里吞：所有腿都 reject 时 winner 也 reject，调用方照旧走 502 错误路径。
 */
function startOriginRace(request: Request, url: URL, options: OriginOptions): OriginRace {
  // 腿数 = 配置了几个目标（1~3）。1 个目标时退化成单路回源，不做竞速。
  const labels = ["origin1", "origin2", "origin3"] as const;
  const legCount = Math.max(1, RACE_LEGS);
  const controllers: AbortController[] = Array.from({ length: legCount }, () => new AbortController());
  let decided = false;
  let abandoned = false;
  let settledWinner: OriginWinner | null = null;

  const legs: Array<Promise<OriginWinner>> = controllers.map((controller, index) => {
    // 除第一路外都用 clone：各腿消费自己的 body（GET 没有 body，这里照样 clone，
    // 免得以后被复用到带 body 的方法上时几腿互相锁死）。
    const attempt = index === 0 ? request : request.clone();
    const startedAt = Date.now();
    /**
     * 2026-10-29：**每一腿打不同的域名**（第 index 个目标）。
     *
     * 起因：站主发现"同一用户一会儿快一会儿慢"，实测同一个出口 IP 会被 CF 分到
     * SIN / EWR / IAD / **MRS（马赛）** 等不同机房——`region=aws-ap-southeast-1` 却
     * `colo=MRS`。而两路都打同一个目标域名时，CF 看到的目标 IP 相同、BGP 路径相同，
     * 竞速拿到的就是"两次同样的慢"（实测 1456ms → 1533ms，无收益）。
     *
     * 不同 zone 的域名宣告的是**不同 anycast IP 段**，BGP 可能选到不同的机房。
     * 于是第二路打备用域：如果两条路真的分开，竞速就能挑到快的那个机房；
     * 如果还是没变化，就说明这段网络确实只有一条路，可以彻底收手。
     *
     * 正确性：og:url / 分享链接用的是常量 `SITE_ORIGIN`（apex），与请求 Host 无关；
     * 会话 cookie 只按名字读取，也与 Host 无关（反代还会剥掉 Set-Cookie 的 Domain）。
     */
    // 每一腿打 ORIGIN_TARGETS[index]（第 0 项是主目标，其余是备用域）。
    const legOptions: OriginOptions = { ...options, signal: controller.signal, targetIndex: index };
    return fetchOrigin(attempt, url, legOptions).then((res) => {
      const value: OriginWinner = {
        res,
        label: (labels[index] ?? "origin1") as "origin1" | "origin2" | "origin3",
        // 上面这个 cast 只覆盖回源那三路；静态档的 label 由 serveStatic 自己构造。
        ms: Math.max(0, Date.now() - startedAt),
      };
      if (decided) {
        // 已经有人赢了：这一路白跑，body 立刻取消，别留一条没人读的流。
        void discard(res);
      } else {
        decided = true;
        // 赢家出现 → 立刻 abort 剩下的腿。
        for (let i = 0; i < controllers.length; i += 1) {
          if (i !== index) controllers[i]?.abort();
        }
      }
      return value;
    });
  });

  const winner = Promise.any(legs);
  // 外部 abort 时所有腿都 reject：这里先挂处理器，避免 unhandled rejection。
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
 * 源站有没有**明确禁止**缓存这份 HTML。
 *
 * 只有 `no-store` 与 `Vary: *` 是硬拒绝；`private, no-cache` 放行 —— 源站对匿名 HTML 固定这么返回，
 * 拒绝它等于匿名档彻底没有缓存（改前就是这条理由，现在依然成立）。匿名性由请求侧保证：
 * 带 cookie / authorization / range / upgrade 的请求根本进不了匿名档。
 *
 * 这里只看「能不能让 CDN 存」，不决定 TTL，也不看 content-encoding（那条由 applyCdnPolicy 单独卡）。
 */
function isStorable(headers: Headers): boolean {
  const contentType = (headers.get("content-type") ?? "").toLowerCase();
  if (!contentType.includes("text/html")) return false;
  const cacheControl = (headers.get("cache-control") ?? "").toLowerCase();
  if (cacheControl.includes("no-store")) return false;
  if ((headers.get("vary") ?? "").trim() === "*") return false;
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
  // 源站内部信号，绝不回传浏览器（也不许它参与 CDN 判定）。
  out.delete(ORIGIN_USER_MARK);

  // 内容寻址的哈希资源可以放心 immutable：文件名变了 URL 就变了（第 15 条）。
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
 * ── Server-Timing ────────────────────────────────────────────────────────
 *
 * 目标：让一次请求能拼出完整的分段表 ——
 *   浏览器 DNS/TCP/TLS/TTFB（netcheck 已有，本文件不管）
 *   → 反代内部 `proxy;dur`（本文件）
 *   → 反代→Worker 往返（trace 的 `up`）
 *   → Worker 内部 `d1` / `ssr` / `app`（源站 Server-Timing，本文件透传）。
 *
 * `proxy;dur` = 「进 handler → 发起回源」的纯代理开销（收 POST body / 竞速起跑 / 改头都算在内）。
 * `total;dur` = 收到请求 → 交出首字节前，**反代视角的整段服务时长**；
 * 客户端拿它才能把「用户 → 反代」那段减出来：`responseStart - requestStart - total`。
 *
 * 第 54 条之后每次响应都来自源站（没有缓存回放），源站的 d1 / ssr / app 永远是真数，
 * 所以**无条件透传**（原来还要判断「这份是不是缓存回放的旧数」，那个分支随缓存一起删了）。
 * 合并按 RFC 8941 的列表语义：源站指标在前，逗号 + `proxy;dur` + `total;dur` 追加在后；
 * 源站一个都没有时只输出这两条。上限 5 个：源站固定 3 个（d1/ssr/app）+ 代理 2 个，正好顶格。
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

function withServerTiming(res: Response, proxyMs: number, totalMs: number): Response {
  try {
    const headers = new Headers(res.headers);
    const merged = splitServerTiming(headers.get("server-timing") ?? "").slice(
      0,
      MAX_SERVER_TIMING_METRICS - 2,
    );
    merged.push(`proxy;dur=${Math.max(0, Math.round(proxyMs))}`);
    // 反代视角整段：收到请求 → 交出首字节。与 proxy 的差就是回源往返（up）。
    merged.push(`total;dur=${Math.max(0, Math.round(totalMs))}`);
    headers.set("server-timing", merged.join(", "));
    return withBody(res, headers);
  } catch {
    return res;
  }
}

/**
 * 回源响应的统一收尾（原来 processOrigin 里「改写」的那一半）。
 *
 * 只做四件事：删内部头 / Set-Cookie 去 Domain（第 10 条）/ Location 改写（第 9 条）/ CORS 改写（第 11 条）。
 * **不再删 content-length**：改前删它是因为 body 被 tee 过、帧长由我们自己重算；
 * 第 54 条之后 body 原样透传，长度仍然是源站声明的那个，删了反而要平台重新 chunked。
 */
function processOrigin(res: Response, requestUrl: URL, proxyOrigin: string, method: string): Response {
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
  return withBody(res, out);
}

/* ── 给 CDN 下指令（第 19/20/21/23 条、第 54 条）─────────────────────────── */

const CDN_CACHE_CONTROL = "netlify-cdn-cache-control";
const CDN_VARY = "netlify-vary";

/**
 * 给 CDN 下指令。**所有返回点都经过这里**（handler 只有一个出口，连 TARGET_URL 缺失的 500 也走这里），
 * 这样就不存在「某条分支忘了写头、CDN 按默认策略乱存」的可能。
 *
 * 缓存指令判定只看「这份响应能不能给所有人看」，与档位标签分开：
 *   · 匿名档 + GET + 200 + 无 Set-Cookie + 无跟踪参数 + identity + text/html
 *       → public, max-age=ANON_TTL_S, stale-while-revalidate=ANON_SWR_S
 *   · 静态档 + GET + 200 + 无 Set-Cookie + identity + 类型在白名单
 *       → public, max-age=STATIC_TTL_S, immutable
 *   · 其余（登录态 / POST / 3xx / 4xx / 5xx / 带 Set-Cookie / 带跟踪参数 / 源站 no-store）
 *       → private, no-store
 *
 * **Netlify-Vary 是另一条独立的判定，只看 pathname（第 21 条、第 54 条的一致性铁律）**：
 *   · 静态资源（isStaticPath）→ 一律不发；
 *   · 其余所有 URL          → 一律发同一行 `cookie=zhuge_session`，
 *     不管它是登录态、private/no-store、POST、3xx、502 还是 500。
 * 为什么不能「只有 public 才发」：同一个 URL 的**第一份响应**说了算，后面发的会被忽略。
 * 只要登录用户先访问过一次那个 URL（响应是 private/no-store、没发 Vary），这个 URL 的缓存键就被
 * 定成「只看 URL」，之后匿名档再发 `cookie=…` 也无效，匿名副本照样按「只看 URL」存进去，
 * 下一个登录用户就会命中它 —— 串号是必然，不是概率。所以判据必须与「这份响应能不能存」正交。
 */
function applyCdnPolicy(
  response: Response,
  tier: Tier,
  url: URL,
  method: string,
): { response: Response; cdn: CdnPolicy } {
  // 第 23 条：一键止血 —— 一个 CDN 头都不加（连 Vary / x-proxy-cdn 都不加），等于每次请求都穿透源站。
  if (!CDN_CACHE_ENABLED) return { response, cdn: "off" };

  try {
    const headers = new Headers(response.headers);

    // ① 先定 Vary：只跟 URL 空间走，与下面的 public/private 判定完全无关（一致性铁律）。
    if (!isStaticPath(url.pathname)) headers.set(CDN_VARY, `cookie=${SESSION_COOKIE}`);

    // ② 再定缓存指令。
    const encoding = (headers.get("content-encoding") ?? "").trim().toLowerCase();
    // 只允许存 identity：带编码的对象一旦被 CDN 按「无编码」回放，浏览器解出来就是坏内容。
    // 匿名档 / 静态档都强制 identity 回源（第 22 条），所以这条正常情况下永远成立。
    const identity = encoding.length === 0 || encoding === "identity";
    const noCookies = getSetCookies(headers).length === 0;
    const base = method === "GET" && response.status === 200 && noCookies && identity;

    if (tier === "anon" && base && !hasTrackingParams(url) && isStorable(response.headers)) {
      headers.set(
        CDN_CACHE_CONTROL,
        `public, max-age=${ANON_TTL_S}, stale-while-revalidate=${ANON_SWR_S}`,
      );
      /**
       * 2026-10-29 线上实测：光设 `Netlify-CDN-Cache-Control` **不够**。
       *
       * 源站对匿名 HTML 发的是 `Cache-Control: private, no-cache`（登录态语义），
       * 这个 `private` 是"禁止任何共享缓存存储"的硬指令，于是 CDN 根本没存：
       * 连打三次同一 URL，三次都是 `X-Proxy-Cache: miss`（函数每次都执行）。
       *
       * 所以必须把**浏览器侧**的头一起改掉，否则 `Netlify-CDN-Cache-Control` 被无视：
       *   · `private` → `public`（允许共享缓存存储）
       *   · `max-age=0, must-revalidate` → 浏览器每次都回源校验（拿到的一定是新鲜内容），
       *     真正的缓存时长由 `Netlify-CDN-Cache-Control` 决定，两者互不干扰
       *   · 顺手删 `Expires` / `Pragma`：老式"不缓存"指令，会让某些代理层再次拒绝存储
       */
      headers.set("cache-control", "public, max-age=0, must-revalidate");
      headers.delete("expires");
      headers.delete("pragma");
      // x-proxy-cache 兼容（第 26 条）：这一份是回源取的、并且会交给 CDN 存 ⇒ 与旧的 miss 等价。
      headers.set(CACHE_STATE, "miss");
      headers.set(CDN_STATE, "anon");
      return { response: withBody(response, headers), cdn: "anon" };
    }

    if (tier === "static" && base && isStaticContentType(response.headers)) {
      headers.set(CDN_CACHE_CONTROL, `public, max-age=${STATIC_TTL_S}, immutable`);
      // 同上：源站可能带 `no-cache`/`private`，会把 CDN 挡住。静态资源本来就不该让浏览器
      // 每次校验，所以这里给长 max-age，与 CDN 的 30 天对齐。
      headers.set("cache-control", `public, max-age=${STATIC_TTL_S}, immutable`);
      headers.delete("expires");
      headers.delete("pragma");
      headers.set(CACHE_STATE, "miss");
      headers.set(CDN_STATE, "static");
      return { response: withBody(response, headers), cdn: "static" };
    }

    headers.set(CDN_CACHE_CONTROL, "private, no-store");
    headers.set(CACHE_STATE, "bypass");
    headers.set(CDN_STATE, "private");
    return { response: withBody(response, headers), cdn: "private" };
  } catch {
    // 改头失败：宁可不加头（退回平台默认，等于不缓存），也绝不因此 5xx。
    return { response, cdn: "off" };
  }
}

/* ── 回源：GET 多路竞速 / 非 GET 单路 ───────────────────────────────────── */

/** 回源赢家的统一收尾：先把 trace 的分段记下来，再交给 processOrigin 改写。 */
function finishOrigin(winner: OriginWinner, url: URL, trace: Trace): Response {
  trace.tUp = (trace.tFetch ?? Date.now()) + winner.ms;
  trace.colo = traceColo(winner.res);
  trace.race = winner.label;
  return processOrigin(winner.res, url, url.origin, "GET");
}

/**
 * GET 一律多路回源竞速（第 3 条）：配了几个目标就打几路（1~3），谁先给出响应头用谁。
 * 第 54 条之后没有「缓存那一路」了，所以这里只剩回源之间互相竞速。
 */
async function serveGet(request: Request, url: URL, trace: Trace, options: OriginOptions): Promise<Response> {
  trace.tFetch = Date.now();
  const race = startOriginRace(request, url, options);
  let winner: OriginWinner;
  try {
    winner = await race.winner;
  } catch {
    trace.race = "none"; // 所有腿都失败：原来的错误路径
    return text(502, "Bad Gateway");
  }
  return finishOrigin(winner, url, trace);
}

/**
 * 非 GET 一律不竞速（第 4 条）：写操作翻倍且无法取消，只能原样单路回源。
 * 登录态、匿名、bypass 三档在写操作上完全一样：都只负责把响应原样改写后交回去。
 */
async function serveWrite(request: Request, url: URL, trace: Trace): Promise<Response> {
  trace.race = "none";
  let originRes: Response;
  try {
    trace.tFetch = Date.now();
    originRes = await fetchOrigin(request, url, { canonicalReferer: false });
    trace.tUp = Date.now(); // 回源响应头到达
    trace.colo = traceColo(originRes);
  } catch {
    return text(502, "Bad Gateway");
  }
  return processOrigin(originRes, url, url.origin, request.method);
}

/**
 * 静态档：**唯一一路**回源（第 16 条），不竞速 —— 图片多跑一次只是一次 R2 读、零 D1，
 * 但白跑一路没有任何收益（没有缓存那一路可以和它抢）。命不命中 CDN 都不上报 trace。
 */
async function serveStatic(request: Request, url: URL, trace: Trace): Promise<Response> {
  trace.static = true;
  const startedAt = Date.now();
  trace.tFetch = startedAt;
  try {
    const res = await fetchOrigin(request, url, { forceIdentity: true, canonicalReferer: false });
    return finishOrigin({ res, label: "static", ms: Math.max(0, Date.now() - startedAt) }, url, trace);
  } catch {
    trace.race = "none";
    return text(502, "Bad Gateway");
  }
}

/* ── 入口 ───────────────────────────────────────────────────────────────── */

export default async function handler(request: Request, ctx: Context): Promise<Response> {
  const t0 = Date.now(); // 链路追踪：进函数
  // 本 isolate 的第几个请求：只进 trace 日志。计数放在最前面，连配置缺失的 500 也算一次。
  REQ_SEQ += 1;
  const seq = REQ_SEQ;
  const url = new URL(request.url);

  // 配置缺失：连档位都判不了，直接 500。**但仍然走 applyCdnPolicy** —— 否则这条响应不带
  // Netlify-Vary，会把这个 URL 的 Vary 指令钉成「只看 URL」，配好之后匿名副本就再也分不开键了
  // （第 54 条的一致性铁律：一个 URL 的**第一份**响应说了算）。
  if (TARGET_URL === null || TARGET_ORIGIN.length === 0) {
    return applyCdnPolicy(
      text(500, "TARGET_URL environment variable is missing or invalid"),
      "bypass",
      url,
      request.method,
    ).response;
  }

  const trace: Trace = { t0, iso: ISOLATE_ID, seq };

  // 静态资源档在分流之前单独判一次：GET + 静态前缀 + 无 Range 才接管（第 16 条）。
  const tier: Tier = isStaticRequest(request, url) ? "static" : classifyTier(request, url);

  let response: Response;
  if (tier === "static") {
    response = await serveStatic(request, url, trace);
  } else if (request.method !== "GET") {
    response = await serveWrite(request, url, trace);
  } else if (tier === "anon") {
    // 匿名档：CDN 会存这一份，所以强制 identity（第 22 条）；
    // referer 用自身地址，保证「同一个 URL 存下来的那一份」不随触发者漂移。
    response = await serveGet(request, url, trace, { forceIdentity: true, canonicalReferer: true });
  } else {
    // 登录态 / bypass：不经过 CDN 存储，按客户端自己的 accept-encoding 透传。
    response = await serveGet(request, url, trace, {
      forceIdentity: false,
      canonicalReferer: tier === "user",
    });
  }

  // ── 链路追踪上报 + 给 CDN 下指令（tEnd 在这里：返回响应前）────────────────
  const tEnd = Date.now();
  const totalMs = Math.max(0, tEnd - t0);
  // up = 「发起 fetch → 拿到响应头」的实际耗时；没有回源（只可能是 500/502 早退）记 0。
  const upstreamMs = trace.tFetch === undefined ? 0 : Math.max(0, (trace.tUp ?? tEnd) - trace.tFetch);
  // proxy = 进函数 → 发起回源；竞速后回源在 handler 一进来就发，所以它只剩这点开销。
  const proxyMs = trace.tFetch === undefined ? totalMs : Math.max(0, trace.tFetch - t0);
  const raceName = trace.race ?? "none";

  // 给 CDN 下指令 / 发 Netlify-Vary：**所有**返回点都经过这里（含上面的 500），
  // 不存在「某条分支忘了写头」或「同一个 URL 时而发 Vary 时而不发」的可能（第 21/24 条）。
  const policy = applyCdnPolicy(response, tier, url, request.method);
  trace.cdn = policy.cdn;

  try {
    const sample = Math.random() < TRACE_SAMPLE_RATE;
    // 静态档一律不报（第 16 条）：/img/* 一次首屏就十几二十条，写进 ip_logs 会把日志表刷爆。
    // 长轮询（第 17 条）按设计就慢，同样不报。
    if (trace.static !== true && !LONG_POLL_PATHS.has(url.pathname)) {
      const slow = upstreamMs > TRACE_UP_SLOW_MS || totalMs > TRACE_TOTAL_SLOW_MS;
      if (slow || sample) {
        reportTrace(ctx, trace, url, policy.cdn, upstreamMs, totalMs, proxyMs, raceName);
      }
    }
  } catch {
    // 埋点自身任何异常一律吞掉：响应保持不变
  }

  // Server-Timing：透传源站的 d1/ssr/app，追加本代理的 proxy;dur 与 total;dur。
  // total 用的是上面这一刻的 tEnd（返回响应前），所以包含到「交出首字节」为止的全部反代时间。
  return withServerTiming(policy.response, proxyMs, totalMs);
}
