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
// 10. 写缓存/命中路径都删掉 content-length：body 已由我们自己重新构造，帧长交给运行时；
//     条目里另存 x-proxy-bytes 记录"写进去的真实字节数"，命中时用它做完整性校验（第 48 条）。
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
//
// ── 第四档：静态资源缓存（2026-10-29）───────────────────────────────────────
// 39. 静态档是**独立一档**：独立 cache 名、独立键空间、独立时间窗。anon/user 的判据（Accept / cookie /
//     gzip / epoch）与它无关，混进去只会让那两档的键多出维度、TTL 互相迁就。
//     唯一入口是 handler 里的 isStaticRequest：GET + 静态前缀 + 无 Range；不匹配就完全走原来的三档。
// 40. 判据只看 pathname（/img/ /assets/ /frames/ /splash-*.png），query 只进缓存键：
//     同一张图带 `?r=3`（客户端破自己缓存）仍是同一份资源，让 query 参与判据会把它踢出静态档。
// 41. 静态档的回源只有**一路**（不 clone 请求、不 startOriginRace），但缓存探测与这一路是**并行**的：
//     缓存先赢就 abort 它，回源先赢就用它、忽略缓存那一路。理由：图片多跑一次只是一次 R2 读、零 D1，
//     这点代价换来「Cache API 卡住（实测过 11s）也不拖住图片」；而两路回源就没有必要了。
// 42. 静态档不报 trace（命中/未命中都不报）：/img/* 一次首屏就十几二十条，写进 ip_logs 会把日志表刷爆。
// 43. 写入门槛比 HTML 严：200 + content-type 白名单 + 无 Set-Cookie；401/403/404、HTML 错误页、
//     application/octet-stream 一律交给原来的 bypass 收尾 —— 宁可多回源一次，也不把一次失败固化 30 天。
// 44. 硬过期（age > SWR 30 天）先删条目再回源：这才是真的「重取」，否则条目永远占着 match 的位置。
// 45. 静态条目只允许 identity（不带 content-encoding）：键里没有 accept-encoding 维度，压缩体一旦
//     被任何一层按「无编码」回放，浏览器解出来就是坏图。压缩交给外层 CDN 按客户端能力现场做。
//
// ── 静态档完整性修复（2026-10-29 线上事故）───────────────────────────────────
// 46. 事故复盘：线上 comet.svg 的条目/回放体是 **完整的 zstd 体**（1715 → 774 字节，解压后逐字节等于源站），
//     不是 tee 截断；坏在它被**按 identity 回放**（响应里没有 content-encoding）。静态键没有编码维度，
//     只要压缩体在某一层丢了 CE 头，浏览器就会把 774 字节压缩数据当 SVG 解析 → 头像框全破。
//     所以静态档回源**强制 identity**，缓存里只存原始字节，客户端拿到的也永远是原始字节。
//     压缩交给外层 CDN 按客户端 Accept-Encoding 现场做（它会正确写上自己用的 CE）。
// 47. 写缓存不再 tee：先把 body 完整读成一段字节（≤ 2MiB），再用同一段字节分别构造「写缓存」和
//     「给客户端」两个**独立 Response**。tee 的两半共享底层流，任何一半被 cancel/abort 都可能让另一半
//     读不完；独立字节没有这个耦合，也不再有「哪条分支先被放掉」的时序问题。
// 48. 命中前必须把条目**完整读出来校验**：字节数必须等于条目里记的 x-proxy-bytes，且不能带
//     content-encoding；任何一项不满足都当 miss 并删除条目（宁可不缓存，也不能回放坏条目）。
// 49. 校验失败一律不写缓存：content-length 对不上（源站截断）、超过 2MiB、读失败 → 不缓存；
//     截断的 body 直接 502，绝不把半截当 200 发出去。
//
// ── isolate 内两级内存镜像（2026-10-29）──────────────────────────────────────
// 50. 生产 trace 分组实测（平均）：bypass 2ms / hit 601ms / miss 1240ms，bypass 与 hit 的差
//     全在 Cache API —— 在这个边缘，**一次 caches.open + match 就要 0.3~0.6 秒**，而几乎
//     每个请求都要付一次。所以匿名档在模块作用域再加一层内存镜像：正缓存 4s（命中直接用存下
//     的字节重建 Response，完全不碰 Cache API）、负缓存 3s（刚确认过 miss 就直接跳过查询）。
//     写入成功后立刻清掉负标记 —— 否则突发时第一条 miss 会把后面几百条都锁在「不查缓存」上，
//     它们也就永远看不到刚写进去的条目，缓存收益全丢。
//     上限 12 条 / 24MiB，按插入顺序淘汰最老的；任何异常静默降级回原有路径。
//     只服务匿名 GET，带跟踪参数的请求不进镜像；三档判定、竞速、header 改写、trace 字段一律不动。
//
// ── 缓存句柄上提 / 计时拆分 / isolate 维度（2026-10-29）──────────────────────
// 51. `caches.open()` 提到模块作用域，每个 isolate 只开一次：实测 hit 均值 601ms / miss 1240ms，
//     但 hit 最小值只有 3ms —— 快路径证明这笔开销不是固有的，而是「几乎每个请求都重新 open」。
//     Netlify 文档明确允许把 open 提到顶层（只有 match/put/delete 必须在请求内），所以 open 只留
//     在 isolate 的第一个请求上，之后直接复用同一个 Promise。
//     计时同时拆成 openMs / matchMs 两段（cacheMs 的口径不变，仍是「进函数 → 查询结束」，
//     即 open + match 的总和，日志兼容）：不拆的话「open 慢」和「match 慢」挤在一个数里，
//     改哪一边都只能靠猜；拿不到就记 0。
//     另加 isolate 维度：`iso` 是本 isolate 的随机 6 位标识，`seq` 是本 isolate 内第几个请求。
//     二者**只进 trace 日志、绝不进响应头**。用途：seq 连续且 iso 相同的一段里 cacheMs 一起变大，
//     说明是同一 isolate 上在缓存后端排队 / 冷连接；换了 iso 才变慢，说明是新 isolate 的冷启动。
//     降级语义不变：open 失败时把句柄槽位置回 null（下一个请求重试），本次按「这一档没有缓存」走，
//     四个调用点照旧各自 catch，绝不 5xx。
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

const CACHE_VERSION = "v4";
// BUILD_ID 只在这里读一次（Deno.env 在本文件的类型检查里没有声明，多处引用只会多几条同类错误）。
// 行为与原来逐字等价：两档 cache 名的后缀仍是同一个 BUILD_ID，取不到仍是 "static"。
const BUILD_ID: string = Deno.env.get("BUILD_ID") ?? "static";
const CACHE_NAME = `zhuge-anon-${CACHE_VERSION}-${BUILD_ID}`;

// 匿名档窗口（2026-10-29 放大：批量探测 305 节点并发要能落在同一个热条目上）
// 注意：这组常量是**匿名档专属**，成员档用下面独立的 USER_* 一组，改这里不影响成员档。
const FRESH_MS = 300_000; // 5min：命中即回，不再回源
const SWR_MS = 600_000; // 10min：命中旧副本 + 后台刷新
const HARD_STALE_MS = 900_000; // 15min：只在源站 5xx/超时时才肯拿出来的最旧副本
const STORE_TTL_S = 1_080; // 18min：必须 > HARD_STALE_MS，否则兜底时条目已经没了

// ── isolate 内两级内存镜像（第 50 条）：只服务匿名档，纯加速层，删掉即回到原行为 ──
// 正缓存 4s：这段时间内再次请求同一个 path+query，直接用内存里的字节重建 Response，不碰 Cache API。
// 负缓存 3s：刚确认过 miss，这段时间内直接跳过 caches.open/match；写入成功会立刻清掉它。
const MIRROR_MS = 4_000; // 正缓存 TTL
const MISS_MIRROR_MS = 3_000; // 负缓存 TTL
const MIRROR_MAX_ENTRIES = 12; // 每张表各自的条目上限
const MIRROR_MAX_BYTES = 24 * 1024 * 1024; // 正缓存字节上限

// 用户桶窗口：更宽松，但失效靠 epoch 而不是靠时间
const USER_FRESH_MS = 120_000; // 120s
const USER_SWR_MS = 300_000; // 300s
const USER_HARD_STALE_MS = 600_000; // 600s
const USER_STORE_TTL_S = 720; // 必须 > USER_HARD_STALE_MS
const EPOCH_TTL_S = 7 * 24 * 3_600; // epoch 条目必须活得比任何页面条目都久

// ── 第四档（静态资源）窗口：与上面两组完全独立，改这里不影响 anon / user 任何一档 ──
// v2（2026-10-29）：条目语义从「源站给什么编码就存什么」改成「只存 identity」，
// 旧的 v1 条目带压缩体，必须物理隔离；换版本号后即使 BUILD_ID 缺失（回落到 "static"）也读不到旧条目。
const STATIC_CACHE_VERSION = "v2";
// 独立 cache 名：静态档的条目与 anon/user 的 HTML 条目物理隔离，键空间也互不可见。
const STATIC_CACHE_NAME = `zhuge-static-${STATIC_CACHE_VERSION}-${BUILD_ID}`;
const STATIC_FRESH_MS = 7 * 24 * 3_600_000; // 7 天：纯新鲜窗口（分档见 staticAgeOf）
const STATIC_SWR_MS = 30 * 24 * 3_600_000; // 30 天：SWR 窗口上界，同时就是硬过期点
const STATIC_STORE_TTL_S = 30 * 24 * 3_600; // 30 天：= SWR；硬过期后由下一次请求删掉重取
// 单个静态条目的大小上限：超过就不进缓存、直接回源透传（读入内存的上限，见第 47/49 条）。
// 2026-10-29 站主："站里本来最大就 5mb" ⇒ 上限从 2MiB 提到 8MiB，覆盖上传上限并留余量。
// 原来 2MiB 会把 4MB 的图挡在缓存外（而且超限分支没回退透传，直接断了连接）。
const STATIC_MAX_CACHE_BYTES = 8 * 1024 * 1024;
// 条目内部记录「实际写进缓存的字节数」：命中时用它校验完整性（不依赖会被框架/平台改写的 content-length）。
const STATIC_BYTES = "x-proxy-bytes";
// 键的内部固定 origin：不含 cookie / theme / epoch，也不与 cache.invalid 的两种 HTML 键重叠。
const STATIC_KEY_ORIGIN = "https://static-cache.internal";
// 条目里没记到源站原值时的兜底（源站对这些资源实际发的是 immutable 1 年）。
const STATIC_DEFAULT_CC = "public, max-age=31536000, immutable";

/* ── 缓存句柄上提 + isolate 维度（第 51 条）────────────────────────────────── */

/**
 * 本 isolate 的随机标识：只用于把 trace 日志按 isolate 分组，**绝不进响应头**（避免泄漏部署细节）。
 */
const ISOLATE_ID = Math.random().toString(36).slice(2, 8);

/**
 * 本 isolate 内的请求序号：handler 入口 +1 后记进本次 trace。
 * 与 iso 一起读日志就能分清「同一个 isolate 上排队」和「请求换了 isolate」。
 */
let REQ_SEQ = 0;

/**
 * 每个 isolate 只 `caches.open()` 一次，之后所有请求复用同一个 Promise（第 51 条）。
 *
 * 为什么可以上提：Netlify 文档明确说 open 可以提到模块顶层，只有 match / put / delete 必须在请求内。
 * 上提之后 open 只在这个 isolate 的第一个请求上真正花钱，cacheMs 剩下的部分才是 match 的成本。
 *
 * 降级语义与原来一致：open 失败 = 「这一档没有缓存」。
 * 失败时把槽位置回 null，下一个请求会重新 open（否则一个 isolate 会永久失去缓存）；
 * reject 原样抛给调用方 —— 四个调用点本来就都包在 try/catch 里，最终只是本次不回写、绝不 5xx。
 *
 * 本文件只有两个 cache 名：CACHE_NAME（匿名 / 登录两档共用）与 STATIC_CACHE_NAME（静态档），
 * 各占一个槽位；不传参就是 HTML 那两档。
 */
let cachePromise: Promise<Cache> | null = null;
let staticCachePromise: Promise<Cache> | null = null;

function getCache(name: string = CACHE_NAME): Promise<Cache> {
  const isStatic = name === STATIC_CACHE_NAME;
  const pending = isStatic ? staticCachePromise : cachePromise;
  if (pending !== null) return pending;

  let created: Promise<Cache>;
  try {
    created = caches.open(name);
  } catch (err) {
    // 运行时没有 Cache API（或 open 同步抛错）：不占槽位，本次直接降级成「没有缓存」。
    return Promise.reject(err instanceof Error ? err : new Error(String(err)));
  }

  if (isStatic) staticCachePromise = created;
  else cachePromise = created;

  // 失败就把槽位摘掉，允许下一个请求重试；这个 catch 同时保证失败的 Promise 有处理器
  // （不会变成 unhandled rejection），而 reject 本身仍原样返回给调用方。
  created.catch(() => {
    if (isStatic) {
      if (staticCachePromise === created) staticCachePromise = null;
    } else if (cachePromise === created) {
      cachePromise = null;
    }
  });

  return created;
}

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
  /** 本 isolate 的随机标识（第 51 条）：只进 trace 日志，绝不进响应头。 */
  iso: string;
  /** 本 isolate 内的请求序号（第 51 条）：只进 trace 日志，用来区分排队与换 isolate。 */
  seq: number;
  /** 缓存查询结束；直连档没有缓存查询，取 t0。 */
  tCache?: number;
  /**
   * `caches.open()` 那一段的耗时（第 51 条）。open 已在模块级缓存，除 isolate 首个请求外恒为 0；
   * 没走缓存探测（镜像命中 / 负缓存 / 直连档）时保持 undefined，上报时按 0 处理。
   */
  openMs?: number;
  /**
   * `cache.match()` 那一段的耗时（第 51 条）；用户档的 epoch 读取不在这两段里，
   * 但仍算在 cacheMs 内（cacheMs 口径不变，见第 51 条）。
   */
  matchMs?: number;
  /** 发起回源 fetch 的时刻；没有回源（缓存命中）时为空。 */
  tFetch?: number;
  /** 回源响应头到达（fetch 返回那一刻）；竞速时 = 赢家那一路的耗时。 */
  tUp?: number;
  /** 回源响应头 cf-ray 的后缀（`a51a…-HKG` → `HKG`），拿不到就是 `?`。 */
  colo?: string;
  /**
   * 竞速的赢家；没有竞速（非 GET）时是 `none`。
   * 静态档只有一路回源，赢家记 `static`（缓存赢仍记 `cache`），不占用 origin1 / origin2 的语义。
   * 注意：静态档恒不上报（trace.static），这个值只在本进程内用于分段计时与日志判读。
   */
  race?: "cache" | "origin1" | "origin2" | "origin3" | "static" | "none";
  /** 缓存查询最终完成（即使响应已经返回）：回源先赢时用它补报真实的 cacheMs。 */
  cacheSettled?: Promise<void>;
  /**
   * 静态资源档（第四档）：命中/未命中都**不上报** trace（第 42 条）。
   * 只是个标记位，trace 里其它字段照旧填（Server-Timing 还在用它们），不参与任何响应决策。
   */
  static?: true;
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
 * 真正的卡顿（比如缓存卡 11 秒）反而被淹掉。
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
      // 2026-10-29：**本函数自己跑在哪个区域**（不是 CF 的 colo）。
      // 站主反馈"一会儿快一会儿慢"的根因就是这个：Netlify 每次请求可能把函数调度到
      // 新加坡（出口 3.1.x → CF SIN，查库本地）或美东（出口 54.x → CF EWR，跨太平洋）。
      // Deno Deploy 系运行时通过 DENO_REGION 暴露所在区域；取不到就记 "?"。
      region: edgeRegion(),
    });
    // 一行结构化日志：Netlify 函数日志里 grep `[trace]` 就能直接看出慢在哪一段。
    // region = 本函数跑在哪个区域（Netlify 调度结果）；colo = CF 服务源站的那个机房。
    // 两者通常同区（SIN↔ap-southeast、EWR/IAD↔us-east-1），但 region 才是"抽签"的直接证据。
    // open / match 是 cacheMs 拆出来的两段（第 51 条），紧跟在 cacheMs 后面，方便正则切：
    //   /cacheMs=(\d+)ms open=(\d+)ms match=(\d+)ms/
    // iso / seq 只在这里出现（绝不进响应头）：同一 isolate 且 seq 连续的一段里 cacheMs 一起变大
    // 就是缓存后端排队；iso 变了才变慢则是新 isolate 的冷连接。
    const openMs = trace.openMs ?? 0;
    const matchMs = trace.matchMs ?? 0;
    console.log(
      `[trace] region=${edgeRegion()} cache=${cache} up=${upstreamMs}ms total=${totalMs}ms proxy=${proxyMs}ms cacheMs=${cacheMs}ms open=${openMs}ms match=${matchMs}ms colo=${trace.colo ?? "?"} path=${path} iso=${trace.iso} seq=${trace.seq}`,
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

/** 解析长度声明：只认安全的非负整数（`1715`、`"1715"`），其它一律当"没有声明"。 */
function parseDeclaredLength(raw: string | null): number | null {
  if (raw === null) return null;
  const value = Number(raw.trim());
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

/**
 * 把整条 body 读成一段字节（第 47 条）。
 * 超过 cap / 中途出错 / 被取消一律返回 null —— **绝不返回半截**，
 * 调用方只能据此判定「这条不能缓存 / 这个条目是坏的」。
 */
async function readBodyCapped(
  body: ReadableStream<Uint8Array>,
  cap: number,
): Promise<Uint8Array<ArrayBuffer> | null> {
  let reader: ReadableStreamDefaultReader<Uint8Array>;
  try {
    reader = body.getReader();
  } catch {
    return null; // 已被锁定 / 已消费：当读失败处理
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      const chunk = next.value;
      if (chunk === undefined) continue;
      total += chunk.byteLength;
      if (total > cap) {
        try {
          await reader.cancel();
        } catch {
          // 已经关闭 / 被锁定：无所谓，返回 null 就够
        }
        return null;
      }
      chunks.push(chunk);
    }
  } catch {
    try {
      await reader.cancel();
    } catch {
      // 同上
    }
    return null;
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
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

/* ── 静态资源档：识别 / 缓存键 / content-type 白名单 ─────────────────────── */

/**
 * 静态档路径判定：**只看 pathname**（第 40 条）。
 *   · /img/      站内图片（R2，key 内容寻址）
 *   · /assets/   React Router 构建产物（带哈希，IMMUTABLE_ASSET 那一套）
 *   · /frames/   头像框 SVG
 *   · /splash-*  根目录 iOS 启动图（只认 .png）
 */
function isStaticPath(pathname: string): boolean {
  if (pathname.startsWith("/img/")) return true;
  if (pathname.startsWith("/assets/")) return true;
  if (pathname.startsWith("/frames/")) return true;
  return pathname.startsWith("/splash-") && pathname.toLowerCase().endsWith(".png");
}

/**
 * 静态档的请求资格：GET + 静态前缀 + **不带 Range**。
 * Range 一律不缓存：视频/断点续传要的是 206 + Content-Range，缓存里存的是整包，回放会毁掉播放器。
 * 非 GET（HEAD / POST …）同样不接管 —— 原样落回三档分流（HEAD 因为 method !== GET 进 bypass）。
 */
function isStaticRequest(request: Request, url: URL): boolean {
  if (request.method !== "GET") return false;
  if (request.headers.has("range")) return false;
  return isStaticPath(url.pathname);
}

/** 排序后的**完整** query：一个参数都不丢（`?v=5` 与 `?v=6` 必须是两个条目）。 */
function sortedQueryString(url: URL): string {
  const pairs: Array<[string, string]> = [];
  url.searchParams.forEach((value, name) => pairs.push([name, value]));
  pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)); // sort 稳定，重复键保持原顺序
  return new URLSearchParams(pairs).toString();
}

/**
 * 静态档缓存键：https://static-cache.internal + pathname + (`?` + 排序后的 query)
 * 不含 cookie、不含 theme / epoch / uid：这份字节对所有人生效（第 2 条）。
 */
function buildStaticCacheKey(url: URL): Request {
  const qs = sortedQueryString(url);
  const id = `${STATIC_KEY_ORIGIN}${url.pathname}${qs.length > 0 ? `?${qs}` : ""}`;
  return new Request(id, { method: "GET" });
}

// content-type 白名单（比较时取分号前的主体、小写）：
// 图片 / SVG（image/*）、字体（font/*）、以及下面这些 JS / CSS / 老字体类型。
// **不包含** application/octet-stream、text/html、application/json：类型说不清就不缓存。
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
 * 静态条目能不能回放（第 45/46 条）：条目必须是 identity。
 * 带 content-encoding 的条目（旧版本写进去的压缩体、或外来条目）对本函数**永远**不可回放 ——
 * 静态键里没有编码维度，留着它只会在下一次命中时被当成原始字节发给客户端。
 */
function staticEntryReplayable(hit: Response): boolean {
  const encoding = (hit.headers.get("content-encoding") ?? "").trim().toLowerCase();
  return encoding.length === 0 || encoding === "identity";
}

/**
 * 条目的年龄档（三个常量都在这里落地）：
 *   fresh   < FRESH(7 天)      → 纯命中
 *   swr     FRESH~SWR(30 天)   → SWR 段，仍然回放（资源 immutable，不值得为它回源）
 *   expired ≥ SWR              → 硬过期，删条目重取
 */
type StaticAge = "fresh" | "swr" | "expired";

function staticAgeOf(ageMs: number): StaticAge {
  if (ageMs < STATIC_FRESH_MS) return "fresh";
  if (ageMs < STATIC_SWR_MS) return "swr";
  return "expired";
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
    const cache = await getCache(); // 与匿名/用户档共用同一个 isolate 句柄（第 51 条）
    await bumpEpoch(cache, uidHash);
  } catch {
    // 抓不到缓存 / 没有 crypto：写请求照常成功，只是这次失效没生效
  }
}

/* ── 回源 ───────────────────────────────────────────────────────────────── */

type OriginOptions = {
  /** 强制 accept-encoding: gzip（缓存档必须，保证桶里只有一种编码）。 */
  forceGzip: boolean;
  /**
   * 用 ORIGIN_TARGETS 里的第几项作为目标（2026-10-29）。
   * 竞速让每一腿打不同的域名，好让 BGP 可能选到不同机房。不传 = 第 0 项（主目标）。
   */
  targetIndex?: number;
  /**
   * 强制 accept-encoding: identity（静态档必须，见第 46 条）。
   * 静态条目的键里没有编码维度，只有 identity 字节才能回放给任何客户端。
   */
  forceIdentity?: boolean;
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

  if (options.forceIdentity === true) {
    // 静态档：只要原始字节（第 46 条）。压缩由外层 CDN 按客户端的 Accept-Encoding 现场做，
    // 缓存里绝不出现第二套编码 —— 否则键里没有编码维度，迟早把压缩体发给不认它的客户端。
    headers.set("accept-encoding", "identity");
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

/* ── 三路竞速：缓存 + 两路回源（2026-10-29）─────────────────────────────── */

type OriginWinner = { res: Response; label: "origin1" | "origin2" | "origin3"; ms: number };

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
  /** 写缓存计划；null = 本次不写（打不开缓存 / 带跟踪参数 / 缓存还没就绪 / 负缓存命中）。 */
  plan: StorePlan | null;
  /**
   * 负缓存命中（第 50 条）：这次确实没查 Cache API，但结论仍是 miss。
   * 只用来在写缓存计划为空时把 x-proxy-cache 如实标成 miss（而不是退化成 bypass），
   * 不参与任何响应决策。
   */
  missMirror?: true;
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
  /** 透传给 processOrigin，用于回源成功后直接填镜像（算 theme / engine 维度）。 */
  request?: Request,
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
    request,
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

/* ── 匿名档的 isolate 内内存镜像（第 50 条）──────────────────────────────── */

/**
 * 镜像条目：整段 body 字节 + 原始状态/头 + 存入时刻。
 *
 * 键是 `url.pathname + url.search`（不带 cookie —— 匿名档本来就不分用户）。
 * theme / engine 不参与键，只在命中时校验：Cache API 的键里有这两个维度（第 2 条），
 * 不校验就会出现「dark 主题的请求拿到 light 主题的 HTML」。
 */
type MirrorEntry = {
  body: ArrayBuffer;
  status: number;
  statusText: string;
  headers: [string, string][];
  at: number;
  theme: string;
  engine: string;
};

/** 正缓存：path+query → 一段可直接重建 Response 的字节。 */
const mirrorHits = new Map<string, MirrorEntry>();
/**
 * 负缓存：path+query → 「确认 miss 的时刻 + 当时的 theme/engine」。
 *
 * 键同样只是 path+query，但值里带上维度并在命中时校验：Cache API 的键含有 theme/engine，
 * 一个 dark 请求的 miss 不该让紧接着的 light 请求也跳过查询（那会白白丢掉一次命中）。
 */
const mirrorMisses = new Map<string, { at: number; theme: string; engine: string }>();
/** 正缓存当前占用字节数（用来卡 MIRROR_MAX_BYTES，避免每次遍历求和）。 */
let mirrorHitBytes = 0;

function mirrorKeyOf(url: URL): string {
  return `${url.pathname}${url.search}`;
}

function mirrorDrop(key: string): void {
  const entry = mirrorHits.get(key);
  if (entry === undefined) return;
  mirrorHitBytes -= entry.body.byteLength;
  mirrorHits.delete(key);
}

/** 顺手清掉过期的正/负条目（两张表都 ≤ 12 条，遍历代价可忽略）。 */
function mirrorPrune(now: number): void {
  for (const [key, entry] of mirrorHits) {
    if (now - entry.at >= MIRROR_MS) mirrorDrop(key);
  }
  for (const [key, miss] of mirrorMisses) {
    if (now - miss.at >= MISS_MIRROR_MS) mirrorMisses.delete(key);
  }
}

/**
 * 记一条正缓存，并顺手把负标记清掉（有正条目就不可能还是 miss）。
 * 超条目 / 超字节时按 **Map 迭代顺序 = 插入顺序** 淘汰最老的。
 * 任何异常都吞掉：镜像写失败等于没有镜像，绝不能变成 5xx。
 */
function mirrorStore(
  key: string,
  body: ArrayBuffer,
  status: number,
  statusText: string,
  headers: [string, string][],
  theme: string,
  engine: string,
  now: number,
): void {
  try {
    // 单条就超过总上限：直接不镜像，否则它会把别的条目全部挤掉、自己也留不住。
    if (body.byteLength > MIRROR_MAX_BYTES) return;
    mirrorPrune(now);
    mirrorDrop(key); // 同键覆盖：先把旧的字节数减掉
    mirrorHits.set(key, { body, status, statusText, headers, at: now, theme, engine });
    mirrorHitBytes += body.byteLength;
    mirrorMisses.delete(key);
    while (mirrorHits.size > MIRROR_MAX_ENTRIES || mirrorHitBytes > MIRROR_MAX_BYTES) {
      const oldest = mirrorHits.keys().next();
      if (oldest.done === true) break;
      mirrorDrop(oldest.value);
    }
  } catch {
    // 静默降级：下一次照样走 Cache API
  }
}

/** 取一条正缓存：过期 / 维度不匹配都当没有（过期项顺手删掉）。 */
function mirrorLookup(key: string, theme: string, engine: string, now: number): MirrorEntry | undefined {
  const entry = mirrorHits.get(key);
  if (entry === undefined) return undefined;
  if (now - entry.at >= MIRROR_MS) {
    mirrorDrop(key);
    return undefined;
  }
  return entry.theme === theme && entry.engine === engine ? entry : undefined;
}

/** 负缓存是否还在有效期：命中说明「刚刚查过就是没有」，可以省掉这次 Cache API 查询。 */
function mirrorMissKnown(key: string, theme: string, engine: string, now: number): boolean {
  const miss = mirrorMisses.get(key);
  if (miss === undefined) return false;
  if (now - miss.at >= MISS_MIRROR_MS) {
    mirrorMisses.delete(key);
    return false;
  }
  // 维度不同 = 一条不同的缓存键，这次 miss 对它没有参考价值。
  return miss.theme === theme && miss.engine === engine;
}

/** 记一条负缓存：重新插入等于把它挪到最年轻的一端。 */
function mirrorRememberMiss(key: string, theme: string, engine: string, now: number): void {
  try {
    mirrorMisses.delete(key);
    mirrorMisses.set(key, { at: now, theme, engine });
    while (mirrorMisses.size > MIRROR_MAX_ENTRIES) {
      const oldest = mirrorMisses.keys().next();
      if (oldest.done === true) break;
      mirrorMisses.delete(oldest.value);
    }
  } catch {
    // 静默降级
  }
}

/**
 * 写缓存成功后让负缓存失效（第 50 条的关键一步）：
 * 不清掉的话，突发里第一批 miss 留下的负标记会让后面几百条请求在 3 秒内根本不查缓存，
 * 也就看不到刚写进去的条目 —— 缓存收益全丢，还会让源站持续被压。
 */
function mirrorForgetMiss(url: URL): void {
  try {
    mirrorMisses.delete(mirrorKeyOf(url));
  } catch {
    // 静默降级
  }
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
  /**
   * 2026-10-29：回源成功后直接填镜像要用它算 theme / engine 维度。
   * 传不进来就跳过填镜像（安全降级，绝不影响响应）。
   */
  request?: Request,
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
    /**
     * 2026-10-29：**回源成功后直接填镜像**（原版缺的就是这一步）。
     *
     * 原设计的镜像只在「Cache API 命中」时才填充（见 probeAnonymous 第 ② 步），于是：
     *   · 冷 isolate 第一次必然 Cache API miss → 镜像空着；
     *   · 负缓存又把接下来 3 秒的 Cache API 查询整个跳过 → 镜像继续空着。
     * 结果每个 URL 的头几发都要付 189~951ms 的 Cache API 查询，镜像形同虚设。
     *
     * 这里从「本来就要写进 Cache API 的那条流」上再 tee 一支出来，后台读进内存。
     * 只对匿名桶（`!requireUserMark`）填，避免把登录态页面灌进共享镜像。
     * 后台读，绝不拖慢这次响应：客户端那条分支完全不受影响。
     */
    let toPut = toCache;
    if (!plan.requireUserMark && request !== undefined) {
      try {
        const [putBranch, mirrorBranch] = toCache.tee();
        toPut = putBranch;
        const dims = bucketDimensions(request);
        const mirrorKey = mirrorKeyOf(requestUrl);
        const pairs: [string, string][] = [];
        storeHeaders.forEach((value, name) => pairs.push([name, value]));
        void (async () => {
          const body = await new Response(mirrorBranch).arrayBuffer();
          mirrorStore(mirrorKey, body, 200, res.statusText, pairs, dims.theme, dims.engine, Date.now());
        })().catch(() => {
          // 镜像只是加速层：读失败就当没有，下一次照样走 Cache API。
        });
      } catch {
        // tee 失败：不镜像，照常写缓存
      }
    }

    stored = plan.cache
      .put(plan.key, new Response(toPut, { status: 200, statusText: res.statusText, headers: storeHeaders }))
      .then(() => {
        // 写成功 ⇒ 立刻让负缓存失效（第 50 条关键一步），否则刚写进去的条目在 3 秒内
        // 没人看得见，突发流量会一直落在「跳过缓存」的快路径上。
        // 只有匿名桶需要（负缓存只服务匿名档）；用户桶的键空间不同，不碰。
        if (!plan.requireUserMark) mirrorForgetMiss(requestUrl);
      })
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

/**
 * 匿名档的缓存探测：打不开 / match 抛错一律降级为「这一档没有缓存」，绝不 5xx。
 *
 * 2026-10-29（第 50 条）：在 Cache API 前面先看 isolate 内的两级内存镜像。
 * 镜像只是加速层 —— 任何一步出错都静默回到原来的 caches.open/match 路径。
 */
async function probeAnonymous(request: Request, url: URL, ctx: Context, trace: Trace): Promise<CacheProbe> {
  let cache: Cache | null = null;
  let key: Request | null = null;
  let stale: StaleHit | undefined;
  let hit: CacheHit | undefined;

  // 带跟踪参数的请求只读不写（第 5 条），也不进镜像：它们本来就不该被复用。
  // theme / engine 与 Cache API 键是同一组维度，只用于命中校验（不参与镜像键）。
  let mirrorable = !hasTrackingParams(url);
  let mirrorKey = "";
  let theme = "";
  let engine = "";
  if (mirrorable) {
    try {
      const dims = bucketDimensions(request);
      mirrorKey = mirrorKeyOf(url);
      theme = dims.theme;
      engine = dims.engine;
    } catch {
      mirrorable = false;
    }
  }

  // ① 负缓存：刚确认过 miss → 直接跳过 caches.open/match（trace 的 cacheMs 照样有值）。
  if (mirrorable) {
    try {
      if (mirrorMissKnown(mirrorKey, theme, engine, Date.now())) {
        trace.tCache = Date.now();
        return { plan: null, missMirror: true };
      }
    } catch {
      // 镜像故障当没有镜像：继续走下面的 Cache API
    }
  }

  // ② 正缓存：4 秒内命中过同一个 path+query → 用内存里的字节重建 Response，完全不碰 Cache API。
  if (mirrorable) {
    try {
      const mirrored = mirrorLookup(mirrorKey, theme, engine, Date.now());
      if (mirrored !== undefined) {
        const restored = new Response(mirrored.body, {
          status: mirrored.status,
          statusText: mirrored.statusText,
          headers: new Headers(mirrored.headers),
        });
        const mirroredAge = entryAge(restored);
        // 存的瞬间可能正好压在 fresh 窗口边界上：过了 FRESH_MS 就交回常规路径，
        // SWR 的后台刷新语义不能被镜像改掉。
        if (mirroredAge < FRESH_MS) {
          trace.tCache = Date.now();
          // 与 matched 命中一致：cf-ray 就在镜像下来的头里，回源已经写过就不覆盖。
          if (trace.colo === undefined) trace.colo = traceColo(restored);
          return { hit: { res: restored, state: "hit", ageMs: mirroredAge }, plan: null };
        }
        mirrorDrop(mirrorKey);
      }
    } catch {
      // 镜像故障当没有镜像：继续走下面的 Cache API
    }
  }

  try {
    const tOpen = Date.now();
    const openedCache = await getCache(); // 模块级句柄（第 51 条）：除 isolate 首个请求外几乎零成本
    trace.openMs = Date.now() - tOpen;
    const cacheKey = buildCacheKey(request, url);
    cache = openedCache;
    key = cacheKey;

    const tMatch = Date.now();
    const matched = await openedCache.match(cacheKey);
    trace.matchMs = Date.now() - tMatch;
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

      // 命中后把同一段字节放进正缓存镜像。这里**后台读**（waitUntil）而不是 await：
      // 命中路径一旦 await 一次完整 body 拷贝，竞速就可能从「缓存秒赢」变成「回源先赢」，
      // 那就等于改了既有行为；读失败只是这一次不填镜像。
      if (mirrorable && hit !== undefined && hit.state === "hit") {
        waitUntil(
          ctx,
          matched
            .clone()
            .arrayBuffer()
            .then((bytes) => {
              const pairs: [string, string][] = [];
              matched.headers.forEach((value, name) => pairs.push([name, value]));
              mirrorStore(mirrorKey, bytes, matched.status, matched.statusText, pairs, theme, engine, Date.now());
            })
            .catch(() => {}),
        );
      }
    } else if (mirrorable) {
      // ③ 记一条负缓存：接下来 3 秒的同类请求不再付这次 Cache API 的 0.3~0.6 秒。
      mirrorRememberMiss(mirrorKey, theme, engine, Date.now());
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
    // 负缓存命中（第 50 条）同理：没查 Cache API 不代表这一档是 bypass。
    decision.probe === null || decision.probe.missMirror === true ? "miss" : undefined,
    request,
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
    const tOpen = Date.now();
    const openedCache = await getCache(); // 与匿名档同一个 isolate 句柄（第 51 条）
    trace.openMs = Date.now() - tOpen;
    // epoch 只在这里读一次，之后回源、写缓存全程用同一个值：
    // 回源期间发生的写操作只会让新内容落到新 epoch，不会把旧 HTML 写进当前 epoch。
    const epoch = await readEpoch(openedCache, uidHash);
    const cacheKey = buildUserCacheKey(request, url, uidHash, epoch);
    cache = openedCache;
    key = cacheKey;
    observe = { user: tag, epoch };

    const tMatch = Date.now();
    const matched = await openedCache.match(cacheKey);
    trace.matchMs = Date.now() - tMatch;
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
    request,
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

/* ── 档位四：静态资源（缓存 vs **单路**回源并行，不写 trace）──────────────── */

/** 静态档的写入计划：只有 cache 与 key —— 没有 theme / epoch / uid 维度。 */
type StaticStorePlan = { cache: Cache; key: Request };

/**
 * 静态档的回源收尾（第 43/46/47/49 条）。
 *
 * 写入条件：status 200 + content-type 白名单 + **没有任何 Set-Cookie** + **identity 字节** +
 * 长度已知且 0 < content-length ≤ STATIC_MAX_CACHE_BYTES。
 * 形状不合格的那一份（401/403/404、HTML 错误页、octet-stream、带 Set-Cookie）**原样交给
 * processOrigin(plan=null)** —— 状态码、响应头、Set-Cookie 去 Domain、Location / CORS 改写逐字一致。
 *
 * 要写缓存时**不再 tee**：先把 body 完整读成一段字节并和 content-length 对账，再用这同一段字节
 * 分别构造「写缓存」与「给客户端」两个独立 Response。任何一半被取消都不会影响另一半。
 */
async function processStaticOrigin(
  res: Response,
  requestUrl: URL,
  proxyOrigin: string,
  plan: StaticStorePlan | null,
): Promise<OriginOutput> {
  const cacheableShape =
    res.status === 200 &&
    res.body !== null &&
    getSetCookies(res.headers).length === 0 &&
    isStaticContentType(res.headers);

  if (!cacheableShape || res.body === null) {
    return processOrigin(res, requestUrl, proxyOrigin, null, "GET");
  }

  const out = buildResponseHeaders(res, requestUrl, "GET");
  rewriteLocation(out, proxyOrigin);
  rewriteCors(out, proxyOrigin);

  // 静态键里没有 accept-encoding 维度（第 45 条），所以条目只允许是 identity。
  // 回源已经强制 identity；万一源站仍然回了压缩体，这一次不缓存、原样透传（CE 头不能剥）。
  const encoding = (res.headers.get("content-encoding") ?? "").trim().toLowerCase();
  const encoded = encoding.length > 0 && encoding !== "identity";
  const declared = parseDeclaredLength(res.headers.get("content-length"));
  // 没有 content-length / 空 body / 超过上限：不缓冲也不缓存，直接透传。
  // （静态档只缓存「长度已知且足够小」的文件；宁可不缓存，也不猜长度。）
  const writable =
    plan !== null && !encoded && declared !== null && declared > 0 && declared <= STATIC_MAX_CACHE_BYTES;

  if (!writable) {
    // 形状合格但这次不写：缓存那一路还没跑完 / 缓存不可用 / 编码或长度不合格。
    out.set(CACHE_STATE, plan === null ? "static-miss" : "static-bypass");
    return { response: withBody(res, out) };
  }

  // 完整读入（上限 STATIC_MAX_CACHE_BYTES，现为 8MiB）。读失败 / 超限 / 中途断开都是 null，绝不拿半截去写缓存。
  const bytes = await readBodyCapped(res.body, STATIC_MAX_CACHE_BYTES);
  if (bytes === null || bytes.byteLength !== declared) {
    // 源站 body 和 content-length 对不上（截断 / 超限 / 中途断开）：不缓存，也不能把半截当 200 发出去。
    // 2026-10-29：改上限后这条只应在"源站真的截断"时命中；4MB 的图不再落这里。
    void discard(res);
    return { response: text(502, "Bad Gateway") };
  }

  out.delete("content-length"); // body 已是内存里的完整字节，旧的 framing 不再适用
  out.set(CACHE_STATE, "static-miss");

  // 条目里另存源站原始 cache-control（浏览器下次别再经过本函数），TTL 只用来定平台淘汰时间。
  const storeHeaders = new Headers(out);
  storeHeaders.set(ORIGIN_CC, out.get("cache-control") ?? "");
  storeHeaders.set("cache-control", `public, max-age=${STATIC_STORE_TTL_S}`);
  storeHeaders.set(BORN, String(Date.now()));
  storeHeaders.set(STATIC_BYTES, String(bytes.byteLength)); // 命中时唯一可信的长度（第 48 条）
  storeHeaders.set("content-length", String(bytes.byteLength)); // 标准头兜底：平台若丢了自定义头，还能用它对账
  storeHeaders.delete(CACHE_STATE);
  storeHeaders.delete(CACHE_AGE);

  let stored: Promise<void> | undefined;
  try {
    // 写缓存吃的是独立副本（同一段已校验的字节），不再和客户端那份共享底层流。
    stored = plan.cache
      .put(plan.key, new Response(bytes, { status: 200, statusText: res.statusText, headers: storeHeaders }))
      .catch(() => {
        // 写失败只是这次没缓存；客户端那份是独立字节，不受影响。
      });
  } catch {
    // cache.put 同步抛错（例如缓存已被关闭）同样不能影响客户端响应
  }

  return {
    response: new Response(bytes, { status: 200, statusText: res.statusText, headers: out }),
    stored,
  };
}

/**
 * 静态档回放：cache-control 用存储时记下的**源站原值**（immutable 1 年），
 * 这样浏览器/CDN 下次根本不再经过这个函数 —— 与 HTML 两档「回放 private, no-cache」正好相反。
 */
function fromStaticCache(hit: Response, ageMs: number): Response {
  const headers = new Headers(hit.headers);
  const originCacheControl = headers.get(ORIGIN_CC);
  headers.delete(ORIGIN_CC);
  headers.delete(BORN);
  headers.delete(STATIC_BYTES); // 内部长度标记绝不外泄（正常路径已在 readStaticEntry 删过一次）
  headers.set(
    "cache-control",
    originCacheControl !== null && originCacheControl.length > 0 ? originCacheControl : STATIC_DEFAULT_CC,
  );
  headers.set(CACHE_STATE, "static-hit");
  headers.set(CACHE_AGE, String(Math.max(0, Math.round(ageMs / 1000))));
  return withBody(hit, headers);
}

/** 静态档的缓存探测结果：hit 一定是「完整且 identity」的那一种；plan 用来回源后写回。 */
type StaticProbe = { hit?: { res: Response; ageMs: number }; plan: StaticStorePlan | null };

/**
 * 命中前的完整性校验（第 48 条）：把条目完整读成字节，再和条目里记的 x-proxy-bytes 对账。
 * 任何一项不满足（读失败 / 空 / 超过 2MiB / 长度不符）都当 miss 并删掉条目 ——
 * 坏条目比没有缓存更糟：它会在 30 天里持续把坏字节发给所有人。
 */
async function readStaticEntry(
  matched: Response,
  cache: Cache,
  key: Request,
): Promise<Response | null> {
  const declared = parseDeclaredLength(
    matched.headers.get(STATIC_BYTES) ?? matched.headers.get("content-length"),
  );
  const bytes = matched.body === null ? null : await readBodyCapped(matched.body, STATIC_MAX_CACHE_BYTES);
  if (bytes === null || bytes.byteLength === 0) {
    try {
      await cache.delete(key);
    } catch {
      // 删不掉也照样当 miss：本次绝不回放它
    }
    return null;
  }
  if (declared !== null && declared !== bytes.byteLength) {
    try {
      await cache.delete(key);
    } catch {
      // 同上
    }
    return null;
  }

  const headers = new Headers(matched.headers);
  headers.delete(STATIC_BYTES);
  headers.delete("content-length"); // body 已是内存里的完整字节，长度交给运行时
  return new Response(bytes, { status: 200, statusText: matched.statusText, headers });
}

/**
 * 静态档缓存探测（与那唯一一路回源**并行**跑，见 serveStatic）：
 * 打不开 / match 抛错一律降级为「没有缓存」，本次不回写、直接单路回源，绝不 5xx。
 * 命中必须同时满足：不是硬过期 + identity + 完整性校验通过（第 46/48 条），否则删条目当 miss。
 */
async function probeStatic(url: URL, ctx: Context, trace: Trace): Promise<StaticProbe> {
  try {
    const tOpen = Date.now();
    const openedCache = await getCache(STATIC_CACHE_NAME); // 静态档自己的 isolate 句柄（第 51 条）
    trace.openMs = Date.now() - tOpen;
    const cacheKey = buildStaticCacheKey(url);

    const tMatch = Date.now();
    const matched = await openedCache.match(cacheKey);
    trace.matchMs = Date.now() - tMatch;
    trace.tCache = Date.now(); // 缓存查询结束（命中与未命中都在这一刻）
    if (matched) {
      if (trace.colo === undefined) trace.colo = traceColo(matched);
      const ageMs = entryAge(matched);
      const age = staticAgeOf(ageMs);

      if (age === "expired") {
        // 硬过期（≥ SWR 30 天）：取消 body 后删条目，回源重取（第 44 条）。
        // 这里**不 await** discard：放掉一条流不该出现在探测的关键路径上。
        void discard(matched);
        waitUntil(ctx, openedCache.delete(cacheKey).catch(() => false));
      } else if (!staticEntryReplayable(matched)) {
        // 压缩体条目对本函数永远不可回放（第 46 条）：删掉，本次按 miss 重取。
        void discard(matched);
        waitUntil(ctx, openedCache.delete(cacheKey).catch(() => false));
      } else {
        // fresh（< 7 天）与 swr（7~30 天）两档都直接回放、都标 static-hit（静态资源 immutable，
        // 这一档不发起后台刷新）；回放前必须过完整性校验，坏条目在这里被删掉并当 miss。
        const hit = await readStaticEntry(matched, openedCache, cacheKey);
        if (hit !== null) return { hit: { res: hit, ageMs }, plan: { cache: openedCache, key: cacheKey } };
      }
    }
    return { plan: { cache: openedCache, key: cacheKey } };
  } catch {
    // 缓存打不开 / match 抛错：本次不回写
  }
  if (trace.tCache === undefined) trace.tCache = Date.now(); // 缓存提前失败：查询也结束了
  return { plan: null };
}

/**
 * 静态档的写缓存收尾：processStaticOrigin 出响应，stored 挂到 waitUntil 上。
 * processStaticOrigin 现在是 async（要先把 body 读成字节），所以这里也要 await。
 */
async function finishStaticOrigin(
  res: Response,
  url: URL,
  proxyOrigin: string,
  plan: StaticStorePlan | null,
  ctx: Context,
): Promise<Response> {
  const { response, stored } = await processStaticOrigin(res, url, proxyOrigin, plan);
  if (stored !== undefined) waitUntil(ctx, stored);
  return response;
}

/**
 * 静态档主流程：**缓存探测与「唯一一路」回源并行**，谁先成功用谁。
 *
 *   cacheP  ──┐
 *   origin  ──┴─ 先到先用：缓存先赢 → abort 那一路回源；回源先赢 → 缓存那一路忽略（它没法 abort）
 *
 * 与 HTML 档的差别只有一条：回源是**单路**（第 41 条），不是两路。白跑一次图片回源 = 一次 R2 读、
 * 零 D1，所以这条路径也享受「缓存卡住不拖住用户」，但不会把回源量乘二。
 *
 *   · age < FRESH(7d)         → 回放（先过完整性校验），x-proxy-cache: static-hit
 *   · FRESH ≤ age < SWR(30d)  → 同样回放（内容 immutable，不值得为它再回源一次），仍标 static-hit
 *   · age ≥ SWR / 非 identity / 完整性校验失败 → 删条目，回源重取
 *   · 未命中                  → 单路回源 → 写缓存，x-proxy-cache: static-miss
 *
 * 全程不报 trace（第 42 条），也不碰 epoch（静态资源与登录态无关）。
 */
async function serveStatic(request: Request, url: URL, ctx: Context, trace: Trace): Promise<Response> {
  trace.static = true; // 命中 / 未命中都不上报，见 handler 里的 report 守卫
  const proxyOrigin = url.origin;

  // ① 唯一一路回源立刻出发（不 clone 请求）；它与下面的缓存探测并行。
  const controller = new AbortController();
  let cacheWins = false; // 缓存先赢：这一路回源即使已经成功落地，body 也要放掉
  trace.tFetch = Date.now();
  const originP: Promise<Response> = fetchOrigin(request, url, {
    forceGzip: false,
    forceIdentity: true, // 静态条目只存 identity（第 46 条）
    canonicalReferer: false,
    signal: controller.signal,
  }).then((res) => {
    if (cacheWins) {
      void discard(res); // 缓存已经回放了，这条没人要
      return res;
    }
    trace.tUp = Date.now();
    trace.colo = traceColo(res);
    trace.race = "static"; // 回源赢家记 "static"，不占用 origin1 / origin2 的语义
    return res;
  });

  // ② 缓存探测与它同时开跑；probe 兜成永不 reject（任何意外都退化成「这一档没缓存」）。
  const probeP: Promise<StaticProbe> = probeStatic(url, ctx, trace).catch(
    (): StaticProbe => ({ plan: null }),
  );
  trace.cacheSettled = probeP.then(
    () => undefined,
    () => undefined,
  );

  const first = await Promise.race([
    probeP.then((probe) => ({ kind: "probe" as const, probe })),
    originP.then(
      (res) => ({ kind: "origin" as const, res }),
      () => ({ kind: "failed" as const }),
    ),
  ]);

  // 结果一：缓存先赢 → abort 那唯一一路回源，直接回放。
  if (first.kind === "probe" && first.probe.hit !== undefined) {
    cacheWins = true;
    controller.abort();
    // 回源那一路可能刚好也成功了（只是比缓存慢一拍）：把它的 body 放掉，别留一条没人读的流。
    void originP.then(
      (res) => {
        void discard(res);
      },
      () => undefined,
    );
    trace.race = "cache";
    trace.tFetch = undefined; // 没有用上回源：up 记 0，proxy 退回整段函数耗时（与 HTML 档同口径）
    trace.tUp = undefined;
    return fromStaticCache(first.probe.hit.res, first.probe.hit.ageMs);
  }

  // 结果二：回源抛了 → 缓存那一路可能正好命中（它只是慢），先等它跑完再决定。
  if (first.kind === "failed") {
    const probe = await probeP;
    if (probe.hit !== undefined) {
      trace.race = "cache";
      trace.tFetch = undefined;
      trace.tUp = undefined;
      return fromStaticCache(probe.hit.res, probe.hit.ageMs);
    }
    return text(502, "Bad Gateway");
  }

  // 结果三：probe 赢了但没有可回放的命中（miss / 编码不匹配 / 缓存故障）→ 等那唯一一路回源，
  // 用它 + 探测给出的 plan 写缓存。
  if (first.kind === "probe") {
    try {
      const res = await originP;
      return finishStaticOrigin(res, url, proxyOrigin, first.probe.plan, ctx);
    } catch {
      trace.tFetch = undefined;
      trace.tUp = undefined;
      return text(502, "Bad Gateway");
    }
  }

  // 结果四：回源先赢（正常 miss 就是这条）→ 用它；缓存那一路还在跑的话，跑完把 body 放掉。
  void probeP.then(
    (probe) => {
      if (probe.hit !== undefined) void discard(probe.hit.res);
    },
    () => undefined,
  );
  return finishStaticOrigin(first.res, url, proxyOrigin, null, ctx);
}

/* ── 入口 ───────────────────────────────────────────────────────────────── */

export default async function handler(request: Request, ctx: Context): Promise<Response> {
  const t0 = Date.now(); // 链路追踪：进函数（2026-10-29）
  // 本 isolate 的第几个请求（第 51 条）：只进 trace 日志。计数放在最前面，连配置缺失的 500 也算一次。
  REQ_SEQ += 1;
  const seq = REQ_SEQ;
  if (TARGET_URL === null || TARGET_ORIGIN.length === 0) {
    return text(500, "TARGET_URL environment variable is missing or invalid");
  }

  const url = new URL(request.url);
  const trace: Trace = { t0, iso: ISOLATE_ID, seq };
  let response: Response;

  // 第四档（静态资源）在分流之前单独判一次：GET + 静态前缀 + 无 Range 才接管。
  // 不匹配的请求一个字节都不多走 —— 下面的 classifyTier 与三档代码完全没改过。
  if (isStaticRequest(request, url)) {
    response = await serveStatic(request, url, ctx, trace);
  } else {
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
  const rawCacheState = (response.headers.get(CACHE_STATE) ?? "").trim();
  const cacheState = traceCacheState(rawCacheState);
  // 只有本次真的回源（miss / miss-user / bypass / static-miss / static-bypass）才透传源站的 d1/ssr/app；
  // 缓存回放（hit / stale* / static-hit）里那份是「当初那次」的数，透传会把旧数冒充本次。
  // static-miss / static-bypass 不在 traceCacheState 的白名单里（静态档不上报），所以这里单列。
  const originFresh =
    cacheState === "miss" ||
    cacheState === "miss-user" ||
    cacheState === "bypass" ||
    rawCacheState === "static-miss" ||
    rawCacheState === "static-bypass";
  try {
    const sample = Math.random() < TRACE_SAMPLE_RATE;
    // 缓存慢本身也算「慢请求」：竞速后回源会抢跑，这类请求的 total/up 都很漂亮，
    // 只有 cacheMs 能把「缓存卡了 11s」暴露出来，否则它们只会落在 2% 采样里。
    const report = (cacheMs: number): void => {
      // 静态档一律不报（第 42 条）：/img/* 一次首屏就十几二十条，命中/未命中都写会把 ip_logs 刷爆。
      if (trace.static === true) return;
      // 2026-10-29：**长轮询不算慢**。
      // `/api/device-wait` 是设计上挂 15 秒的长轮询（等推送），它每次都会越过所有阈值，
      // 于是把 Netlify 日志和 ip_logs 刷满 `up=15002ms` 的假"慢请求"，真正的问题被挤掉。
      // 这些端点单独排除，不参与上报。
      if (LONG_POLL_PATHS.has(url.pathname)) return;
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
