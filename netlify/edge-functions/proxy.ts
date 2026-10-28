import type { Context } from "@netlify/edge-functions";

const TARGET = Deno.env.get("TARGET_URL")?.replace(/\/+$/, "") ?? "";
const TARGET_ORIGIN = TARGET ? new URL(TARGET).origin : "";

/**
 * 取 Set-Cookie。
 * Fetch 规范里 Set-Cookie 是「禁止暴露的响应头」，普通 get() 拿不到，
 * 只有 getSetCookie() 能读全。拿不到时返回空数组，调用方会原样透传。
 */
function getSetCookies(h: Headers): string[] {
  const anyH = h as unknown as { getSetCookie?: () => string[] };
  if (typeof anyH.getSetCookie === "function") {
    try {
      return anyH.getSetCookie();
    } catch {
      return [];
    }
  }
  const single = h.get("set-cookie");
  return single ? [single] : [];
}

export default async function handler(request: Request, _ctx: Context) {
  if (!TARGET) {
    return new Response("TARGET_URL environment variable is not set", { status: 500 });
  }

  const url = new URL(request.url);
  const headers = new Headers(request.headers);

  // ① 源站要按真实域名渲染，但浏览器实际在 Netlify 域上
  headers.set("host", new URL(TARGET).host);

  // ② React Router 的 CSRF 校验比对 Origin 与 Host。
  //    经代理时 Origin 仍是 netlify 域 → .data 的 POST 会 400。
  //    只在原请求确实带了 Origin 时才改写（浏览器发 POST 时才会带）。
  if (request.headers.has("origin")) {
    headers.set("origin", TARGET_ORIGIN);
    headers.set("referer", `${TARGET_ORIGIN}${url.pathname}${url.search}`);
  }

  // ③ 带 body 的请求不能直接复用流：边缘运行时要求 duplex，
  //    缓冲成 ArrayBuffer 最稳（表单都很小）
  const isBodyless = request.method === "GET" || request.method === "HEAD";
  const body = isBodyless ? undefined : await request.arrayBuffer();

  const res = await fetch(`${TARGET}${url.pathname}${url.search}`, {
    method: request.method,
    headers,
    body,
    // ④ 不跟随跳转：你的 301/302 必须原样回到浏览器
    redirect: "manual",
  });

  const out = new Headers(res.headers);

  // ⑤ 代理域与源站域不同：Set-Cookie 里的 Domain 必须剥掉，
  //    否则浏览器按域名不匹配直接丢弃 —— 登录存不住、退出也清不掉
  const cookies = getSetCookies(res.headers);
  if (cookies.length > 0) {
    out.delete("set-cookie");
    for (const c of cookies) {
      out.append("set-cookie", c.replace(/;\s*domain=[^;]*/gi, ""));
    }
  }

  // ⑥ 不碰 body：原样流式透传，压缩（br/gzip）自然保留
  return new Response(res.body, {
    status: res.status,
    statusText: res.statusText,
    headers: out,
  });
}
