import type { Context } from "@netlify/edge-functions";

const TARGET = Deno.env.get("TARGET_URL")?.replace(/\/+$/, "");

function getSetCookies(h: Headers): string[] {
  const anyH = h as unknown as { getSetCookie?: () => string[] };
  if (typeof anyH.getSetCookie === "function") return anyH.getSetCookie();
  const single = h.get("set-cookie");
  return single ? [single] : [];
}

export default async function handler(request: Request, _ctx: Context) {
  if (!TARGET) {
    return new Response("TARGET_URL environment variable is not set", { status: 500 });
  }

  const url = new URL(request.url);
  const headers = new Headers(request.headers);

  // 源站要按真实 Host 渲染，但浏览器实际在 Netlify 域上
  headers.set("host", new URL(TARGET).host);

  const isBodyless = request.method === "GET" || request.method === "HEAD";
  const body = isBodyless ? undefined : await request.arrayBuffer();

  const res = await fetch(`${TARGET}${url.pathname}${url.search}`, {
    method: request.method,
    headers,
    body,
    redirect: "manual",
  });

  const out = new Headers(res.headers);

  // 代理域与源站域不同：Set-Cookie 里的 Domain 必须去掉，
  // 否则浏览器按域名不匹配直接丢弃 —— 登录存不住、退出也清不掉。
  const cookies = getSetCookies(res.headers);
  if (cookies.length > 0) {
    out.delete("set-cookie");
    for (const c of cookies) {
      out.append("set-cookie", c.replace(/;\s*domain=[^;]*/gi, ""));
    }
  }

  return new Response(res.body, {
    status: res.status,
    statusText: res.statusText,
    headers: out,
  });
}
