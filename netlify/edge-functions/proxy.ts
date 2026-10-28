import type { Context } from "@netlify/edge-functions";

const TARGET = Deno.env.get("TARGET_URL")?.replace(/\/+$/, "");

export default async function handler(request: Request, _ctx: Context) {
  if (!TARGET) return new Response("TARGET_URL not set", { status: 500 });

  const url = new URL(request.url);
  const headers = new Headers(request.headers);
  headers.set("host", new URL(TARGET).host);

  const isBodyless = request.method === "GET" || request.method === "HEAD";

const res = await fetch(..., { ... });

const out = new Headers(res.headers);
// 代理域和源站域不同：Set-Cookie 里的 Domain 必须去掉，
// 否则浏览器按域名不匹配直接丢弃
const cookies = res.headers.getSetCookie?.() ?? [];
if (cookies.length) {
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
