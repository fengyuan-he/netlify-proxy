import type { Context } from "@netlify/edge-functions";

const TARGET = Deno.env.get("TARGET_URL")?.replace(/\/+$/, "");

export default async (request: Request, _ctx: Context) => {
  if (!TARGET) return new Response("TARGET_URL not set", { status: 500 });

  const url = new URL(request.url);
  const headers = new Headers(request.headers);
  headers.set("host", new URL(TARGET).host);

  const res = await fetch(`${TARGET}${url.pathname}${url.search}`, {
    method: request.method,
    headers,
    body: request.method === "GET" || request.method === "HEAD" ? undefined : request.body,
    redirect: "manual",          // ①
  });

  // ✅ 不碰 body，原样流式返回（这一步不变）
  return new Response(res.body, {
    status: res.status,
    statusText: res.statusText,
    headers: res.headers,
  });
};
