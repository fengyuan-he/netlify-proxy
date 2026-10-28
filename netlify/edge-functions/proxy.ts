import type { Context } from "@netlify/edge-functions";

const TARGET = Deno.env.get("TARGET_URL")?.replace(/\/+$/, "");

export default async function handler(request: Request, _ctx: Context) {
  if (!TARGET) return new Response("TARGET_URL not set", { status: 500 });

  const url = new URL(request.url);
  const headers = new Headers(request.headers);
  headers.set("host", new URL(TARGET).host);

  const isBodyless = request.method === "GET" || request.method === "HEAD";

  const res = await fetch(`${TARGET}${url.pathname}${url.search}`, {
    method: request.method,
    headers,
    body: isBodyless ? undefined : await request.arrayBuffer(),
    redirect: "manual",
  });

  return new Response(res.body, {
    status: res.status,
    statusText: res.statusText,
    headers: res.headers,
  });
}
