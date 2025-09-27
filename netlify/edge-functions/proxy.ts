import type { Context } from "@netlify/edge-functions";

export default async (request: Request, context: Context) => {
  const targetUrl = Deno.env.get("TARGET_URL");

  if (!targetUrl) {
    return new Response("TARGET_URL environment variable is not set", {
      status: 500,
    });
  }

  // Construct the new URL
  const url = new URL(request.url);
  const newUrl = `${targetUrl}${url.pathname}${url.search}`;

  // Just clone the request directly
  const proxiedRequest = new Request(newUrl, request);
  return fetch(proxiedRequest);
};
