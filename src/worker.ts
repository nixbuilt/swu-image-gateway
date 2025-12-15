
export interface Env {
  APP_TOKEN_SECRET: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Read token
    const token = request.headers.get("X-App-Token");
    if (!token) {
      return new Response("Unauthorized: missing X-App-Token", { status: 401 });
    }

    // Expect "<timestamp>.<signature>"
    const [tsStr, sigB64url] = token.split(".");
    if (!tsStr || !sigB64url) {
      return new Response("Invalid token format", { status: 400 });
    }

    // Validate timestamp window
    const ts = Number(tsStr);
    if (!Number.isFinite(ts)) {
      return new Response("Invalid timestamp", { status: 400 });
    }
    const now = Math.floor(Date.now() / 1000);
    const WINDOW_SECONDS = 60;
    if (Math.abs(now - ts) > WINDOW_SECONDS) {
      return new Response("Token expired", { status: 403 });
    }

    // Recompute HMAC-SHA256(secret, tsStr)
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw",
      enc.encode(env.APP_TOKEN_SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const sigBuf = await crypto.subtle.sign("HMAC", key, enc.encode(tsStr));
    const expectedB64url = toBase64Url(new Uint8Array(sigBuf));

    if (!timingSafeEqual(sigB64url, expectedB64url)) {
      return new Response("Invalid signature", { status: 403 });
    }

    // (Optional) restrict to image paths only
    const url = new URL(request.url);
    const isImage =
      /\.(png|jpe?g|gif|webp|avif|svg)$/i.test(url.pathname) ||
      (request.headers.get("accept") || "").includes("image/");
    if (!isImage) {
      return new Response("Forbidden: not an image resource", { status: 403 });
    }

    // Proxy upstream, stripping the sensitive header
    const upstream = await fetch(new Request(request, {
      headers: stripHeaders(request.headers, ["X-App-Token"]),
    }));

    // Add default cache headers if missing
    const headers = new Headers(upstream.headers);
    if (!headers.has("Cache-Control")) {
      headers.set("Cache-Control", "public, max-age=3600, immutable");
    }

    return new Response(upstream.body, {
      status: upstream.status,
      headers,
    });
  },
};

// --- helpers ---

function toBase64Url(bytes: Uint8Array): string {
  let base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function stripHeaders(orig: Headers, toRemove: string[]): Headers {
  const removeLower = toRemove.map(r => r.toLowerCase());
  const h = new Headers();
  for (const [k, v] of orig.entries()) {
    if (!removeLower.includes(k.toLowerCase())) {
      h.set(k, v);
    }
  }
  return h;
}
