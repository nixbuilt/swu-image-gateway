
export interface Env {
  APP_TOKEN_SECRET: string;
  BUCKET: R2Bucket;
  BUCKET_PREFIX?: string; // optional: e.g. "public/"
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // --- 1) Token check exactly as you had ---
    const token = request.headers.get("X-App-Token");
    if (!token) return new Response("Unauthorized: missing X-App-Token", { status: 401 });

    const [tsStr, sigB64url] = token.split(".");
    if (!tsStr || !sigB64url) return new Response("Invalid token format", { status: 400 });

    const ts = Number(tsStr);
    if (!Number.isFinite(ts)) return new Response("Invalid timestamp", { status: 400 });

    const now = Math.floor(Date.now() / 1000);
    const WINDOW_SECONDS = 60;
    if (Math.abs(now - ts) > WINDOW_SECONDS) return new Response("Token expired", { status: 403 });

    const enc = new TextEncoder();
    const keyHmac = await crypto.subtle.importKey(
      "raw",
      enc.encode(env.APP_TOKEN_SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const sigBuf = await crypto.subtle.sign("HMAC", keyHmac, enc.encode(tsStr));
    const expectedB64url = toBase64Url(new Uint8Array(sigBuf));

    if (!timingSafeEqual(sigB64url, expectedB64url)) {
      return new Response("Invalid signature", { status: 403 });
    }

    // --- 2) Only allow images, same logic you had ---
    const url = new URL(request.url);
    const isImage =
      /\.(png|jpe?g|gif|webp|avif|svg)$/i.test(url.pathname) ||
      (request.headers.get("accept") || "").includes("images/");
    if (!isImage) return new Response("Forbidden: not an image resource", { status: 403 });

    // --- 3) Map URL path -> R2 key ---
    const pathKey = url.pathname.replace(/^\/+/, "");
    if (!pathKey) return new Response("Missing object key", { status: 400 });

    const key = (env.BUCKET_PREFIX ?? "") + pathKey;

    // --- 4) Read object from R2 ---
    const object = await env.BUCKET.get(key);
    if (!object) return new Response("Not Found", { status: 404 });

    // --- 5) Build response headers ---
    const headers = new Headers();
    const contentType = object.httpMetadata?.contentType ?? inferContentTypeFromExt(key);
    headers.set("Content-Type", contentType);

    // Default cache policy; tune as needed
    if (!headers.has("Cache-Control")) {
      headers.set("Cache-Control", "public, max-age=3600, immutable");
    }

    // Preserve ETag / timestamps for client caching
    if (object.httpEtag) headers.set("ETag", object.httpEtag);
    headers.set("Last-Modified", object.uploaded.toUTCString());

    // HEAD support (no body)
    if (request.method === "HEAD") {
      return new Response(null, { status: 200, headers });
    }
    if (request.method !== "GET") {
      return new Response("Method Not Allowed", { status: 405, headers: { Allow: "GET, HEAD" } });
    }

    // --- 6) Stream body back to client ---
    return new Response(object.body, { status: 200, headers });
  },
};

// --- helpers identical to your original, plus a tiny content-type inference ---
function toBase64Url(bytes: Uint8Array): string {
  let base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// crude fallback if httpMetadata.contentType isn't set
function inferContentTypeFromExt(key: string): string {
  const ext = (key.split(".").pop() || "").toLowerCase();
  switch (ext) {
    case "png": return "image/png";
    case "jpg": case "jpeg": return "image/jpeg";
    case "gif": return "image/gif";
    case "webp": return "image/webp";
    case "avif": return "image/avif";
    case "svg": return "image/svg+xml";
       default: return "application/octet-stream";
  }
}