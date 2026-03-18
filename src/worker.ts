
export interface Env {
  APP_TOKEN_SECRET: string;
  BUCKET: R2Bucket;
  BUCKET_PREFIX?: string; // optional: e.g. "public/"
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // --- 1) Token check ---
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

    // --- 2) Only allow images ---
    const url = new URL(request.url);
    const isImage =
      /\.(png|jpe?g|gif|webp|avif|svg)$/i.test(url.pathname) ||
      (request.headers.get("accept") || "").includes("images/");
    if (!isImage) return new Response("Forbidden: not an image resource", { status: 403 });

    // --- 3) Map URL -> R2 key (with md/ sharding, no fallback) ---
    function normalizeKey(path: string) {
      return path.replace(/^\/+/, "").replace(/\.\.+/g, "");
    }

    function computeShard(filename: string) {
      const base = filename.toLowerCase();
      // starts with TWO letters → return first 4 chars
      if (/^[a-z]{2}/.test(base)) {
        return base.slice(0, 4);
      }
      // starts with ONE letter → return first 3 chars
      if (/^[a-z]/.test(base)) {
        return base.slice(0, 3);
      }
      // starts with non‑letter (e.g. digit) → return first 2 chars
      return base.slice(0, 2);
    }

    const pathKey = normalizeKey(url.pathname);
    if (!pathKey) return new Response("Missing object key", { status: 400 });

    // Match ".../cards/images/md/<filename>"
    const mdMatch = pathKey.match(/^(cards\/images\/md)\/([^\/]+)$/i);
    let bucketKey: string;

    if (mdMatch) {
      const basePath = mdMatch[1]; // "cards/images/md"
      const filename = mdMatch[2]; // "0101001.jpg" or "p2502001.jpg"
      const nameOnly = filename.replace(/\.[^.]+$/, "");
      const shard = computeShard(nameOnly);
      bucketKey = `${basePath}/${shard}/${filename}`;
    } else {
      // Non-md paths are unchanged
      bucketKey = pathKey;
    }

    const key = (env.BUCKET_PREFIX ?? "") + bucketKey;

    // --- 4) Read object from R2 ---
    const object = await env.BUCKET.get(key);
    if (!object) return new Response("Not Found", { status: 404 });

    // --- 5) Build response headers ---
    const headers = new Headers();
    const contentType = object.httpMetadata?.contentType ?? inferContentTypeFromExt(key);
    headers.set("Content-Type", contentType);
    headers.set("Cache-Control", "public, max-age=3600, immutable");
    if (object.httpEtag) headers.set("ETag", object.httpEtag);
    headers.set("Last-Modified", object.uploaded.toUTCString());
    headers.set("X-Storage-Path", "sharded");

    // --- 6) Method handling ---
    if (request.method === "HEAD") {
      return new Response(null, { status: 200, headers });
    }
    if (request.method !== "GET") {
      return new Response("Method Not Allowed", { status: 405, headers: { Allow: "GET, HEAD" } });
    }

    // --- 7) Stream body back to client ---
    return new Response(object.body, { status: 200, headers });
  },
};

// --- helpers you already had (or similar) ---
function toBase64Url(bytes: Uint8Array): string {
  let base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function timingSafeEqual(a: string, b: string) {
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}

function inferContentTypeFromExt(key: string): string {
  const lower = key.toLowerCase();
  if (lower.endsWith(".png")) return "image/png";
  if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) return "image/jpeg";
  if (lower.endsWith(".gif")) return "image/gif";
  if (lower.endsWith(".webp")) return "image/webp";
  if (lower.endsWith(".avif")) return "image/avif";
  if (lower.endsWith(".svg")) return "image/svg+xml";
  return "application/octet-stream";
}