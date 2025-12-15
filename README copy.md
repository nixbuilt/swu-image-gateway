# swu-images-worker


# Minimal TypeScript Cloudflare Worker (Image Gateway)

Validates `X-App-Token` header (`<timestamp>.<hmac_base64url>`), then proxies image requests.

## Run locally

```bash
npm install
wrangler secret put APP_TOKEN_SECRET
## paste your shared secret
