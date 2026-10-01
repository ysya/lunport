# SSHelter sync relay

Zero-knowledge relay for SSHelter's sync chain: one Durable Object per chain, storing only
ciphertext. It never sees recovery phrases, host names, keys or passwords.

## Self-host

One click, on the free Workers plan:

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/ysya/sshelter/tree/main/relay)

The button copies this directory into a new repository on your GitHub or GitLab account and deploys it with
Workers Builds; every push to that repository redeploys it. Later changes to `relay/` here do not reach your
copy by themselves. Or deploy from a checkout:

    cd relay
    npm install
    npx wrangler login
    npx wrangler deploy

Then point SSHelter at your Worker URL: Settings → Sync → Relay URL. The app only accepts
`https://` relays (plain `http://` is allowed for `localhost` / `127.0.0.1` during development).

## Limits

- 64 KiB per record, 1 MiB and 4096 records per chain (tombstones count), 1 MiB per request
- 120 requests/min per chain (any endpoint); per IP: 20 chain-creation requests/hour, 1200 requests/hour
- chains idle for 180 days are deleted automatically (reads count as activity; devices keep their local copies)
- reading a chain that was never created returns 404 and allocates nothing

## Test

    npm test          # runs inside workerd via @cloudflare/vitest-plugin
    npm run typecheck
