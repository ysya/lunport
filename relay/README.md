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

## Self-host with Docker Compose

To run the relay on your own server instead of Cloudflare, `selfhost/` runs the same Worker on
[workerd](https://github.com/cloudflare/workerd), Cloudflare's open-source Workers runtime, behind
[Caddy](https://caddyserver.com/) for automatic HTTPS. Every chain is a SQLite file in the `relay-data` volume.

You need a domain whose DNS points at the server, with ports 80 and 443 reachable from the internet so that Caddy
can get a certificate:

    cd relay/selfhost
    echo "RELAY_DOMAIN=relay.example.com" > .env
    docker compose up -d --build

Then enter `https://relay.example.com` in Settings → Sync → Relay URL on every computer. To update, run
`git pull && docker compose up -d --build`. For a consistent backup of the `relay-data` volume, stop the `relay`
service first.

- **No public domain?** SSHelter only accepts `https://` relays, so a bare LAN address does not work. A tunnel that gives you
  an HTTPS address, such as Cloudflare Tunnel or `tailscale serve`, does. Treat it as a reverse proxy (next point).
- **Your own reverse proxy instead of Caddy**:
  - Give the `relay` service a port that only the proxy can reach, for example `127.0.0.1:8080:8080`.
  - Start just that service: `docker compose up -d relay`.
  - Have the proxy set `CF-Connecting-IP` to the client's address, replacing any value the client sent. The relay's
    per-IP limits read that header (on Cloudflare, the edge sets it). Without the header, all clients share one
    limit, which is fine for a private relay. If clients can set it themselves, they can avoid the limits, so never
    expose port 8080 to the internet.
- `selfhost/check-config.mjs` fails the image build if `selfhost/workerd.capnp` drifts from `wrangler.jsonc` (compatibility
  date, Durable Object classes). `selfhost/smoke-test.mjs` checks a running relay end to end, and CI runs both.

## Limits

- 64 KiB per record, 1 MiB and 4096 records per chain (tombstones count), 1 MiB per request
- 120 requests/min per chain (any endpoint); per IP: 20 chain-creation requests/hour, 1200 requests/hour
- chains idle for 180 days are deleted automatically (reads count as activity; devices keep their local copies)
- reading a chain that was never created returns 404 and allocates nothing

## Test

    npm test          # runs inside workerd via @cloudflare/vitest-plugin
    npm run typecheck
