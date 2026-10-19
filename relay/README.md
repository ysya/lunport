# Lunport sync relay

Encrypted relay for [Lunport](../README.md), your SSH workspace. It carries library changes
between devices: hosts, Groups and explicitly shared keys. Each chain has one Durable Object,
storing only ciphertext. It never sees sync codes, host names, private keys or passwords.

See the [user guide](../docs/usage.md#sync-your-library) for setting up devices in the app.

## Self-host

One click, on the free Workers plan. It covers a few computers syncing a handful of spaces; Cloudflare's free daily
limits (100,000 Durable Object requests and 100,000 rows written) are the ceiling.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/ysya/lunport/tree/main/relay)

The button copies this directory into a new repository on your GitHub or GitLab account and deploys it with
Workers Builds; every push to that repository redeploys it. Later changes to `relay/` here do not reach your
copy by themselves. Or deploy from a checkout:

    cd relay
    npm install
    npx wrangler login
    npx wrangler deploy

Then point Lunport at your Worker URL: Settings → Sync → Relay URL. The app only accepts
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

- **No public domain?** Lunport only accepts `https://` relays, so a bare LAN address does not work. A tunnel that gives you
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

## Updating your relay

Lunport tells you in *Settings → Sync* when your relay is missing something the app can use.

- **Deployed with the button (GitHub):** in your relay repository, open *Actions → Update relay → Run workflow*. It
  opens a pull request that brings the relay up to the latest Lunport release (or the tag, branch or commit you enter),
  runs its tests, and lists removed files and any Durable Object or migration change. Merge it and Cloudflare deploys it
  with the same Worker name, so the URL and the stored chains stay the same. Set the repository variable `AUTO_UPDATE`
  to `true` for a weekly check.
  - Without a ref it never downgrades: if your relay is newer than the latest release, for example because you updated
    to a beta, the run says so and changes nothing. Enter an older ref to downgrade on purpose; the pull request is then
    titled *Downgrade relay …*. Downgrading to a release older than relay 0.2.0 (SSHelter v0.16.x and earlier, and the
    v0.17.0-1 beta) does not work: its test setup also collects the update script's own tests, so *Test it* fails and
    no pull request opens.
  - Once an update pull request exists for an upstream commit, whether open, closed or merged, later runs leave that
    commit alone. To take a closed one after all, reopen it on GitHub.
  - If the run says Actions may not open pull requests, use the link it prints or allow it under
    *Settings → Actions → General*.
  - When the upstream version of the workflow file itself changes, the run warns and the pull request links it: copy it
    to `.github/workflows/update-relay.yml` by hand, because GitHub does not let a workflow change workflow files.
- **Deployed before this workflow existed:** copy `.github/workflows/update-relay.yml` and
  `.github/scripts/update-relay.mjs` from this folder to the same paths in your relay repository, then run the workflow
  as above. Deploying from a checkout of this repository also works:
  `cd relay && npm install && npx wrangler login && npx wrangler deploy`. Set `name` in `wrangler.jsonc` to your
  Worker's name first, otherwise wrangler creates a second Worker with empty storage, and copy the two files anyway: the
  next push to your relay repository redeploys that repository's own, older code.
- **Deployed with wrangler:** `git pull`, then `npx wrangler deploy` again.
- **Docker Compose:** `git pull && docker compose up -d --build` in `relay/selfhost`.
- **GitLab:** download the `relay/` folder of the release you want, replace your repository's files with it (keep the
  `name` in `wrangler.jsonc`), and push.

## API

Besides the per-chain endpoints (`PUT`/`DELETE /v1/chains/{id}`, `GET`/`POST /v1/chains/{id}/records`):

- `POST /v1/pull` — pull up to 64 chains in one request: `[{ "chain", "token", "since" }]`. Each item is checked like
  `GET /v1/chains/{id}/records` and answers `ok`, `not_found`, `rate_limited` or `deferred` (the response passed its
  2 MiB budget; ask again).
- `POST /v1/chains/{id}/freeze` — stop all further writes to a chain (used when the sync code changes). It answers
  `204` (also when the chain is already frozen), `404` for an unknown chain or a wrong token, and `429` over the chain's
  rate limit. From then on every push answers `409 {"status":"frozen"}` and writes nothing, while reads and batch pulls
  work as before. Deleting a frozen chain removes its records but keeps it frozen: a later `PUT` answers `200`, not
  `201`.
- `GET /v1/info` — the relay version and features, so the app knows whether this relay needs an update.

## Central migration implementation status

The independent ingress and private-core examples are described in [security/README.md](security/README.md). They remain unrouted and require reviewed provisioning and infrastructure verification.

The account service remains an opt-in preview with built-in Passkey sign-in by default and optional generic OIDC settings. It does not yet advertise a complete legacy migration capability.

The native `central-sync-preview` build connects first-device source capture, whole-library review, explicit consent, bounded staging, retirement, verified readback and the protected local cutover transaction. Approved secondary devices can also verify and adopt the existing encrypted library. Nonempty supported local and retained data uses a separately reviewed additive merge: imported host, group, collection and key identities are remapped together, and managed private-key material is encrypted before upload. Existing remote identities remain intact. Consent precedes any merge upload, and activation requires authenticated readback plus the same protected vault/state transaction. Concurrent foreign collection changes are preserved through verified catalog adjustments; edits to imported entries pause the merge with its sources retained.

Ordinary library edits pause after protected source capture; account safety controls remain available. Reopening resumes the saved operation, including prepared and vault-published stages. A lost successful state response only completes its receipt and preserves later active edits. A secondary device never starts a competing initial migration; an empty remote library remains waiting. Reads share a 32-request/30-second round budget and retain a small fixed set of encrypted transcript/plan archives rather than an archive per HTTP page. An interrupted in-memory read may need to reread its prefix against the protected checkpoint. Imported host trust approvals are cleared, and locally stored passwords or passphrases may need reentry for remapped hosts; none are uploaded.

Joining devices with legacy cloud chains still stop before merge until complete source freeze/retirement and normalization are supported for that route. Older source-format normalization, maximum-history byte/file capacity, reconciliation when membership or epochs change during a frozen operation, hardware signer adapters and real deployment/restore reconciliation remain release gates. The native two-device tests use synthetic material and real localhost HTTP; browser consent/scope tests mock native commands. Keep central mode disabled for general use.


The central redesign keeps both deployment paths: managed Workers with Durable Objects, and Docker Compose running the same application on workerd with persistent SQLite storage. Account/device authorization and synchronization progress add server responsibilities; content encryption and decryption stay in the clients. Self hosting does not require a second application backend.

The existing Compose file serves the legacy relay. A separate [central Compose preview](selfhost/central/README.md) now packages the gateway, private application module, independent security storage, explicit provisioning and health checks. Full central self hosting requires a stable HTTPS hostname and complete upgrade/backup/restore validation; OIDC is optional. Passkey login stays separate from device approval and E2EE Vault recovery. Backups must preserve account/device revocations, security floors and permanent retirement alongside ciphertext. Declaring the new Durable Object classes alone does not complete this setup. Keep central mode disabled until these checks pass on the chosen deployment.

`LegacyRetirementStore` is a separate Durable Object namespace with no expiry, alarm, delete or reset RPC. Every legacy data endpoint checks it and fails closed if it is unavailable. The internal migration freeze preserves its source snapshot and prevents idle cleanup, deletion and recreation; retrying must use the same operation and target. Ordinary `/freeze` continues to support sync-code rotation.

Private central migration primitives verify a signed complete-target manifest, keep bounded staged ciphertext separate from daily sync, install the target atomically, and authorize one-way retirement by reading the actual target's durable commit receipt. HTTP migration routes remain disabled. A separate trusted ingress and deployment floor are also required before production migration: restoring an older public Worker can otherwise bypass these checks. Preserve security namespaces and their high-water state when backing up or restoring; an empty replacement registry is not evidence that old sync codes are safe to reuse. The Docker configuration declares the same namespaces but does not establish an independent ingress or rollback protection.

## Limits

- 64 KiB per record, 1 MiB and 4096 records per chain (tombstones count), 1 MiB per request
- 120 requests/min per chain (any endpoint); per IP: 20 chain-creation requests/hour, 1200 requests/hour, 12000 chains pulled/hour through `POST /v1/pull`
- chains idle for 180 days are deleted automatically (reads count as activity; devices keep their local copies)
- reading a chain that was never created returns 404 and allocates nothing

## Test

    npm test          # runs inside workerd via @cloudflare/vitest-plugin
    npm run typecheck
