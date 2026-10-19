# Central service Compose preview

This separate Compose runs the same application as managed Workers. A stable workerd security image owns the private entry point, central account/Passkey/Vault databases, permanent retirement registry and security floor. A separate application image exports only the core module into a read-only runtime mount. The application updater has no security volume, proxy capability or network access. One workerd process hosts both Workers through their existing named RPC; only Caddy can reach its private HTTP socket.

Central account support remains a disabled preview. The isolated deployment tests cover encrypted migration, device approval/revocation, consistent restore and older application backups while current security authority is retained. Production HTTPS/origin verification and operator restore procedures still require the actual deployment environment. The existing [legacy relay Compose](../compose.yaml) remains available. This preview creates new installation namespaces; an existing relay needs a reviewed namespace/data/security-marker import before changing its public origin. Starting empty volumes cannot establish that old sync codes or revoked devices are safe.

## New installation

Use a server with Docker Compose, a public domain pointing at it, and reachable ports 80/443. Built-in Passkey is the default login method and needs no OIDC provider. Use one stable public HTTPS origin: its hostname is the WebAuthn RP ID and changing it does not move existing passkeys. OIDC remains optional for an external provider. The default outbound policy supports public HTTPS identity endpoints; a private-network provider needs a reviewed, narrowly scoped outbound binding.

```sh
cd relay/selfhost/central
cp .env.example .env
chmod 600 .env
```

Set `RELAY_DOMAIN`, generate `SECURITY_INSTALLATION` once with `openssl rand -hex 16`, and generate `SELFHOST_PROXY_KEY` with `openssl rand -hex 32`. Preserve the installation ID, proxy capability and namespace/storage inventory in the protected backup. The proxy capability authenticates only the Caddy hop; it is separate from device credentials and content encryption keys. Keep `CENTRAL_ENABLED=0` until the complete service/native release has passed its deployment checks. Leave `PASSKEY_ENABLED=1` and the optional OIDC issuer/JWKS fields empty for built-in login. Configure the OIDC fields only when enabling an external provider; accounts are pinned to the selected method and are never automatically linked.

```sh
docker compose build core-bundle gateway
docker compose --profile setup run --rm control inspect
```

Inspection prints the installation ID, registry and authoritative namespace witnesses, floor and pin state. It creates no authorization floor. For a confirmed fresh installation only, copy that registry identity and the installation ID into this one-shot command:

```sh
docker compose --profile setup run --rm \
  -e SELFHOST_EXPECTED_REGISTRY=<registry-from-inspection> \
  -e SELFHOST_CONFIRM_NEW_INSTALLATION=<installation-id> \
  control provision-new
docker compose up -d gateway caddy
```

Replace the angle-bracket placeholders before running the command. The public endpoint is `https://RELAY_DOMAIN`. Missing/corrupt/mismatched floor state returns an unavailable response instead of initializing itself. There is no HTTP provisioning or reset API. Operator commands acquire the same nonblocking security-volume lock as the runtime; stop `gateway` before inspecting or changing an already running installation.

Caddy replaces client IP/proto headers and adds the private proxy capability. The adapter validates the exact configured host and reconstructs HTTPS from fixed configuration, then removes proxy secrets before ordinary gateway handling. Publish only Caddy's ports. A public workerd/core port or an additional proxy that passes client forwarding headers defeats this deployment boundary.

## Updates and backend floors

Build/update the application artifact independently, then restart the gateway to load it:

```sh
docker compose build core-bundle
docker compose up --no-deps --force-recreate core-bundle
docker compose restart gateway
```

Review compatibility, storage migrations and the required backend floor before each update. Review/build the `gateway` security image separately when its code/configuration changes; application updates must retain that approved image and its persistent volumes. Pin released image digests in `.env` when distributing a deployment rather than relying on mutable local tags.

For an approved floor increase, stop the gateway and use the inspected registry with an explicit minimum:

```sh
docker compose stop gateway
docker compose --profile setup run --rm control inspect
docker compose --profile setup run --rm \
  -e SELFHOST_EXPECTED_REGISTRY=<registry-from-inspection> \
  -e SELFHOST_MINIMUM_FLOOR=<approved-minimum> \
  control raise-floor
docker compose up -d gateway
```

A lower floor or repeat fresh provisioning is rejected. A backend below the saved floor becomes unavailable; it never falls back to a public/legacy application entry point. Raising the floor before installing a compatible backend stops service, so follow the reviewed release order.

## Existing central preview handoff

An older central preview stored `accounts`, `vaults` and `passkeys` under `app-data`. Stop the gateway and retain a complete, consistent backup and the original installation ID before changing images. Build the approved security/core images and the offline operator:

```sh
docker compose stop gateway
docker compose --profile setup build core-bundle gateway authority-operator
docker compose run --rm core-bundle
docker compose --profile setup run --rm authority-operator plan
```

Run the offline import before starting the new runtime or control image; workerd creates namespace metadata at startup. An existing floor without an authority pin remains unavailable. Do not run `provision-new`. The plan lists exact fixed namespaces, object filenames, byte counts and hashes; preserve its SHA-256 outside the candidate backup. The offline operator requires Node's built-in SQLite support, bundled in its separate image. It mounts original application storage read-only, holds the runtime lock, validates SQLite in private scratch copies and preserves every source byte.

```sh
docker compose --profile setup run --rm authority-operator import --expected <plan-sha256>
docker compose --profile setup run --rm control inspect
docker compose --profile setup run --rm \
  -e SELFHOST_EXPECTED_REGISTRY=<inspected-registry> \
  -e SELFHOST_EXPECTED_AUTHORITY=<inspected-authority-witness> \
  -e SELFHOST_AUTHORITY_RECEIPT=<plan-sha256> \
  control bind-authority
```

Import uses the original `lunport-<installation>-<role>` namespace keys and object IDs. Existing destination state must exactly match; newer or unknown authority is never overwritten. Exact partial staged copies can resume. Unknown, changed or corrupt input remains retained and blocks completion. The private bind command independently rereads the receipt, namespace listings and every copied file through a read-only service before pinning the handoff and minimum floor 2. No HTTP reset/provisioning route is added. Keep originals and backups after the handoff, verify `status: 200` and `pinned: true`, then start the reviewed gateway. The old application namespaces remain retained and are no longer central authority.

## Backup and restore

Stop `gateway` and exclude concurrent operator commands while taking a consistent backup. `security-data` contains current central accounts, Passkeys, device/session and login-family revocations, membership/key epochs, ciphertext, namespace pins and permanent retirement. `app-data` contains legacy relay chains and application limiter state. Also preserve `.env`, installation and namespace identities, import evidence, approved image digests and Caddy configuration/certificates. Never remove persistent volumes as part of an update.

Before restoring an older application backup, retain current independent security storage and capture a trusted current checkpoint while the runtime is stopped:

```sh
docker compose --profile setup run --rm authority-operator checkpoint
```

Preserve that exact digest independently. Restore only application storage, keeping current `security-data`, then reconcile:

```sh
docker compose --profile setup run --rm authority-operator reconcile --expected <trusted-current-sha256>
docker compose --profile setup run --rm control inspect
```

`matching` means the candidate central namespace bytes agree. `retain-current-authority` lists divergent roles whose candidate copies must stay inactive; the command does not import or merge them. Both require the expected current digest to match before and after comparison. Check the installation/namespace inventory and require a valid existing authority pin before restarting. A missing, stale or untrusted reference is a failure; do not replace it with a digest computed from the old backup.

Restoring the security store itself requires a demonstrably current authority reference and corresponding object data. A checksum cannot recover missing newer data or detect rollback when every independent current reference was also replaced. Keep the gateway stopped if current security state cannot be established. A missing, corrupt or unbound authority pin fails closed; fresh provisioning is not a restore procedure.

## Verification

After building the two images, run the disposable integration check from the repository root:

```sh
node relay/selfhost/central/smoke-test.mjs
```

It creates a uniquely named project with synthetic settings, checks private provisioning, Caddy header replacement, proxy spoof rejection, independent storage, restart persistence, consistent stopped-volume backup/restore, persisted login revocations, mutual exclusion and a monotonic floor, then removes only its own containers/volumes. `SELFHOST_TEST_SECURITY_IMAGE` and `SELFHOST_TEST_CORE_IMAGE` select other already built test images. The test enables central mode only in its disposable installation and checks Passkey discovery, page and bundle without OIDC. Its Caddy listener is loopback-only HTTP for forwarding checks; real HTTPS certificates and an optional OIDC provider still require their own deployment environment. Set `SELFHOST_TEST_BROWSER_MODULE` to an installed Playwright module and `SELFHOST_TEST_BROWSER_EXECUTABLE` to Chromium to also exercise an actual virtual authenticator through this deployment. That check intercepts a synthetic HTTPS origin and makes no claim about real TLS. No real SSH material or production data is used.

For the central protocol check, bundle the test client with the locked relay development dependencies:

```sh
node relay/node_modules/esbuild/bin/esbuild relay/selfhost/central/protocol-test.ts \
  --bundle --platform=node --format=esm --outfile=/tmp/lunport-protocol-test.mjs
```

Also set `SELFHOST_TEST_PROTOCOL_MODULE=/tmp/lunport-protocol-test.mjs` alongside the two browser settings when running the smoke test. It then creates synthetic devices, migrates the encrypted native fixture through the deployed HTTP gateway, permanently retires a legacy chain, denies an unapproved device, verifies a pairing confirmation, unwraps/decrypts the same history on the approved second device, revokes that device, removes it from signed membership, rotates the content key to epoch 2, and checks every retained version with the new key and rejection of the old key. The stopped-volume restore must preserve the device denial, legacy retirement and login-family revocations. An application-only restore must preserve the independent security floor. The browser/protocol path also captures older application-layout copies before Passkey and device changes, restores them while retaining current independent authority, and verifies all denials and exact current ciphertext. Set `SELFHOST_TEST_SOURCE_SECURITY_IMAGE` and `SELFHOST_TEST_SOURCE_CORE_IMAGE` to approved older preview images to exercise the actual stopped-volume handoff, original-file preservation and private authority binding. `SELFHOST_TEST_OPERATOR_IMAGE` selects the built offline operator image. These tests do not authorize replacing independent security storage with an older copy.

## Passkey accounts

The system browser requires user verification for each new Passkey sign-in. The desktop app binds a one-use, 60-second authorization code to its exact loopback listener with S256 PKCE; the browser never receives the verifier or account refresh token. Short-lived access tokens and rotating refresh families stay in native memory/OS-protected storage. A refresh is not fresh user authentication. Replaying an already rotated refresh token revokes its family.

Choose “Manage passkeys, then sign in” in the browser to add up to eight credentials to the same account. Register a backup on another device or security key before losing the original. Removing a credential invalidates existing account-login families; the credential used for the current management ceremony cannot be removed. Sign in with a different backup first to remove it. Passkey management requires fresh WebAuthn verification and a separate five-minute capability returned only in that verification response. It stays in browser memory and is never placed in a link. Knowing or initiating the original sign-in link does not grant credential management; a refresh token or offline Vault kit cannot bypass verification.

Passkey sign-in does not supply an encrypted Vault's keys or approve a new device. Existing device approval/offline Vault recovery remains necessary for decryption. If all Passkeys are lost and their provider cannot restore one, this version has no account-login reset; the Vault kit alone cannot log in to the server. Keep an independent backup Passkey. Hardware-backed SSH key adapters and complete legacy migration remain separate release gates.
