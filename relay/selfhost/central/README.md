# Central service Compose preview

This separate Compose runs the same application as managed Workers. A stable workerd gateway image owns the private entry point, permanent retirement registry and security floor. A separate application image exports only the core module into a read-only runtime mount. The application updater has no security volume, proxy capability or network access. One workerd process hosts both Workers through their existing named RPC; only Caddy can reach its private HTTP socket.

Central account support remains a disabled preview. This configuration does not complete native migration, production HTTPS/provider verification or production restore validation. The existing [legacy relay Compose](../compose.yaml) remains available. This preview creates new installation namespaces; an existing relay needs a reviewed namespace/data/security-marker import before changing its public origin. Starting empty volumes cannot establish that old sync codes or revoked devices are safe.

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

Inspection prints the installation ID, actual registry identity and current floor. It creates no authorization floor. For a confirmed fresh installation only, copy that registry identity and the installation ID into this one-shot command:

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

## Backup and restore

Stop `gateway` and exclude concurrent operator commands while taking a consistent backup. Preserve `app-data` and `security-data` together, including Passkey public credentials and login-family revocations, device/session revocations, membership/epoch state, security floors, permanent retirement and ciphertext. Also preserve `.env`, namespace identities, approved security/core image references and Caddy's persistent configuration/certificates. Core module artifacts can be regenerated only from the matching approved image. Keep persistent volumes when stopping the service; removing a volume destroys that part of the installation.

Before exposing a restored service, reconcile the latest revocation, membership, epoch and retirement high-water state. An internally consistent older backup can still revive previously revoked access. Keep the gateway stopped when current security state cannot be established. Do not use fresh provisioning or an empty replacement volume to clear a restore failure.

## Verification

After building the two images, run the disposable integration check from the repository root:

```sh
node relay/selfhost/central/smoke-test.mjs
```

It creates a uniquely named project with synthetic settings, checks private provisioning, Caddy header replacement, proxy spoof rejection, independent storage, restart persistence, mutual exclusion and a monotonic floor, then removes only its own containers/volumes. `SELFHOST_TEST_SECURITY_IMAGE` and `SELFHOST_TEST_CORE_IMAGE` select other already built test images. The test enables central mode only in its disposable installation and checks Passkey discovery, page and bundle without OIDC. Its Caddy listener is loopback-only HTTP for forwarding checks; real HTTPS certificates, optional OIDC and multi-device/restore behavior still need deployment testing. Set `SELFHOST_TEST_BROWSER_MODULE` to an installed Playwright module and `SELFHOST_TEST_BROWSER_EXECUTABLE` to Chromium to also exercise an actual virtual authenticator through this deployment. That check intercepts a synthetic HTTPS origin and makes no claim about real TLS. No real SSH material or production data is used.

## Passkey accounts

The system browser requires user verification for each new Passkey sign-in. The desktop app binds a one-use, 60-second authorization code to its exact loopback listener with S256 PKCE; the browser never receives the verifier or account refresh token. Short-lived access tokens and rotating refresh families stay in native memory/OS-protected storage. A refresh is not fresh user authentication. Replaying an already rotated refresh token revokes its family.

Choose “Manage passkeys, then sign in” in the browser to add up to eight credentials to the same account. Register a backup on another device or security key before losing the original. Removing a credential invalidates existing account-login families; the credential used for the current management ceremony cannot be removed. Sign in with a different backup first to remove it. Passkey management requires fresh WebAuthn verification and a five-minute, browser-bound capability; it accepts neither a refresh token nor an offline Vault kit as a bypass.

Passkey sign-in does not supply an encrypted Vault's keys or approve a new device. Existing device approval/offline Vault recovery remains necessary for decryption. If all Passkeys are lost and their provider cannot restore one, this version has no account-login reset; the Vault kit alone cannot log in to the server. Keep an independent backup Passkey. Hardware-backed SSH key adapters and complete legacy migration remain separate release gates.
