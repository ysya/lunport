# Central sync ingress deployment status

The code has separate gateway and private-core entry points. These examples are **unrouted and unprovisioned**. They are review material, not a production migration capability or permission to deploy.

The account provider is intentionally generic and disabled (`CENTRAL_ENABLED=0`). Select issuer/JWKS/API audience/native client ID when an OIDC provider is chosen. The native system-browser Code+PKCE flow must then be tested with that provider.

## Security ownership

The security Worker owns `LEGACY_RETIREMENT`, `SECURITY_FLOOR` and its IP limiter. The application core owns its existing chain/account/vault namespaces. Gateway traffic uses only the named `CentralSyncBackend.forward(requiredFloor, registryIdentity, request)` RPC. There is no public-URL or `fetch` fallback. The revision and namespace check run in the same invocation as data routing. Private-core mode returns 404 from default HTTP fetch.

FloorStore requires explicit private deployment provisioning. It records the stable installation ID, actual registry namespace identity and minimum backend security revision. Requests can raise that floor and cannot lower it; missing/corrupt/mismatched state rejects traffic. Provisioning is never an HTTP endpoint. No public provisioning tool or production credentials are included. Backend builds predating the named RPC fail closed; future implementations must preserve its mandatory floor argument.

## Operator work still required

1. Inventory all existing Worker names, routes, workers.dev/previews and namespace identities. Preserve the original chain/account/vault owners. If a retirement registry/floor already exists, these fresh examples must not rebind or replace it. Restore/import all security markers and high-water state through a reviewed procedure first. Changing the Worker name creates different storage; it does not move the library.
2. Choose a stable random installation ID and the public HTTPS origin. Keep the security Worker and its deployment approval path independent from application releases. Audit provider deployment permissions: do not assume an application token is restricted to one Worker. These source files do not establish that isolation.
3. For a first security namespace only, deploy the unrouted bootstrap example (no missing core bindings), then the private core, then the full unrouted gateway. Review the exact names and migration history before each step. No command here runs a deployment automatically.
4. Provision the floor through an authorized private deployment RPC with the reviewed registry identity and initial minimum. Never auto-provision after a restore or treat an empty namespace as proof that old sync codes are unused. Keep encrypted backups of security metadata and inventory namespace identities alongside ciphertext.
5. Attach the intended public HTTPS route only to the gateway. Disable every direct backend route, workers.dev URL and preview URL in actual infrastructure. Verify that the old legacy origin is either covered by the gateway or permanently stopped. An old `workers.dev` hostname cannot simply be assumed to follow a differently named gateway.
6. Audit the running deployment, not just JSON configuration. Test rollback to a pre-entrypoint backend, an older floor-aware backend, registry outage, namespace replacement and restore. Unknown state must stop sync. Selfhost still needs equivalent independent ingress/firewall/deployment controls before claiming complete migration.

The examples close public routes by default. `npm run check:security-config` checks source configuration relationships only; it cannot verify Cloudflare routing, IAM, deployed versions, private provisioning or backups. Native migration and publication remain guarded until full inventory, consent, target verification, permanent retirement and deployment checks are connected.
