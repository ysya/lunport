# Central sync ingress deployment status

The gateway and private core are separate Worker deployments; verify their actual deployment identities and approvals. Built-in Passkey login is the default; OIDC is optional. The fresh-install examples remain **unrouted, unprovisioned and disabled** (`CENTRAL_ENABLED=0`). A deployed installation needs its actual routes, namespace IDs, update pipeline and operator permissions verified before activation.

The repository's default `wrangler.jsonc` retains historical Durable Object class identities but its HTTP entrypoint returns 404. Running `npm run deploy` without an explicit split configuration does not install this boundary; use the reviewed security and private-core configurations for central accounts.

## Security ownership

The independent security Worker owns `AccountStore`, `PasskeyStore` and `VaultStore`, including device/session denials, login-family revocations, membership, key epochs and encrypted Vault history. It also owns the historical retirement registry, backend floor and ingress limiter. Keeping each central object's complete database together avoids splitting authorization and ciphertext commits across stores. The application core retains only the historical chain class and its own limiter.

The security gateway admits only `/v1/*` and calls its local security objects. Legacy chain HTTP paths return 404 at both the gateway and private core. The gateway has no binding to the core or chain namespace. Historical chain storage remains attached to the private core so existing Durable Object identities can be upgraded without deleting stored data. Verify actual deployed bindings and IAM rather than relying only on these examples.

The gateway verifies its independently pinned namespace witness and removes a client-supplied private authority header before handling account traffic. The retired `CentralSyncBackend.forward` entrypoint and private-core default HTTP both return 404. Backend floor 2 remains required for account traffic. Upgrade both Workers as one reviewed release; an older core can still serve legacy traffic until its code is replaced.

The floor pins the stable installation ID, retirement registry and all three authoritative namespace identities. A previous floor without an authority pin remains unavailable until explicit private handoff. Missing, corrupt or mismatched floor pins and namespace bindings fail closed; traffic never initializes or repairs those pins. Namespace identities do not prove the freshness or completeness of a restored security database; restoration still requires the trusted current-state comparison below. Private provisioning is not an HTTP endpoint. An application-only restore cannot replace current central authorization or history.

## Fresh installations

The three example configurations create new namespaces. Deploy the closed security bootstrap first, then the closed private core, then the closed full security gateway. Bootstrap has no reference to a missing core. Inspect actual namespace identities and provision only a confirmed new installation through private operator access. Existing installations must not use fresh provisioning to clear an unbound floor or missing security data.

Attach the intended public HTTPS origin only after these checks. Enable `CENTRAL_ENABLED` on the security Worker only after provisioning and native-client checks; the private core has no central-account configuration. Disable every direct core route, workers.dev URL and preview URL. Preserve separately administered deployment identities and reviewed update paths. Verify the actual API token scope, bindings and build triggers; account-wide application credentials or an old automatic build pipeline must not be assumed to enforce that boundary.

## Existing public relay

`prepare-authority-transfer.mjs` prepares closed configurations without deploying. It keeps the original public Worker name as the security owner, preserving its workers.dev hostname and any existing central namespaces. The legacy chain namespace transfers to a new private core; the source namespace ID must remain unchanged. The script preserves the deployed prefix of the original migration history and creates only classes absent from the verified live inventory. A destination class must not first be created empty and then used as a transfer target. These requirements follow [Cloudflare's existing-class transfer contract](https://developers.cloudflare.com/durable-objects/reference/durable-object-class-migrations-legacy/).

The operator supplies the original project configuration and a trusted, complete live inventory, pinned by the SHA-256 of that exact inventory file. Its schema is `version: 1`, `account_id`, `script_name`, `origin`, `migration_tag`, `private_script_absent: true`, and `namespaces: [{class_name, id, storage: "sqlite"}]`. IDs and account identity must come from the actual Cloudflare installation. A hash of a historical backup or invented IDs is not a current inventory. Verify that the proposed new private Worker name is unused.

```sh
cd relay
node security/prepare-authority-transfer.mjs \
  wrangler.jsonc /protected/live-inventory.json <inventory-sha256> \
  <stable-installation-id> <unused-private-core-name>
```

The script writes new configuration files beside the original and refuses to replace differing files. It never changes or deploys the source configuration. With writes stopped and retained backups, review/deploy the private-core bootstrap, verify the transferred chain ID, then deploy the original Worker as the independent security owner. The generated final core retains only local `CHAIN` and `IP_LIMIT` bindings; the gateway has no chain or core binding. Compare every preserved namespace ID with the trusted inventory. Keep all outputs unrouted until private floor/authority provisioning, current-state inventory, data readback, actual IAM and update-pipeline checks pass. Restore the original public routing explicitly; do not assume a hostname follows a different Worker.

The generator refuses already split private-core deployments and unfamiliar ownership/migration histories. Those require preserving their existing security owner and transferring the three central namespaces to that owner with a reviewed provider-native transfer, never creating empty replacement classes. The [Compose handoff](../selfhost/central/README.md#existing-central-preview-handoff) is a different storage adapter and must not be applied to Cloudflare data.

## Backup and restore

Preserve current independent authority while restoring older application data. Reconcile the candidate against a demonstrably current checkpoint and the exact installation/namespace identities; retain current authority for any divergent central object. Do not merge security fields by timestamp, recreate missing credentials, lower a floor or revive an old registry. The Compose operator implements stopped-storage import and reconciliation with exact readback. Cloudflare uses its provider-native namespace/storage operations and must verify the same identities and current-state requirements in the actual account.

A native device takeover has a separate history reconciliation step. The old public cache becomes passive provenance bound to its exact encrypted replacement archive; its old device-bound projection receipts cannot authorize the selected replacement identity. The UI keeps original files and requests an explicit whole-library merge review. Managed SSH private keys remain inside the encrypted migration and the protected local Vault; no private-key download is added.

Reconciliation requires the selected approved device, authenticated original source coverage, every independent content/control minimum and, for legacy cloud keybooks, a signed permanent retirement proof. Signed logical history can preserve previously captured old-epoch content after the old identity is removed, without saving central Vault master keys. The native edit barrier and synchronization block remain in place through encrypted upload, complete authenticated readback and the atomic protected-Vault/cache publication. Only that sealed transaction clears the exact covered archive flags. Reaching a round's request/time allowance yields resumable public progress without starting another network request. Changed files, unavailable evidence and interrupted writes retain the original sources and resumable progress.

If the independent security store itself must be restored, a trusted newer reference is required. If all current authority and external references have been lost or rolled back, old copies cannot prove their own freshness. Keep the service unavailable in that case; E2EE does not reconstruct missing revocation history.

`npm run check:security-config` verifies source relationships only. Isolated Workers and Compose tests exercise implementation behavior; they do not verify live Cloudflare IAM, TLS, routes, namespace transfers or automatic builds. Central library setup still requires explicit consent and exact target/readback verification; new legacy chain source migration is rejected.
