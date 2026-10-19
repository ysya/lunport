# Central sync ingress deployment status

The gateway and private core use separate deployment identities. Built-in Passkey login is the default; OIDC is optional. The fresh-install examples remain **unrouted, unprovisioned and disabled** (`CENTRAL_ENABLED=0`). A deployed installation needs its actual routes, namespace IDs, update pipeline and operator permissions verified before activation.

## Security ownership

The independent security Worker owns `AccountStore`, `PasskeyStore` and `VaultStore`, including device/session denials, login-family revocations, membership, key epochs and encrypted Vault history. It also owns the permanent legacy-retirement registry, backend floor and ingress limiter. Keeping each central object's complete database together avoids splitting authorization and ciphertext commits across stores. The application core owns legacy relay chains and its own limiter and references central objects through explicit private bindings.

Gateway traffic uses only `CentralSyncBackend.forward(requiredFloor, registryIdentity, request)`. The gateway replaces the client's authority header with its independently pinned namespace witness. The core verifies the floor, registry and its own central namespace witnesses in the same invocation as routing. There is no public-URL or `fetch` fallback; private-core default HTTP returns 404. Backend floor 2 is required. Both an older backend and an older gateway are rejected by the current core.

The floor pins the stable installation ID, retirement registry and all three authoritative namespace identities. A previous floor without an authority pin remains unavailable until explicit private handoff. Missing, corrupt or mismatched floor pins and namespace bindings fail closed; traffic never initializes or repairs those pins. Namespace identities do not prove the freshness or completeness of a restored security database; restoration still requires the trusted current-state comparison below. Private provisioning is not an HTTP endpoint. An application-only restore cannot replace current central authorization or history.

## Fresh installations

The three example configurations create new namespaces. Deploy the closed security bootstrap first, then the closed private core, then the closed full security gateway. Bootstrap has no reference to a missing core. Inspect actual namespace identities and provision only a confirmed new installation through private operator access. Existing installations must not use fresh provisioning to clear an unbound floor or missing security data.

Attach the intended public HTTPS origin only after these checks. Disable every direct core route, workers.dev URL and preview URL. Preserve a separately administered security deployment and update approval path; account-wide application credentials or an old automatic build pipeline must not be assumed to enforce that boundary.

## Existing public relay

`prepare-authority-transfer.mjs` prepares closed configurations without deploying. It keeps the original public Worker name as the security owner, preserving its workers.dev hostname and any existing central namespaces. The legacy chain namespace transfers to a new private core; the source namespace ID must remain unchanged. The script preserves the deployed prefix of the original migration history and creates only classes absent from the verified live inventory. A destination class must not first be created empty and then used as a transfer target. These requirements follow [Cloudflare's existing-class transfer contract](https://developers.cloudflare.com/durable-objects/reference/durable-object-class-migrations-legacy/).

The operator supplies the original project configuration and a trusted, complete live inventory, pinned by the SHA-256 of that exact inventory file. Its schema is `version: 1`, `account_id`, `script_name`, `origin`, `migration_tag`, `private_script_absent: true`, and `namespaces: [{class_name, id, storage: "sqlite"}]`. IDs and account identity must come from the actual Cloudflare installation. A hash of a historical backup or invented IDs is not a current inventory. Verify that the proposed new private Worker name is unused.

```sh
cd relay
node security/prepare-authority-transfer.mjs \
  wrangler.jsonc /protected/live-inventory.json <inventory-sha256> \
  <stable-installation-id> <unused-private-core-name>
```

The script writes new configuration files beside the original and refuses to replace differing files. It never changes or deploys the source configuration. With writes stopped and retained backups, review/deploy the private-core bootstrap, verify the transferred chain ID, deploy the original Worker as the independent security owner, then deploy the final private-core bindings. Compare every preserved namespace ID with the trusted inventory. Keep all outputs unrouted until private floor/authority provisioning, the complete legacy-retirement/high-water inventory, data readback, actual IAM and update-pipeline checks pass. Restore the original public routing explicitly; do not assume a hostname follows a different Worker.

The generator refuses already split private-core deployments and unfamiliar ownership/migration histories. Those require preserving their existing security owner and transferring the three central namespaces to that owner with a reviewed provider-native transfer, never creating empty replacement classes. The [Compose handoff](../selfhost/central/README.md#existing-central-preview-handoff) is a different storage adapter and must not be applied to Cloudflare data.

## Backup and restore

Preserve current independent authority while restoring older application data. Reconcile the candidate against a demonstrably current checkpoint and the exact installation/namespace identities; retain current authority for any divergent central object. Do not merge security fields by timestamp, recreate missing credentials, lower a floor or revive an old registry. The Compose operator implements stopped-storage import and reconciliation with exact readback. Cloudflare uses its provider-native namespace/storage operations and must verify the same identities and current-state requirements in the actual account.

If the independent security store itself must be restored, a trusted newer reference is required. If all current authority and external references have been lost or rolled back, old copies cannot prove their own freshness. Keep the service unavailable in that case; E2EE does not reconstruct missing revocation history.

`npm run check:security-config` verifies source relationships only. Isolated Workers and Compose tests exercise implementation behavior; they do not verify live Cloudflare IAM, TLS, routes, namespace transfers or automatic builds. Native migration still requires full source inventory, explicit consent, exact target/readback verification and permanent retirement.
