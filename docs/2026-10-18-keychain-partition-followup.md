# Keychain authorization after Always Allow

The user reports that updates still request Keychain authorization after choosing **Always Allow**. The fixed project certificate from the earlier fix addresses the designated requirement, but it does not address every Keychain authorization layer.

## Evidence and scope

Published 1.2.0, 1.3.0 and 1.4.0 bundles have the same project certificate and designated requirement. The 1.4.0 bundle still passes strict, deep, all-architecture signature verification outside the filesystem sandbox. Rotating the certificate or re-signing an installation is not the proposed fix.

Apple's [securityd client identity implementation](https://github.com/apple-oss-distributions/Security/blob/main/securityd/src/clientid.cpp#L187) assigns an Apple-verified Team ID partition to supported Apple distribution/development identities. Other signed code, including the project's self-signed certificate, falls back to `cdhash:<executable hash>`. That hash changes with each executable build, independently of the designated requirement. Apple's older [designated requirement guidance](https://developer.apple.com/library/archive/technotes/tn2206/) does not by itself establish compatibility with a separate partition restriction.

The earlier CI fixture used a newly created legacy-format keychain without a partition ACL. It therefore could not establish compatibility with the partition gate. The extended probe also creates a synthetic item with `SecItemAdd` in the disposable runner's existing login keychain, requires a nonempty partition ACL, verifies the original executable can read it, then checks that a rebuilt executable with the same certificate and designated requirement is denied. Authentication UI stays disabled throughout, and cleanup deletes only that uniquely named synthetic item.

The [native identity job passed](https://github.com/ysya/lunport/actions/runs/39074293630/job/117518159624) at commit `35b6c1f`. Its relevant output is:

```text
probe 1: write-modern passed without interaction
partition ACL count: 1
probe 1: partition passed without interaction
probe 1: read passed without interaction
probe 2: denied passed without interaction
Reproduced: a cdhash-restricted existing item rejects a rebuilt executable with the same certificate and designated requirement.
probe 1: delete passed without interaction
```

This reproduces the mechanism, not the user's exact affected item. A read-only, noninteractive metadata survey on this host found no generic-password items for the exact `SSHelter` service. It read no passwords, printed no account names and changed no access rules. The affected installation's ACLs therefore remain unverified.

## Bounded change already implemented

Legacy SSH route selection still read the protected password just to choose an authentication method. On macOS this now uses the existing metadata-only presence query. The connector obtains protected data when authentication actually needs it. This removes an unnecessary protected read; it does **not** eliminate partition-related authorization after updates.

The signing policy and download documentation now distinguish stable code requirements from partition authorization. Existing credentials, service/account names and stored access rules are preserved.

The local Legacy SSH directory suite passes all 28 tests. The native result above validates the identity/partition probe; it does not substitute for the separate signed-bundle build or the PR's full platform checks.

## Authorized fixed helper implementation

The user approved implementation and verification of the fixed helper on 2026-10-18. Apple Developer ID remains a possible future distribution choice, but this implementation uses the existing pinned project certificate.

Production macOS `secrets::get/set/delete` now launch a one-request helper. Development, Windows and Linux keep their existing isolated/native stores. Metadata-only presence checks still read no password. Credentials retain their existing service (`SSHelter`), accounts and values. Production never edits an ACL, removes a partition restriction, copies credentials into a file, or falls back to direct App access after a helper failure.

### Frozen artifact and lifecycle

The universal helper is embedded as data in the App, so bundle signing cannot alter its signature. The reviewed artifact came from [the isolated candidate build](https://github.com/ysya/lunport/actions/runs/39075922311) at `9f8a9ee57e238b19d07932708274d416c2cbf6d3`. Its SHA-256 is `6d74a63293b153fccae754e1c4d38449e5cc26065738fae7d0cfc64dcddf2178`; the manifest records source SHA-256 and each architecture's code hash. Only public signed executable data is committed; no private signing material is embedded.

First protected use installs those bytes at `~/Library/Application Support/org.homelab.sshelter/credential-helper/v1/Lunport Credential Helper`. Ordinary App updates leave a matching file and inode intact. Missing/corrupt regular files are restored atomically from the signed App. Installation rejects symlinks, unexpected owners, shared writable directories and hard-linked executable files. There is no launch agent, daemon, network port or permanent listener. Each helper exits after one operation, and both ends have bounded timeouts and cleanup.

Normal release builds verify and reuse this artifact. They never run the candidate build script. Changing the frozen source or bytes fails verification. A necessary helper security update must use a deliberate new version with a new authorization/migration plan; it can require macOS authorization again.

### Authenticated channel

The App creates an anonymous Unix socket pair and launches the helper without inherited environment configuration. Before reading the request, the helper obtains the caller's kernel audit token and verifies its UID, direct parent process, pinned certificate, production bundle identifier and live code validity. It requires hardened runtime and rejects debugging or entitlements permitting library/unsigned-code injection.

The helper sends a public greeting first. Before sending even the account name, the App checks the live child's audit token, expected PID, pinned certificate, helper identifier and one of the exact frozen architecture code hashes. This closes the gap between checking an installation path and executing it. A replaced executable receives no request or password. The release verifier checks that both App architectures meet the helper's signing/runtime requirements.

The versioned binary protocol accepts only get/set/delete/metadata operations in the fixed service, bounds account/data lengths, and rejects extra or malformed input. Secrets never enter command arguments, environment variables, logs, settings or sync. Response/input buffers are cleared when possible; no password cache is introduced.

### Existing items and first authorization

The first use of each existing protected item can show the normal macOS dialog for **Lunport Credential Helper**. Choosing **Always Allow** authorizes that fixed helper. Denial, cancellation or a locked Keychain preserves the item and returns an actionable error. New items are created with the helper as their owner, including its fixed partition hash. Subsequent App builds use the same helper identity. Locking or changing Keychain policies still retains normal macOS behavior.

The automated native suite proves that pre-approval access is denied without obtaining data and that the original App can still read the unchanged item. It separately creates an already-approved legacy fixture and proves both App builds can read it via the same helper. Modern login-keychain fixtures must contain the helper's exact partition hash and remain readable across different App builds. The suite does **not** automate the real Always Allow dialog; that interactive step remains a manual installation check.

### Validation

- [Isolated native helper suite and candidate build](https://github.com/ysya/lunport/actions/runs/39075922311): modern partition ownership, App upgrade, pre/post-approval legacy fixtures, denied ad-hoc/wrong-ID/unhardened/unsafe-entitlement clients, forged helper, malformed/bounded protocol, and cleanup passed with authentication UI disabled.
- Local installer/input/manifest tests: four passed; the native production-transport test is ignored locally because it requires a disposable runner and a production-signed test executable.
- A separate CI job signs that Rust test executable with the pinned identity and exercises the actual App transport and frozen helper, including missing/corrupt-file recovery. The signed universal App/updater build and platform checks remain required before publication.
