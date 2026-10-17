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

## Decision before a structural fix

**A. Apple Developer ID distribution signing — recommended.** Configure a Developer ID Application certificate in CI and verify its Team ID in both universal architectures. This keeps the existing credential architecture. Moving from the project certificate can require an initial authorization for existing items; subsequent releases can retain the Apple-verified Team ID. It requires an Apple developer account and its signing identity, which the user previously did not have. This work should begin only after that identity is available and authorized.

**B. A fixed credential helper — an architectural alternative to evaluate.** Install an immutable, narrowly scoped credential helper outside the replaceable App bundle. Ordinary App updates retain exactly that helper binary, so the Keychain caller's hash stays fixed. The helper would validate each client as the same user and a valid Lunport executable with the pinned certificate and bundle identifier, using an authenticated local IPC connection. Its operations would be limited to Lunport's credential service, with no secret logging. Existing items would need a deliberate initial authorization/migration to that helper. Updating the helper itself could require authorization again.

Before implementation, this alternative needs a concrete IPC/peer-validation design, lifecycle and installer behavior, recovery when the helper is missing, compatibility with existing credentials, and an isolated migration/upgrade/unauthorized-client test suite. Failure must preserve original entries and leave the existing explicit OS authorization path available. This is a proposal, not an implemented guarantee.

The repository's `Agent.md` says **“Ask before making architectural changes.”** The helper alternative therefore needs the user's approval before integration. Neither option is silently enabled by the diagnostic/test changes in this follow-up.
