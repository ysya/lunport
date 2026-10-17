# Lunport 1.3.1-1 Beta evidence

This Beta publishes the compact host-grid changes from draft [PR #36](https://github.com/ysya/lunport/pull/36) for hands-on feedback. The source is `1c59566f1117f8e91929b95ac1c7fecb18c09239`; the PR remains unmerged and Stable remains 1.3.0. [Validation](../1.3.1-1-validation.md) records the source checks, review limits and publication results.

Publication metadata is retained in `publication/`. Installer payloads are downloaded into a temporary directory and are not committed. Build the strict minisign checker using the [shared instructions](../1.1.0-review/README.md), then reproduce this Beta's verification:

```sh
receipt_dir="$(mktemp -d /tmp/lunport-131-beta1-receipts.XXXXXX)"
cp -R docs/releases/1.3.1-1-review/publication/. "$receipt_dir/"
gh release download v1.3.1-1 --repo ysya/lunport --skip-existing --dir "$receipt_dir/release"
node docs/releases/1.3.1-1-review/verify-publication.mjs "$receipt_dir" v1.3.1-1 \
  1c59566f1117f8e91929b95ac1c7fecb18c09239 "$checker_dir/target/debug/lunport-signature-check"
```

The verifier checks all asset sizes and GitHub SHA256 digests, authenticates nine updater payloads with legacy signatures disabled and rejects modified copies. It verifies all platform aliases, the Beta channel, Stable's unchanged manifest and four historical Stable release/tag identities. Archived endpoints describe publication time; live channels may advance later.

Manifest requests use the shipped updater's `Accept: application/json` and `tauri-plugin-updater/2.10.1` user agent without added query parameters. The macOS receipt checks the downloaded universal App without launching it: Intel/Apple Silicon architectures, strict bundle signature, fixed certificate, designated requirement, existing identities, version and Folded L icon. Project signing does not provide Apple Developer ID or notarization.
