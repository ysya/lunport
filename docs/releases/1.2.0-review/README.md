# Lunport 1.2.0 evidence

[Release validation](../1.2.0-validation.md) records the full-height sidebar, key renaming, native Development App checks, platform suites and fixed macOS project signing. The release source is `cc3ce196cad26775ddf5d3cbd9c8d189a8b79fa8`; its tree matches the merged release PR exactly.

Publication metadata is retained in `publication/`. Installer payloads are downloaded into a temporary directory and are not committed. The [shared verifier and signature-checker instructions](../1.1.0-review/README.md) describe the same strict minisign implementation used by the updater. For this release, use the local wrapper so both historical Stable releases are checked:

```sh
receipt_dir="$(mktemp -d /tmp/lunport-120-receipts.XXXXXX)"
cp -R docs/releases/1.2.0-review/publication/. "$receipt_dir/"
gh release download v1.2.0 --repo ysya/lunport --skip-existing --dir "$receipt_dir/release"
node docs/releases/1.2.0-review/verify-publication.mjs "$receipt_dir" v1.2.0 \
  cc3ce196cad26775ddf5d3cbd9c8d189a8b79fa8 "$checker_dir/target/debug/lunport-signature-check"
```

Archived endpoints describe publication time; live channels may advance later. Manifest requests use the shipped updater's `Accept: application/json` and `tauri-plugin-updater/2.10.1` user agent, without cache-busting query parameters. GitHub varies its redirect cache by Accept. The macOS receipt checks the downloaded universal App without launching it: both architectures, strict bundle signature, certificate pin, stable designated requirement, existing bundle/executable identities, version and Folded L icon. Project signing does not provide Apple Developer ID or notarization.
