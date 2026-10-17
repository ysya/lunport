# Lunport 1.3.0 evidence

[Release validation](../1.3.0-validation.md) records synced Group ordering, Known hosts management, manual TCP checks, actual v1.2.0 compatibility, native Development App review and platform/package checks. Release source `922d278bfef86bbaee4e709e8f8232e1bc33d581` has exactly the same tree as the tested release PR head.

Publication metadata is retained in `publication/`. Installer payloads are downloaded into a temporary directory and are not committed. The [shared verifier and signature-checker instructions](../1.1.0-review/README.md) describe the same strict minisign implementation used by the updater. Use this release's wrapper to also check the frozen v1.1.0 and v1.2.0 releases:

```sh
receipt_dir="$(mktemp -d /tmp/lunport-130-receipts.XXXXXX)"
cp -R docs/releases/1.3.0-review/publication/. "$receipt_dir/"
gh release download v1.3.0 --repo ysya/lunport --skip-existing --dir "$receipt_dir/release"
node docs/releases/1.3.0-review/verify-publication.mjs "$receipt_dir" v1.3.0 \
  922d278bfef86bbaee4e709e8f8232e1bc33d581 "$checker_dir/target/debug/lunport-signature-check"
```

Archived endpoints describe publication time; live channels may advance later. Manifest requests use the shipped updater's `Accept: application/json` and `tauri-plugin-updater/2.10.1` user agent, without cache-busting query parameters. The macOS receipt checks the downloaded universal App without launching it: both architectures, strict bundle signature, fixed certificate, stable designated requirement, existing bundle/executable identities, version and Folded L icon. Project signing does not provide Apple Developer ID or notarization.
