# Lunport 1.4.0 evidence

[Release validation](../1.4.0-validation.md) records the approved UI preview, version-stamped candidate checks and exact release tree. Publication metadata and CI snapshots are stored under `publication/` and `ci/`; installer payloads remain in a temporary verification directory.

The verifier extends the [shared minisign and artifact verifier](../1.1.0-review/README.md) with frozen historical releases through v1.3.0 and the v1.3.1-1 beta. After building the checker described there, reproduce using archived metadata:

```sh
receipt_dir="$(mktemp -d /tmp/lunport-140-receipts.XXXXXX)"
cp -R docs/releases/1.4.0-review/publication/. "$receipt_dir/"
gh release download v1.4.0 --repo ysya/lunport --skip-existing --dir "$receipt_dir/release"
node docs/releases/1.4.0-review/verify-publication.mjs "$receipt_dir" v1.4.0 \
  2e091fab86a6b86ba91462b1a9039e83959ffc71 "$checker_dir/target/debug/lunport-signature-check"
```

Archived endpoints describe publication time; live channels may advance. Manifest requests use the shipped updater headers without cache-busting query parameters. macOS verification reads the signed universal bundle without launching or installing it or importing credentials into the user's Keychain.
