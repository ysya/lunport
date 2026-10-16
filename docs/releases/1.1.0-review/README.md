# Lunport 1.1.0 evidence

[Release validation](../1.1.0-validation.md) links the failing native baseline, repaired regressions, complete platform/profile tests, actual package upgrades and publication receipts. Large installer payloads are downloaded into a temporary directory and are not committed here.

`signature-checker.rs` is the exact verifier source used for this release. It uses `minisign-verify = 0.2.5`, the same version as the Tauri updater, authenticates the artifact and trusted comment with the shipped public key, and rejects a modified copy. Legacy signatures are disabled.

From the repository root, reproduce the archived publication verification with Cargo, Node and authenticated `gh`:

```sh
checker_dir="$(mktemp -d /tmp/lunport-signature-check.XXXXXX)"
cargo init --bin --name lunport-signature-check "$checker_dir"
cp docs/releases/1.1.0-review/signature-checker.rs "$checker_dir/src/main.rs"
printf '\nminisign-verify = "=0.2.5"\n' >> "$checker_dir/Cargo.toml"
cargo build --manifest-path "$checker_dir/Cargo.toml"

receipt_dir="$(mktemp -d /tmp/lunport-receipts.XXXXXX)"
cp -R docs/releases/1.1.0-review/publication/. "$receipt_dir/"
gh release download v1.1.0 --repo ysya/lunport --skip-existing --dir "$receipt_dir/release"
node docs/releases/1.1.0-review/verify-publication.mjs "$receipt_dir" v1.1.0 \
  d1a77544f223794d8a88c2c3cdae211f99ad15e9 "$checker_dir/target/debug/lunport-signature-check"
```

This checks downloaded bytes against the archived release digests, uploaded signature files, tag commit, all manifest aliases, the new and original updater endpoints as observed at publication, and the frozen historical v1.0.0 asset identities. Archived endpoints describe publication time; the live channels may advance in a future release.
