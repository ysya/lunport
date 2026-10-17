#!/bin/bash
set -euo pipefail
repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
test "$(git -C "$repo_dir" rev-parse 'v1.2.0^{commit}')" = cc3ce196cad26775ddf5d3cbd9c8d189a8b79fa8
scratch="$(mktemp -d "${TMPDIR:-/tmp}/lunport-group-order-compat.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
git -C "$repo_dir" archive v1.2.0 | tar -xf - -C "$scratch"
cp "$repo_dir/scripts/compat/group-order-v1.2.rs" "$scratch/src-tauri/src/sync/group_order_compat.rs"
printf '\n#[cfg(test)]\n#[path = "group_order_compat.rs"]\nmod group_order_compat;\n' >> "$scratch/src-tauri/src/sync/record_merge.rs"
mkdir -p "$scratch/dist"
printf '<!doctype html><title>Compatibility fixture</title>\n' > "$scratch/dist/index.html"
CARGO_TARGET_DIR="$repo_dir/src-tauri/target" cargo test --locked --manifest-path "$scratch/src-tauri/Cargo.toml" --lib group_order_compat -- --nocapture
