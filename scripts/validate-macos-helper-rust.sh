#!/bin/bash
# Runs the app's own Rust code against frozen credential programs from the checkout, from a CI-only test executable signed with the
# project certificate as the app. Disposable macOS CI runner only.
#   validate-macos-helper-rust.sh          channel, installation and recovery against helper v2, which keeps Production credentials
#   validate-macos-helper-rust.sh bridge   the credential migration's session through the frozen bridge to the frozen helper v1,
#                                          asked for an account no item has (nothing is created, changed or asked)
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_OS:-} == macOS ]] || exit 1
: "${APPLE_SIGNING_IDENTITY:?Prepare the pinned signing identity first}"
repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
case "${1:-helper}" in
  helper) probe=secrets::macos_helper::tests::native_frozen_transport_probe
          # The frozen programs a Production build embeds: helper v1 and the bridge for the credential migration, helper v2 for
          # everything else.
          python3 "$repo_dir/scripts/verify-macos-credential-helper.py"
          python3 "$repo_dir/src-tauri/signing/legacy/verify-credential-bridge.py"
          python3 "$repo_dir/scripts/verify-macos-credential-helper.py" --version v2 ;;
  bridge) probe=secrets::macos_helper::bridge::tests::native_frozen_bridge_probe
          python3 "$repo_dir/scripts/verify-macos-credential-helper.py"
          python3 "$repo_dir/src-tauri/signing/legacy/verify-credential-bridge.py" ;;
  *) echo 'Usage: validate-macos-helper-rust.sh [bridge]' >&2; exit 64 ;;
esac
# Signed as the production app, whose bundle identifier the frozen programs require of their parent (scripts/identity.mjs).
app_identifier="$(node "$repo_dir/scripts/identity.mjs" | python3 -c 'import json, sys; print(json.load(sys.stdin)["production"]["appId"])')"
report="${RUNNER_TEMP:?}/lunport-helper-rust-build.jsonl"
cargo test --locked --manifest-path "$repo_dir/src-tauri/Cargo.toml" --lib --no-run --message-format=json > "$report"
test_binary="$(python3 - "$report" <<'PY'
import json, pathlib, sys
matches = [event['executable'] for line in pathlib.Path(sys.argv[1]).read_text().splitlines() if (event:=json.loads(line)).get('reason')=='compiler-artifact' and event.get('executable') and event.get('profile',{}).get('test') and event['target']['name']=='lunport_lib']
assert len(matches)==1, 'expected one native library test executable'
print(matches[0])
PY
)"
# Keep a production-authorized test executable out of the reusable Cargo cache.
signed_probe="${RUNNER_TEMP}/lunport-helper-rust-signed-probe"
trap 'rm -f "$signed_probe"' EXIT
cp "$test_binary" "$signed_probe"
chmod 700 "$signed_probe"
codesign --force --sign "$APPLE_SIGNING_IDENTITY" --options runtime --timestamp=none --identifier "$app_identifier" "$signed_probe"
"$signed_probe" --ignored --exact "$probe" --test-threads=1 --nocapture
