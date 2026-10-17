#!/bin/bash
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_OS:-} == macOS ]] || exit 1
: "${APPLE_SIGNING_IDENTITY:?Prepare the pinned signing identity first}"
repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
python3 "$repo_dir/scripts/verify-macos-credential-helper.py"
report="${RUNNER_TEMP:?}/lunport-helper-rust-build.jsonl"
cargo test --locked --manifest-path "$repo_dir/src-tauri/Cargo.toml" --lib --no-run --message-format=json > "$report"
test_binary="$(python3 - "$report" <<'PY'
import json, pathlib, sys
matches = [event['executable'] for line in pathlib.Path(sys.argv[1]).read_text().splitlines() if (event:=json.loads(line)).get('reason')=='compiler-artifact' and event.get('executable') and event.get('profile',{}).get('test') and event['target']['name']=='sshelter_lib']
assert len(matches)==1, 'expected one native library test executable'
print(matches[0])
PY
)"
# Keep a production-authorized test executable out of the reusable Cargo cache.
signed_probe="${RUNNER_TEMP}/lunport-helper-rust-signed-probe"
trap 'rm -f "$signed_probe"' EXIT
cp "$test_binary" "$signed_probe"
chmod 700 "$signed_probe"
codesign --force --sign "$APPLE_SIGNING_IDENTITY" --options runtime --timestamp=none --identifier org.homelab.sshelter "$signed_probe"
"$signed_probe" --ignored --exact secrets::macos_helper::tests::native_frozen_transport_probe --test-threads=1 --nocapture
