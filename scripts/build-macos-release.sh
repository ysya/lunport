#!/bin/bash
# tauri-action calls this instead of `pnpm tauri`, so validation happens BEFORE upload.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_OS:-} == macOS ]] || { echo 'Disposable macOS CI runner required.' >&2; exit 1; }
: "${APPLE_SIGNING_IDENTITY:?Run macos-signing.sh prepare first}"
[[ ${1:-} == build ]] || { echo 'Only tauri build is supported.' >&2; exit 64; }
# The release embeds the frozen programs: helper v1 and the bridge to it for the credential migration, helper v2 for everything else.
# Until helper v2 is frozen and committed this stops the build, as the app's own compile-time check would.
python3 scripts/verify-macos-credential-helper.py
python3 src-tauri/signing/legacy/verify-credential-bridge.py
python3 scripts/verify-macos-credential-helper.py --version v2
# Tauri names the bundle after the product (scripts/identity.mjs).
app="$(node scripts/identity.mjs | python3 -c 'import json, sys; print(json.load(sys.stdin)["production"]["productName"])').app"
pnpm tauri "$@"
bundle='src-tauri/target/universal-apple-darwin/release/bundle/macos'
bash scripts/macos-signing.sh verify "$bundle/$app"
# Verify the actual updater payload as well as the bundle the DMG is built from.
unpacked="$(mktemp -d "${RUNNER_TEMP}/lunport-updater.XXXXXX")"
trap 'rm -rf "$unpacked"' EXIT
tar -xzf "$bundle/$app.tar.gz" -C "$unpacked"
bash scripts/macos-signing.sh verify "$unpacked/$app"
