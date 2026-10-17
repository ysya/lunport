#!/bin/bash
# tauri-action calls this instead of `pnpm tauri`, so validation happens BEFORE upload.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_OS:-} == macOS ]] || { echo 'Disposable macOS CI runner required.' >&2; exit 1; }
: "${APPLE_SIGNING_IDENTITY:?Run macos-signing.sh prepare first}"
[[ ${1:-} == build ]] || { echo 'Only tauri build is supported.' >&2; exit 64; }
python3 scripts/verify-macos-credential-helper.py
pnpm tauri "$@"
bundle='src-tauri/target/universal-apple-darwin/release/bundle/macos'
bash scripts/macos-signing.sh verify "$bundle/Lunport.app"
# Verify the actual updater payload as well as the bundle the DMG is built from.
unpacked="$(mktemp -d "${RUNNER_TEMP}/lunport-updater.XXXXXX")"
trap 'rm -rf "$unpacked"' EXIT
tar -xzf "$bundle/Lunport.app.tar.gz" -C "$unpacked"
bash scripts/macos-signing.sh verify "$unpacked/Lunport.app"
