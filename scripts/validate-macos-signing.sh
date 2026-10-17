#!/bin/bash
# Exercise the release verifier on a tiny universal bundle before compiling the app.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_OS:-} == macOS ]] || exit 1
: "${APPLE_SIGNING_IDENTITY:?Prepare the pinned CI identity first}"
probe="$(mktemp -d "${RUNNER_TEMP}/lunport-signing-probe.XXXXXX")"
trap 'rm -rf "$probe"' EXIT
app="$probe/Lunport.app"
mkdir -p "$app/Contents/MacOS"
cat > "$app/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>org.homelab.sshelter</string>
<key>CFBundleExecutable</key><string>sshelter</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleName</key><string>Lunport Signing Probe</string>
</dict></plist>
EOF
clang -arch arm64 -arch x86_64 -Wno-deprecated-declarations scripts/macos-keychain-probe.c \
  -framework Security -framework CoreFoundation -o "$app/Contents/MacOS/sshelter"
codesign --force --sign "$APPLE_SIGNING_IDENTITY" --timestamp=none "$app"
bash scripts/macos-signing.sh verify "$app"
keychain="$RUNNER_TEMP/lunport-project-signing/signing.keychain-db"
account="lunport-ci-project-upgrade-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
"$app/Contents/MacOS/sshelter" write "$keychain" 'SSHelter Development' "$account"
clang -arch arm64 -arch x86_64 -Wno-deprecated-declarations '-DPROBE_VERSION="2"' scripts/macos-keychain-probe.c \
  -framework Security -framework CoreFoundation -o "$app/Contents/MacOS/sshelter"
codesign --force --sign "$APPLE_SIGNING_IDENTITY" --timestamp=none "$app"
bash scripts/macos-signing.sh verify "$app"
"$app/Contents/MacOS/sshelter" read "$keychain" 'SSHelter Development' "$account"
codesign --force --sign - "$app"
"$app/Contents/MacOS/sshelter" denied "$keychain" 'SSHelter Development' "$account"
if bash scripts/macos-signing.sh verify "$app" > "$probe/rejected.log" 2>&1; then
  echo 'Release verifier incorrectly accepted ad-hoc signing.' >&2; exit 1
fi
echo 'Pinned universal bundle accepted; ad-hoc replacement rejected.'
