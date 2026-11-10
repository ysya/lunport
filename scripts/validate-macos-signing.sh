#!/bin/bash
# Exercise the release verifier on a tiny universal bundle before compiling the app.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_OS:-} == macOS ]] || exit 1
: "${APPLE_SIGNING_IDENTITY:?Prepare the pinned CI identity first}"
# A value of the JSON text given first, by the keys after it.
json_value() { python3 -c 'import functools, json, sys; print(functools.reduce(lambda value, key: value[key], sys.argv[2:], json.loads(sys.argv[1])))' "$@"; }
# The probe is the production app as macos-signing.sh verify expects it: its name, bundle identifier and main binary. Its item is kept
# under the Development credential service. All of them come from scripts/identity.mjs.
current="$(node scripts/identity.mjs)"
product="$(json_value "$current" production productName)"
app_id="$(json_value "$current" production appId)"
executable="$(json_value "$current" production mainBinary)"
service="$(json_value "$current" development credentialService)"
probe="$(mktemp -d "${RUNNER_TEMP}/lunport-signing-probe.XXXXXX")"
trap 'rm -rf "$probe"' EXIT
app="$probe/$product.app"
mkdir -p "$app/Contents/MacOS"
cat > "$app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>$app_id</string>
<key>CFBundleExecutable</key><string>$executable</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleName</key><string>Lunport Signing Probe</string>
</dict></plist>
EOF
clang -arch arm64 -arch x86_64 -Wno-deprecated-declarations scripts/macos-keychain-probe.c \
  -framework Security -framework CoreFoundation -o "$app/Contents/MacOS/$executable"
codesign --force --sign "$APPLE_SIGNING_IDENTITY" --options runtime --timestamp=none "$app"
bash scripts/macos-signing.sh verify "$app"
keychain="$RUNNER_TEMP/lunport-project-signing/signing.keychain-db"
account="lunport-ci-project-upgrade-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
"$app/Contents/MacOS/$executable" write "$keychain" "$service" "$account"
clang -arch arm64 -arch x86_64 -Wno-deprecated-declarations '-DPROBE_VERSION="2"' scripts/macos-keychain-probe.c \
  -framework Security -framework CoreFoundation -o "$app/Contents/MacOS/$executable"
codesign --force --sign "$APPLE_SIGNING_IDENTITY" --options runtime --timestamp=none "$app"
bash scripts/macos-signing.sh verify "$app"
"$app/Contents/MacOS/$executable" read "$keychain" "$service" "$account"
codesign --force --sign - "$app"
"$app/Contents/MacOS/$executable" denied "$keychain" "$service" "$account"
if bash scripts/macos-signing.sh verify "$app" > "$probe/rejected.log" 2>&1; then
  echo 'Release verifier incorrectly accepted ad-hoc signing.' >&2; exit 1
fi
echo 'Pinned universal bundle accepted; ad-hoc replacement rejected.'
