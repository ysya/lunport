#!/bin/bash
# Never run against a user's login keychain. The disposable runner owns all fixtures.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_OS:-} == macOS ]] || { echo 'Disposable macOS CI runner required.' >&2; exit 1; }
umask 077
repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
probe="$(mktemp -d "${RUNNER_TEMP}/lunport-helper.XXXXXX")"
keychain="$probe/signing.keychain-db"
account="lunport-ci-helper-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
original_default="$(security default-keychain -d user | sed 's/^ *"//; s/"$//')"
security list-keychains -d user > "$probe/search-list.txt"
cleanup() {
  if [[ -x "$probe/client-1" ]]; then
    security default-keychain -d user -s "$keychain" || true
    "$probe/client-1" legacy-delete "$probe/helper" "$account-legacy" || true
    security default-keychain -d user -s "$original_default" || true
    "$probe/client-1" delete "$probe/helper" "$account-new" || true
  fi
  security default-keychain -d user -s "$original_default" || true
  local previous=() line
  while IFS= read -r line; do line="${line#*\"}"; line="${line%\"*}"; previous+=("$line"); done < "$probe/search-list.txt"
  security list-keychains -d user -s "${previous[@]}" || true
  security delete-keychain "$keychain" >/dev/null 2>&1 || true
  rm -rf "$probe"
}
trap cleanup EXIT
cat > "$probe/certificate.conf" <<'EOF'
[req]
distinguished_name = name
x509_extensions = signing
prompt = no
[name]
CN = Lunport Disposable Helper Test
[signing]
basicConstraints = critical,CA:TRUE
keyUsage = critical,digitalSignature,keyCertSign
extendedKeyUsage = codeSigning
subjectKeyIdentifier = hash
EOF
password="$(/usr/bin/openssl rand -hex 24)"
echo "::add-mask::$password"
/usr/bin/openssl req -new -newkey rsa:2048 -x509 -nodes -sha256 -days 2 \
  -config "$probe/certificate.conf" -keyout "$probe/key.pem" -out "$probe/certificate.pem" 2>/dev/null
/usr/bin/openssl pkcs12 -export -inkey "$probe/key.pem" -in "$probe/certificate.pem" -out "$probe/identity.p12" -passout "pass:$password"
security create-keychain -p "$password" "$keychain"
security unlock-keychain -p "$password" "$keychain"
security set-keychain-settings -lut 3600 "$keychain"
security import "$probe/identity.p12" -k "$keychain" -P "$password" -T /usr/bin/codesign
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$password" "$keychain" >/dev/null
previous=()
while IFS= read -r line; do line="${line#*\"}"; line="${line%\"*}"; previous+=("$line"); done < "$probe/search-list.txt"
security list-keychains -d user -s "$keychain" "${previous[@]}"
identity="$(/usr/bin/openssl x509 -in "$probe/certificate.pem" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':')"
requirement="identifier \"org.homelab.sshelter\" and certificate leaf = H\"$identity\""
python3 - "$probe/config.h" "$requirement" <<'PY'
import json, pathlib, sys
pathlib.Path(sys.argv[1]).write_text('#define LUNPORT_CLIENT_REQUIREMENT '+json.dumps(sys.argv[2])+'\n#define LUNPORT_CREDENTIAL_SERVICE "SSHelter Development"\n')
PY
clang -Wall -Wextra -Werror -Wno-deprecated-declarations \
  -include "$probe/config.h" \
  "$repo_dir/src-tauri/signing/credential-helper-v1.c" -framework Security -framework CoreFoundation -lbsm -o "$probe/helper"
codesign --force --sign "$identity" --keychain "$keychain" --options runtime --timestamp=none \
  --identifier org.homelab.sshelter.credential-helper.v1 "$probe/helper"
helper_hash="$(codesign --display --verbose=4 "$probe/helper" 2>&1 | sed -n 's/^CDHash=//p')"
python3 - "$probe/config.h" "$identity" "$helper_hash" <<'PY'
import json, pathlib, sys
with pathlib.Path(sys.argv[1]).open('a') as file:
    file.write('#define LUNPORT_HELPER_REQUIREMENT '+json.dumps('identifier "org.homelab.sshelter.credential-helper.v1" and certificate leaf = H"'+sys.argv[2]+'" and cdhash H"'+sys.argv[3]+'"')+'\n')
PY
for version in 1 2; do
  clang -Wall -Wextra -Werror -Wno-deprecated-declarations "-DCLIENT_VERSION=\"$version\"" \
    -include "$probe/config.h" "$repo_dir/scripts/macos-helper-client.c" "$repo_dir/src-tauri/src/macos_credential_peer.c" \
    -framework Security -framework CoreFoundation -lbsm -o "$probe/client-$version"
  codesign --force --sign "$identity" --keychain "$keychain" --options runtime --timestamp=none \
    --identifier org.homelab.sshelter "$probe/client-$version"
done
if cmp -s "$probe/client-1" "$probe/client-2"; then echo 'Client builds must differ.' >&2; exit 1; fi
helper_before="$(shasum -a 256 "$probe/helper" | awk '{print $1}')"

"$probe/client-1" set "$probe/helper" "$account-new"
"$probe/client-2" get "$probe/helper" "$account-new"
"$probe/client-2" replace "$probe/helper" "$account-new"
"$probe/client-1" contains "$probe/helper" "$account-new"
# Exercise a deliberate old-item trusted-application grant, never automation
# of the user's OS authorization dialog. The modern
# login-keychain partition/upgrade path is exercised separately above and below.
security default-keychain -d user -s "$keychain"
"$probe/client-1" legacy-create "$probe/helper" "$account-legacy"
"$probe/client-1" contains "$probe/helper" "$account-legacy"
"$probe/client-1" denied "$probe/helper" "$account-legacy"
"$probe/client-1" legacy-verify "$probe/helper" "$account-legacy"
"$probe/client-1" legacy-grant "$probe/helper" "$account-legacy"
"$probe/client-1" get "$probe/helper" "$account-legacy"
"$probe/client-2" get "$probe/helper" "$account-legacy"
"$probe/client-1" legacy-verify "$probe/helper" "$account-legacy"
security default-keychain -d user -s "$original_default"

for malformed in bad-op bad-magic oversized truncated; do
  "$probe/client-2" "$malformed" "$probe/helper" "$account-new"
done
cat > "$probe/forged.c" <<'EOF'
#include <unistd.h>
int main(void) { write(1,"LPKC0001",8); char buffer[1]; return read(0,buffer,1) > 0 ? 99 : 0; }
EOF
clang "$probe/forged.c" -o "$probe/forged-helper"
"$probe/client-2" helper-rejected "$probe/forged-helper" "$account-new"
for variant in adhoc wrong-id unhardened entitlement; do
  cp "$probe/client-2" "$probe/$variant"
  case "$variant" in
    adhoc) codesign --force --sign - --options runtime --identifier org.homelab.sshelter "$probe/$variant" ;;
    wrong-id) codesign --force --sign "$identity" --keychain "$keychain" --options runtime --timestamp=none --identifier org.homelab.unrelated "$probe/$variant" ;;
    unhardened) codesign --force --sign "$identity" --keychain "$keychain" --timestamp=none --identifier org.homelab.sshelter "$probe/$variant" ;;
    entitlement)
      cat > "$probe/unsafe.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>com.apple.security.cs.disable-library-validation</key><true/></dict></plist>
EOF
      codesign --force --sign "$identity" --keychain "$keychain" --options runtime --timestamp=none --entitlements "$probe/unsafe.plist" --identifier org.homelab.sshelter "$probe/$variant" ;;
  esac
  "$probe/$variant" rejected "$probe/helper" "$account-new"
done
"$probe/client-2" get "$probe/helper" "$account-new"
"$probe/client-2" delete "$probe/helper" "$account-new"
"$probe/client-2" missing "$probe/helper" "$account-new"
"$probe/client-2" delete "$probe/helper" "$account-new" # Idempotent deletion maps not-found in the App.
[[ "$(shasum -a 256 "$probe/helper" | awk '{print $1}')" == "$helper_before" ]]
echo 'Modern partition-protected upgrade, deliberate legacy ACL grant, denied clients and bounded protocol passed without authentication UI.'
