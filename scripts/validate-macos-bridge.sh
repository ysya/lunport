#!/bin/bash
# Validates the credential bridge -> helper v1 chain and helper v2 (including adopt) with
# disposable fixture builds signed by two throwaway certificates: one stands in for the
# project certificate, the other for the certificate the previous identity used.
#
# Safe on a developer Mac as well as on CI: every command runs with HOME inside a temporary
# directory whose only keychain is a new disposable one, so the Security framework never
# sees the user's keychain preferences, search list or login keychain. Before the first
# keychain change the script proves that the temporary HOME hides the user's preferences,
# and it restores them on exit should they differ anyway. The fixture bridge passes the
# same HOME to helper v1, helper v2 inherits it from the client, the client refuses to run
# unless that disposable keychain is its default, and nothing allows authorization UI.
#
# A new keychain gives items no partition list, so the partition owner of the items helper
# v2 creates is checked only on a disposable CI runner, in its login keychain (as
# validate-macos-helper.sh does); elsewhere the owner is checked through the item's access.
set -euo pipefail
[[ "$(uname -s)" == Darwin ]] || { echo 'macOS required.' >&2; exit 1; }
umask 077
repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
v1_source="$repo_dir/src-tauri/signing/legacy/credential-helper-v1.c"
v2_source="$repo_dir/src-tauri/signing/credential-helper-v2.c"
bridge_source="$repo_dir/src-tauri/signing/legacy/credential-bridge.c"
client_sources=("$repo_dir/scripts/macos-bridge-client.c" "$repo_dir/src-tauri/src/macos_credential_peer.c")
keychain_probe_source="$repo_dir/scripts/macos-keychain-probe.c"

# The app and helper v2 under their own identifiers, from scripts/identity.mjs (read before HOME changes, which a Node version manager
# may need). The bridge and helper v1 are signed with the stand-in for the previous certificate, so they take stand-in identifiers.
current="$(node "$repo_dir/scripts/identity.mjs")"
json_value() { # JSON text, then keys: the value under them
  python3 -c 'import functools, json, sys; print(functools.reduce(lambda value, key: value[key], sys.argv[2:], json.loads(sys.argv[1])))' "$@"
}
app_id="$(json_value "$current" production appId)"
v2_id="$(json_value "$current" helperV2 identifier)"
bridge_id="$app_id.validation.bridge"  # stands in for the previous app identifier
v1_id="$app_id.validation.helper-v1"   # stands in for helper v1's identifier

real_home="$HOME"
real() { HOME="$real_home" security "$@" 2>&1 || true; }
real_default="$(real default-keychain -d user)"
real_search="$(real list-keychains -d user)"
untouched() {
  [[ "$(real default-keychain -d user)" == "$real_default" && "$(real list-keychains -d user)" == "$real_search" ]]
}
# Put the captured default keychain and search list back, as macos-signing.sh restores its
# search list. Only quoted paths are taken from the captured output.
restore() {
  local line default='' previous=()
  [[ "$real_default" =~ ^[[:space:]]*\"(.+)\"$ ]] && default="${BASH_REMATCH[1]}"
  while IFS= read -r line; do
    if [[ "$line" =~ ^[[:space:]]*\"(.+)\"$ ]]; then previous+=("${BASH_REMATCH[1]}"); fi
  done <<< "$real_search"
  if [[ -n "$default" ]]; then HOME="$real_home" security default-keychain -d user -s "$default" || true; fi
  if ((${#previous[@]})); then HOME="$real_home" security list-keychains -d user -s "${previous[@]}" || true; fi
}
probe="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/lunport-bridge-validation.XXXXXX")"
probe="$(cd "$probe" && pwd -P)"
keychain="$probe/validation.keychain-db"
login_fixtures=() # disposable CI runner only: owner|service|account of items in its login keychain
cleanup() {
  ((${#login_fixtures[@]} == 0)) || remove_login_fixtures
  security delete-keychain "$keychain" >/dev/null 2>&1 || true
  rm -rf "$probe"
  if untouched; then
    echo "The user's default keychain and search list are unchanged."
  else
    restore
    if untouched; then echo "WARNING: the user's default keychain or search list changed during this run and was restored." >&2
    else printf 'WARNING: could not restore the default keychain and search list. Before this run:\n%s\n%s\n' "$real_default" "$real_search" >&2; fi
  fi
}
trap cleanup EXIT
mkdir -m 700 "$probe/home" "$probe/home/Library" "$probe/home/Library/Keychains" "$probe/home/Library/Preferences"
export HOME="$probe/home"
# Read-only proof, before any keychain change, that the empty temporary HOME hides the user's
# preferences: neither the default keychain nor the search list may look like the user's.
if [[ "$(security default-keychain -d user 2>&1 || true)" == "$real_default" ||
      "$(security list-keychains -d user 2>&1 || true)" == "$real_search" ]]; then
  echo 'Stopping before any keychain change: the temporary HOME does not hide the keychain preferences.' >&2
  exit 1
fi
export LUNPORT_VALIDATION_KEYCHAIN="$keychain"

# Two throwaway signing identities in the disposable keychain.
password="$(/usr/bin/openssl rand -hex 24)"
[[ -z "${GITHUB_ACTIONS:-}" ]] || echo "::add-mask::$password"
security create-keychain -p "$password" "$keychain"
security unlock-keychain -p "$password" "$keychain"
security set-keychain-settings -lut 3600 "$keychain"
security default-keychain -d user -s "$keychain"
security list-keychains -d user -s "$keychain"
untouched || { echo 'Stopping: the keychain preferences outside the temporary HOME changed.' >&2; exit 1; }
[[ "$(security default-keychain -d user | sed 's/^ *"//; s/"$//')" == "$keychain" ]] || { echo 'Disposable keychain is not the default.' >&2; exit 1; }
certificate() { # name, common name
  cat > "$probe/$1.conf" <<EOF
[req]
distinguished_name = name
x509_extensions = signing
prompt = no
[name]
CN = $2
[signing]
basicConstraints = critical,CA:TRUE
keyUsage = critical,digitalSignature,keyCertSign
extendedKeyUsage = codeSigning
subjectKeyIdentifier = hash
EOF
  /usr/bin/openssl req -new -newkey rsa:2048 -x509 -nodes -sha256 -days 2 \
    -config "$probe/$1.conf" -keyout "$probe/$1.key" -out "$probe/$1.pem" 2>/dev/null
  /usr/bin/openssl pkcs12 -export -inkey "$probe/$1.key" -in "$probe/$1.pem" -out "$probe/$1.p12" -passout "pass:$password"
  security import "$probe/$1.p12" -k "$keychain" -P "$password" -T /usr/bin/codesign >/dev/null
  rm "$probe/$1.key" "$probe/$1.p12"
  /usr/bin/openssl x509 -in "$probe/$1.pem" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':' | tr '[:upper:]' '[:lower:]'
}
project="$(certificate project 'Lunport Disposable Project Test')"
previous="$(certificate previous 'Lunport Disposable Previous Identity Test')"
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$password" "$keychain" >/dev/null

old_service='Lunport Validation Old'
new_service='Lunport Validation New'

define() { # header, then name value pairs
  python3 - "$@" <<'PY'
import json, sys
path, *pairs = sys.argv[1:]
with open(path, 'a') as header:
    for name, value in zip(pairs[::2], pairs[1::2]):
        header.write(f'#define {name} {json.dumps(value)}\n')
PY
}
build() { # output, source, header, then extra clang arguments
  local output="$1" source="$2" header="$3"
  shift 3
  clang -Wall -Wextra -Werror -Wno-deprecated-declarations -include "$header" "$source" "$@" \
    -framework Security -framework CoreFoundation -lbsm -o "$output"
}
sign() { # certificate, identifier, file, then extra codesign arguments
  local certificate="$1" identifier="$2" file="$3"
  shift 3
  codesign --force --sign "$certificate" --keychain "$keychain" --timestamp=none --identifier "$identifier" "$@" "$file" 2>/dev/null
}
cdhash() { codesign --display --verbose=4 "$1" 2>&1 | sed -n 's/^CDHash=//p'; }
entitlement() { # name: a plist granting that one entitlement
  printf '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>%s</key><true/></dict></plist>\n' "$1" > "$probe/$1.plist"
  echo "$probe/$1.plist"
}

# Production sources compile as the frozen builds compile them.
for target in arm64-apple-macos11.0 x86_64-apple-macos10.13; do
  for source in "$v2_source" "$bridge_source"; do
    clang -target "$target" -Os -Wall -Wextra -Werror -Wno-deprecated-declarations "$source" \
      -framework Security -framework CoreFoundation -lbsm -o "$probe/frozen-build-check"
  done
done
rm "$probe/frozen-build-check"
echo 'Frozen-build compile check passed for helper v2 and the bridge (arm64, x86_64).'

# Helper v1 from its frozen source, accepting only the fixture bridge.
define "$probe/v1.h" LUNPORT_CLIENT_REQUIREMENT "identifier \"$bridge_id\" and certificate leaf = H\"$previous\"" \
  LUNPORT_CREDENTIAL_SERVICE "$old_service"
build "$probe/helper-v1" "$v1_source" "$probe/v1.h" -Os
sign "$previous" "$v1_id" "$probe/helper-v1" --options runtime
v1_hash="$(cdhash "$probe/helper-v1")"
# The same identity on different bytes, which the cdhash pin must reject.
build "$probe/helper-v1-rebuilt" "$v1_source" "$probe/v1.h" -O0
sign "$previous" "$v1_id" "$probe/helper-v1-rebuilt" --options runtime
[[ "$(cdhash "$probe/helper-v1-rebuilt")" != "$v1_hash" ]] || { echo 'Rebuilt helper must differ.' >&2; exit 1; }
# A helper v1 that accepts some other parent, to see the bridge report a refusal.
define "$probe/v1-refusing.h" LUNPORT_CLIENT_REQUIREMENT "identifier \"$app_id.validation.nobody\" and certificate leaf = H\"$previous\"" \
  LUNPORT_CREDENTIAL_SERVICE "$old_service"
build "$probe/helper-v1-refusing" "$v1_source" "$probe/v1-refusing.h" -Os
sign "$previous" "$v1_id" "$probe/helper-v1-refusing" --options runtime
cat > "$probe/forged.c" <<'EOF'
#include <unistd.h>
int main(void) { write(1, "LPKC0001", 8); char buffer[1]; return read(0, buffer, 1) > 0 ? 99 : 0; }
EOF
clang "$probe/forged.c" -o "$probe/forged-helper"

define "$probe/bridge.h" LUNPORT_CLIENT_REQUIREMENT "identifier \"$app_id\" and certificate leaf = H\"$project\"" \
  LUNPORT_HELPER_REQUIREMENT "identifier \"$v1_id\" and certificate leaf = H\"$previous\" and cdhash H\"$v1_hash\"" \
  LUNPORT_FIXTURE_HELPER_HOME "$HOME"
build "$probe/bridge" "$bridge_source" "$probe/bridge.h" -Os
cp "$probe/bridge" "$probe/bridge-unhardened"
cp "$probe/bridge" "$probe/bridge-debuggable"
sign "$previous" "$bridge_id" "$probe/bridge" --options runtime
bridge_hash="$(cdhash "$probe/bridge")"
# The bridge must refuse to run as a program a debugger could attach to.
sign "$previous" "$bridge_id" "$probe/bridge-unhardened"
sign "$previous" "$bridge_id" "$probe/bridge-debuggable" --options runtime --entitlements "$(entitlement com.apple.security.get-task-allow)"

define "$probe/v2.h" LUNPORT_CLIENT_REQUIREMENT "identifier \"$app_id\" and certificate leaf = H\"$project\"" \
  LUNPORT_CREDENTIAL_SERVICE "$new_service" LUNPORT_ADOPT_SERVICE "$old_service"
build "$probe/helper-v2" "$v2_source" "$probe/v2.h" -Os
sign "$project" "$v2_id" "$probe/helper-v2" --options runtime
v2_hash="$(cdhash "$probe/helper-v2")"
# A helper v2 built with one service on both sides, whose adopt must refuse to run.
define "$probe/v2-one-service.h" LUNPORT_CLIENT_REQUIREMENT "identifier \"$app_id\" and certificate leaf = H\"$project\"" \
  LUNPORT_CREDENTIAL_SERVICE "$new_service" LUNPORT_ADOPT_SERVICE "$new_service"
build "$probe/helper-v2-one-service" "$v2_source" "$probe/v2-one-service.h" -Os
sign "$project" "$v2_id" "$probe/helper-v2-one-service" --options runtime

client_for() { # output, pinned helper v2 code hash
  define "$1.h" \
    LUNPORT_HELPER_REQUIREMENT "identifier \"$v2_id\" and certificate leaf = H\"$project\" and cdhash H\"$2\"" \
    LUNPORT_BRIDGE_REQUIREMENT "identifier \"$bridge_id\" and certificate leaf = H\"$previous\" and cdhash H\"$bridge_hash\""
  build "$1" "${client_sources[0]}" "$1.h" "${client_sources[1]}"
}
client_for "$probe/client" "$v2_hash"
client_for "$probe/client-one-service" "$(cdhash "$probe/helper-v2-one-service")"
sign "$project" "$app_id" "$probe/client-one-service" --options runtime
cp "$probe/client" "$probe/client-unsigned"
sign "$project" "$app_id" "$probe/client" --options runtime
variants=(wrong-identifier wrong-certificate no-hardened-runtime ad-hoc get-task-allow
          disable-library-validation allow-dyld-environment-variables allow-unsigned-executable-memory)
for variant in "${variants[@]}"; do
  cp "$probe/client-unsigned" "$probe/client-$variant"
  case "$variant" in
    wrong-identifier) sign "$project" "$app_id.other" "$probe/client-$variant" --options runtime ;;
    wrong-certificate) sign "$previous" "$app_id" "$probe/client-$variant" --options runtime ;;
    no-hardened-runtime) sign "$project" "$app_id" "$probe/client-$variant" ;;
    ad-hoc) codesign --force --sign - --identifier "$app_id" --options runtime "$probe/client-$variant" 2>/dev/null ;;
    get-task-allow) sign "$project" "$app_id" "$probe/client-$variant" --options runtime \
         --entitlements "$(entitlement com.apple.security.get-task-allow)" ;;
    *) sign "$project" "$app_id" "$probe/client-$variant" --options runtime \
         --entitlements "$(entitlement "com.apple.security.cs.$variant")" ;;
  esac
done
echo "Fixtures built: helper v1 $v1_hash, bridge $bridge_hash, helper v2 $v2_hash."

client="$probe/client" bridge="$probe/bridge" v1="$probe/helper-v1" v2="$probe/helper-v2"

echo '--- Every process reaches only the disposable keychain'
"$client" fixture create-granted "$old_service" preflight "$v1"
"$client" bridge get "$bridge" "$v1" preflight
"$client" fixture delete "$old_service" preflight
"$client" fixture create-granted "$new_service" preflight "$v2"
"$client" helper get "$v2" preflight
"$client" fixture delete "$new_service" preflight

echo '--- The allowed app gets items through the bridge from helper v1'
"$client" bridge set "$bridge" "$v1" chain
"$client" bridge get "$bridge" "$v1" chain
"$client" fixture absent "$new_service" chain
"$client" bridge delete "$bridge" "$v1" chain
"$client" bridge missing "$bridge" "$v1" chain
"$client" bridge delete "$bridge" "$v1" chain
"$client" fixture create "$old_service" not-for-helper-v1
"$client" bridge denied "$bridge" "$v1" not-for-helper-v1
"$client" fixture verify "$old_service" not-for-helper-v1
"$client" fixture delete "$old_service" not-for-helper-v1

echo '--- The bridge refuses every other parent, and helper v1 refuses the app directly'
"$client" bridge set "$bridge" "$v1" refusals
for variant in "${variants[@]}"; do
  printf 'client %s: ' "$variant"
  "$probe/client-$variant" bridge rejected "$bridge" "$v1" refusals
done
printf 'helper v1 asked by the app directly, not through the bridge: '
"$client" helper rejected "$v1" refusals
"$client" bridge get "$bridge" "$v1" refusals
"$client" bridge delete "$bridge" "$v1" refusals

echo '--- The bridge refuses to run without hardened runtime or with get-task-allow'
printf 'bridge without hardened runtime: '
"$client" bridge rejected "$probe/bridge-unhardened" "$v1" chain
printf 'bridge with get-task-allow: '
"$client" bridge rejected "$probe/bridge-debuggable" "$v1" chain

echo '--- The bridge relays only to the pinned helper v1'
printf 'forged helper: '
"$client" bridge helper-unpinned "$bridge" "$probe/forged-helper" chain
printf 'rebuilt helper: '
"$client" bridge helper-unpinned "$bridge" "$probe/helper-v1-rebuilt" chain
"$client" bridge helper-refuses "$bridge" "$probe/helper-v1-refusing" chain
"$client" bridge helper-unavailable "$bridge" "$probe/no-such-helper" chain
for malformed in bad-magic bad-helper-magic bad-op oversized relative-path trailing truncated; do
  "$client" bridge "$malformed" "$bridge" "$v1" chain
done

echo '--- Helper v2 serves the app and refuses every other parent'
"$client" helper set "$v2" current
"$client" helper get "$v2" current
"$client" helper contains "$v2" current
# Helper v2 owns what it saves: its access names helper v2 alone, and no other program may read it.
"$client" fixture owner "$new_service" current "$v2"
"$client" fixture denied "$new_service" current
"$client" helper set-other "$v2" current
"$client" helper get-other "$v2" current
for variant in "${variants[@]}"; do
  printf 'client %s: ' "$variant"
  "$probe/client-$variant" helper rejected "$v2" current
done
for malformed in bad-magic bad-op adopt-with-data oversized truncated; do
  "$client" helper "$malformed" "$v2" current
done
"$client" helper delete "$v2" current
"$client" helper missing "$v2" current
"$client" helper delete "$v2" current

echo '--- Adopt moves an item it may read; every other outcome leaves the old item as it was'
# Refused: a helper-v1 item that helper v2 may not read without asking.
"$client" bridge set "$bridge" "$v1" adopt-refused
"$client" helper adopt-refused "$v2" adopt-refused
"$client" helper missing "$v2" adopt-refused
"$client" bridge get "$bridge" "$v1" adopt-refused
"$client" bridge delete "$bridge" "$v1" adopt-refused
# Moved: an item the user allowed helper v2 to read. The moved item belongs to helper v2.
"$client" fixture create-granted "$old_service" adopt-moved "$v2"
"$client" helper adopt "$v2" adopt-moved
"$client" helper get "$v2" adopt-moved
"$client" fixture owner "$new_service" adopt-moved "$v2"
"$client" fixture denied "$new_service" adopt-moved
"$client" fixture absent "$old_service" adopt-moved
"$client" helper adopt-missing "$v2" adopt-moved
"$client" helper delete "$v2" adopt-moved
"$client" helper adopt-missing "$v2" adopt-never-saved
# Repeated after an earlier request already made an identical copy: the move completes.
"$client" fixture create-granted "$old_service" adopt-repeated "$v2"
"$client" helper set "$v2" adopt-repeated
"$client" helper adopt "$v2" adopt-repeated
"$client" fixture absent "$old_service" adopt-repeated
"$client" helper get "$v2" adopt-repeated
"$client" helper delete "$v2" adopt-repeated
# Conflict: different bytes are already saved under the new service; both stay as they are.
"$client" fixture create-granted "$old_service" adopt-conflict "$v2"
"$client" helper set-other "$v2" adopt-conflict
"$client" helper adopt-conflict "$v2" adopt-conflict
"$client" helper get-other "$v2" adopt-conflict
"$client" fixture verify "$old_service" adopt-conflict
"$client" helper delete "$v2" adopt-conflict
"$client" fixture delete "$old_service" adopt-conflict
# Too large: an old item over 1 MiB is not moved.
"$client" fixture create-granted-oversized "$old_service" adopt-oversized "$v2"
"$client" helper adopt-oversized "$v2" adopt-oversized
"$client" helper missing "$v2" adopt-oversized
"$client" fixture present "$old_service" adopt-oversized
"$client" fixture delete "$old_service" adopt-oversized
# One service on both sides: adopt refuses before touching anything, so the only copy survives.
printf 'helper v2 built with one service: '
"$probe/client-one-service" helper set "$probe/helper-v2-one-service" one-service
printf 'helper v2 built with one service: '
"$probe/client-one-service" helper adopt-one-service "$probe/helper-v2-one-service" one-service
printf 'helper v2 built with one service: '
"$probe/client-one-service" helper get "$probe/helper-v2-one-service" one-service
printf 'helper v2 built with one service: '
"$probe/client-one-service" helper delete "$probe/helper-v2-one-service" one-service

remove_login_fixtures() {
  local entry owner service account
  security default-keychain -d user -s "$login" >/dev/null 2>&1 || true
  security list-keychains -d user -s "$login" >/dev/null 2>&1 || true
  for entry in "${login_fixtures[@]}"; do
    IFS='|' read -r owner service account <<< "$entry"
    if [[ "$owner" == helper ]]; then LUNPORT_VALIDATION_KEYCHAIN="$login" "$client" helper delete "$v2" "$account" >/dev/null 2>&1 || true
    else LUNPORT_VALIDATION_KEYCHAIN="$login" "$client" fixture delete "$service" "$account" >/dev/null 2>&1 || true; fi
  done
  login_fixtures=()
  security default-keychain -d user -s "$keychain" >/dev/null 2>&1 || true
  security list-keychains -d user -s "$keychain" >/dev/null 2>&1 || true
}
partition_owner() { # partition probe output, expected code hash
  python3 - "$1" "$2" <<'PY'
import pathlib, plistlib, sys
text = pathlib.Path(sys.argv[1]).read_text()
assert 'partition ACL count: 1' in text, 'the item must carry a partition list'
encoded = next(line.removeprefix('partition: ') for line in text.splitlines() if line.startswith('partition: '))
partitions = plistlib.loads(bytes.fromhex(encoded))['Partitions']
assert 'cdhash:' + sys.argv[2] in partitions, f'unexpected partition owner {partitions}'
print('partition owner cdhash:' + sys.argv[2] + ': passed')
PY
}
if [[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_OS:-} == macOS ]]; then
  echo '--- Partition owner in the disposable runner login keychain'
  login="$(sed -n 's/^ *"\(.*\)"$/\1/p' <<< "$real_default")"
  [[ -f "$login" ]] || { echo 'The runner has no default keychain.' >&2; exit 1; }
  clang -Wno-deprecated-declarations "$keychain_probe_source" -framework Security -framework CoreFoundation -o "$probe/keychain-probe"
  run="${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}"
  login_fixtures=("helper|$new_service|partition-$run" "client|$old_service|partition-old-$run" "helper|$new_service|partition-old-$run")
  # Only the temporary HOME's preferences point at the runner's login keychain.
  security default-keychain -d user -s "$login"
  security list-keychains -d user -s "$login"
  export LUNPORT_VALIDATION_KEYCHAIN="$login"
  "$client" helper set "$v2" "partition-$run"
  "$probe/keychain-probe" partition "$login" "$new_service" "partition-$run" > "$probe/partition.txt"
  partition_owner "$probe/partition.txt" "$v2_hash"
  # A partition-protected item of another program: adopt is refused and changes nothing.
  "$client" fixture create "$old_service" "partition-old-$run"
  "$probe/keychain-probe" partition "$login" "$old_service" "partition-old-$run" > "$probe/partition-old.txt"
  partition_owner "$probe/partition-old.txt" "$(cdhash "$client")"
  "$client" helper adopt-refused "$v2" "partition-old-$run"
  "$client" helper missing "$v2" "partition-old-$run"
  "$client" fixture verify "$old_service" "partition-old-$run"
  "$probe/keychain-probe" partition "$login" "$old_service" "partition-old-$run" > "$probe/partition-old.txt"
  partition_owner "$probe/partition-old.txt" "$(cdhash "$client")"
  remove_login_fixtures
  export LUNPORT_VALIDATION_KEYCHAIN="$keychain"
else
  echo '--- Partition owner: skipped here. A new keychain gives items no partition list, so this'
  echo '    check runs only on a disposable CI runner, in its login keychain.'
fi

echo 'Bridge chain, parent and helper refusals, helper v2 and adopt passed in a disposable keychain.'
