#!/bin/bash
# Checks one exact frozen credential helper the way the app uses it: two differently built clients, signed with the project
# certificate under the identifier the helper accepts, set, read, replace, delete and miss one disposable item in the runner's
# login keychain without authorization UI. Disposable macOS CI runner only.
# Usage: validate-macos-frozen-helper.sh v1|v2 <directory with credential-helper-<version>.{bin,c,json}>
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_OS:-} == macOS ]] || exit 1
: "${APPLE_SIGNING_IDENTITY:?Prepare the pinned signing identity first}"
repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
version="${1:-}"
# A value of the JSON text given first, by the keys after it.
json_value() { python3 -c 'import functools, json, sys; print(functools.reduce(lambda value, key: value[key], sys.argv[2:], json.loads(sys.argv[1])))' "$@"; }
# The clients are signed as the production app the helper serves, and name the service it keeps its items under: for helper v1 the
# identity of releases before 2.0 (scripts/legacy-identity.json), for helper v2 the current one (scripts/identity.mjs).
case "$version" in
  # Helper v1 accepts only a parent signed as the app was before 2.0.0, with the certificate of that time, which only the bridge is
  # signed with now: with the current project certificate this check can pass only for helper v2.
  v1) magic=LPKC0001 certificate="$repo_dir/src-tauri/signing/legacy/macos-project.pem"
      identity="$(cat "$repo_dir/scripts/legacy-identity.json")" ;;
  v2) magic=LPKC0002 certificate="$repo_dir/src-tauri/signing/macos-project.pem"
      identity="$(node "$repo_dir/scripts/identity.mjs")" ;;
  *) echo 'Usage: validate-macos-frozen-helper.sh v1|v2 <directory>' >&2; exit 64 ;;
esac
client_identifier="$(json_value "$identity" production appId)"
service="$(json_value "$identity" production credentialService)"
artifact="${2:?Frozen artifact directory required}"
python3 "$repo_dir/scripts/verify-macos-credential-helper.py" --version "$version" --directory "$artifact"
leaf="$(/usr/bin/openssl x509 -in "$certificate" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':' | tr '[:upper:]' '[:lower:]')"
probe="$(mktemp -d "${RUNNER_TEMP}/lunport-frozen-client.XXXXXX")"
helper="$probe/Lunport Credential Helper"
cp "$artifact/credential-helper-$version.bin" "$helper"
chmod 700 "$helper"
account="lunport-ci-helper-frozen-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
cleanup() {
  if [[ -x "$probe/client-1" ]]; then "$probe/client-1" delete "$helper" "$account" || true; fi
  rm -rf "$probe"
}
trap cleanup EXIT
# The requirement the app pins: the identifier the verifier checked, the certificate leaf and both architectures' code hashes.
python3 - "$artifact/credential-helper-$version.json" "$leaf" "$magic" "$probe/config.h" "$service" <<'PY'
import json, pathlib, sys
manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
hashes = [manifest['cdhashes'][arch] for arch in ('arm64', 'x86_64')]
required = f'identifier "{manifest["identifier"]}" and certificate leaf = H"{sys.argv[2]}" and (' + ' or '.join(f'cdhash H"{value}"' for value in hashes) + ')'
pathlib.Path(sys.argv[4]).write_text(f'#define LUNPORT_HELPER_REQUIREMENT {json.dumps(required)}\n#define LUNPORT_HELPER_MAGIC {json.dumps(sys.argv[3])}\n'
                                     f'#define LUNPORT_CREDENTIAL_SERVICE {json.dumps(sys.argv[5])}\n')
PY
for client in 1 2; do
  clang -Wall -Wextra -Werror -Wno-deprecated-declarations "-DCLIENT_VERSION=\"$client\"" -include "$probe/config.h" \
    "$repo_dir/scripts/macos-helper-client.c" "$repo_dir/src-tauri/src/macos_credential_peer.c" \
    -framework Security -framework CoreFoundation -lbsm -o "$probe/client-$client"
  codesign --force --sign "$APPLE_SIGNING_IDENTITY" --options runtime --timestamp=none \
    --identifier "$client_identifier" "$probe/client-$client"
done
"$probe/client-1" set "$helper" "$account"
"$probe/client-2" get "$helper" "$account"
"$probe/client-2" replace "$helper" "$account"
"$probe/client-1" get "$helper" "$account"
"$probe/client-2" delete "$helper" "$account"
"$probe/client-1" missing "$helper" "$account"
echo "Exact frozen production helper $version accepted both client builds without authentication UI."
