#!/bin/bash
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_OS:-} == macOS ]] || exit 1
: "${APPLE_SIGNING_IDENTITY:?Prepare the pinned signing identity first}"
repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
artifact="${1:?Frozen artifact directory required}"
python3 "$repo_dir/scripts/verify-macos-credential-helper.py" "$artifact"
probe="$(mktemp -d "${RUNNER_TEMP}/lunport-frozen-client.XXXXXX")"
helper="$probe/Lunport Credential Helper"
cp "$artifact/credential-helper-v1.bin" "$helper"
chmod 700 "$helper"
account="lunport-ci-helper-frozen-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
cleanup() {
  if [[ -x "$probe/client-1" ]]; then "$probe/client-1" delete "$helper" "$account" || true; fi
  rm -rf "$probe"
}
trap cleanup EXIT
python3 - "$artifact/credential-helper-v1.json" "$probe/config.h" <<'PY'
import json, pathlib, sys
manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
hashes = list(manifest['cdhashes'].values())
required = 'identifier "org.homelab.sshelter.credential-helper.v1" and certificate leaf = H"a346b47b8dccb4faeac8aec1ea997535809aeec9" and (' + ' or '.join('cdhash H"'+value+'"' for value in hashes) + ')'
pathlib.Path(sys.argv[2]).write_text('#define LUNPORT_HELPER_REQUIREMENT '+json.dumps(required)+'\n#define LUNPORT_CREDENTIAL_SERVICE "SSHelter"\n')
PY
for version in 1 2; do
  clang -Wall -Wextra -Werror -Wno-deprecated-declarations "-DCLIENT_VERSION=\"$version\"" -include "$probe/config.h" \
    "$repo_dir/scripts/macos-helper-client.c" "$repo_dir/src-tauri/src/macos_credential_peer.c" \
    -framework Security -framework CoreFoundation -lbsm -o "$probe/client-$version"
  codesign --force --sign "$APPLE_SIGNING_IDENTITY" --options runtime --timestamp=none \
    --identifier org.homelab.sshelter "$probe/client-$version"
done
"$probe/client-1" set "$helper" "$account"
"$probe/client-2" get "$helper" "$account"
"$probe/client-2" replace "$helper" "$account"
"$probe/client-1" get "$helper" "$account"
"$probe/client-2" delete "$helper" "$account"
"$probe/client-1" missing "$helper" "$account"
echo 'Exact frozen production helper accepted both client builds without authentication UI.'
