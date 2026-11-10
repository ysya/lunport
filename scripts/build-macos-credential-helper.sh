#!/bin/bash
# Generate a reviewable candidate ONCE. Normal release builds never run this.
# Usage: build-macos-credential-helper.sh [v2]  (v2 when omitted)
set -euo pipefail
version="${1:-v2}"
case "$version" in
  v2) ;;
  # Helper v1 is frozen and signed with the certificate releases before 2.0.0 used, which this repository no longer holds: a v1 built
  # here could never pass its verification.
  v1) echo 'Helper v1 is frozen with the previous project certificate and cannot be built here; only helper v2 can.' >&2; exit 64 ;;
  *) echo 'Usage: build-macos-credential-helper.sh [v2]' >&2; exit 64 ;;
esac
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_OS:-} == macOS ]] || exit 1
: "${APPLE_SIGNING_IDENTITY:?Prepare the pinned signing identity first}"
repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
protocol=2
helper_dir="$repo_dir/src-tauri/signing"
# The identifier the app pins helper v2 to (src-tauri/src/identity.rs, through scripts/identity.mjs).
identifier="$(node "$repo_dir/scripts/identity.mjs" | python3 -c 'import json, sys; print(json.load(sys.stdin)["helperV2"]["identifier"])')"
name="credential-helper-$version"
output="${RUNNER_TEMP:?}/lunport-$name-candidate"
[[ ! -e "$output" ]] || exit 1
mkdir -m 700 "$output"
source_file="$helper_dir/$name.c"
for architecture in arm64 x86_64; do
  minimum=11.0
  [[ "$architecture" != x86_64 ]] || minimum=10.13
  clang -target "$architecture-apple-macos$minimum" -Os -Wall -Wextra -Werror -Wno-deprecated-declarations \
    "$source_file" -framework Security -framework CoreFoundation -lbsm -o "$output/$architecture"
done
lipo -create "$output/arm64" "$output/x86_64" -output "$output/$name.bin"
rm "$output/arm64" "$output/x86_64"
codesign --force --sign "$APPLE_SIGNING_IDENTITY" --options runtime --timestamp=none \
  --identifier "$identifier" "$output/$name.bin"
codesign --verify --strict --all-architectures "$output/$name.bin"
cp "$source_file" "$output/$name.c"
python3 - "$output" "$repo_dir" "$name" "$protocol" "$identifier" <<'PY'
import hashlib, json, pathlib, subprocess, sys
output, repo = map(pathlib.Path, sys.argv[1:3])
name, protocol, identifier = sys.argv[3], int(sys.argv[4]), sys.argv[5]
manifest = {"protocol":protocol,"artifact_sha256":hashlib.sha256((output/f'{name}.bin').read_bytes()).hexdigest(),
            "source_sha256":hashlib.sha256((output/f'{name}.c').read_bytes()).hexdigest(),
            "source_commit":subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(),
            "identifier":identifier}
manifest['cdhashes'] = {}
for arch in ['arm64','x86_64']:
    details = subprocess.check_output(['codesign','--display','--verbose=4','--arch',arch,str(output/f'{name}.bin')],stderr=subprocess.STDOUT,text=True)
    manifest['cdhashes'][arch] = next(line.removeprefix('CDHash=') for line in details.splitlines() if line.startswith('CDHash='))
(output/f'{name}.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(manifest,indent=2))
PY
python3 "$repo_dir/scripts/verify-macos-credential-helper.py" --directory "$output" --version "$version"
