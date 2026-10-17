#!/bin/bash
# Generate a reviewable candidate ONCE. Normal release builds never run this.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_OS:-} == macOS ]] || exit 1
: "${APPLE_SIGNING_IDENTITY:?Prepare the pinned signing identity first}"
repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
output="${RUNNER_TEMP:?}/lunport-credential-helper-v1-candidate"
[[ ! -e "$output" ]] || exit 1
mkdir -m 700 "$output"
source_file="$repo_dir/src-tauri/signing/credential-helper-v1.c"
for architecture in arm64 x86_64; do
  minimum=11.0
  [[ "$architecture" != x86_64 ]] || minimum=10.13
  clang -target "$architecture-apple-macos$minimum" -Os -Wall -Wextra -Werror -Wno-deprecated-declarations \
    "$source_file" -framework Security -framework CoreFoundation -lbsm -o "$output/$architecture"
done
lipo -create "$output/arm64" "$output/x86_64" -output "$output/credential-helper-v1.bin"
rm "$output/arm64" "$output/x86_64"
codesign --force --sign "$APPLE_SIGNING_IDENTITY" --options runtime --timestamp=none \
  --identifier org.homelab.sshelter.credential-helper.v1 "$output/credential-helper-v1.bin"
codesign --verify --strict --all-architectures "$output/credential-helper-v1.bin"
cp "$source_file" "$output/credential-helper-v1.c"
python3 - "$output" "$repo_dir" <<'PY'
import hashlib, json, pathlib, subprocess, sys
output, repo = map(pathlib.Path, sys.argv[1:])
manifest = {"protocol":1,"artifact_sha256":hashlib.sha256((output/'credential-helper-v1.bin').read_bytes()).hexdigest(),
            "source_sha256":hashlib.sha256((output/'credential-helper-v1.c').read_bytes()).hexdigest(),
            "source_commit":subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(),
            "identifier":"org.homelab.sshelter.credential-helper.v1"}
(output/'credential-helper-v1.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps(manifest,indent=2))
PY
