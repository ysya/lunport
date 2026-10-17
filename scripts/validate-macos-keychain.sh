#!/bin/bash
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_OS:-} == macOS ]] || { echo 'Disposable macOS CI runner required.' >&2; exit 1; }
umask 077
repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
probe_dir="$(mktemp -d "${RUNNER_TEMP}/lunport-keychain.XXXXXX")"
keychain="$probe_dir/probe.keychain-db"
keychain_password="$(/usr/bin/openssl rand -hex 24)"
echo "::add-mask::$keychain_password"
original_default="$(security default-keychain -d user | sed 's/^ *"//; s/"$//')"
security list-keychains -d user > "$probe_dir/search-list.txt"
cleanup() {
  security default-keychain -d user -s "$original_default" || true
  local previous=()
  while IFS= read -r line; do line="${line#*\"}"; line="${line%\"*}"; previous+=("$line"); done < "$probe_dir/search-list.txt"
  security list-keychains -d user -s "${previous[@]}" || true
  security delete-keychain "$keychain" >/dev/null 2>&1 || true
  rm -rf "$probe_dir"
}
trap cleanup EXIT
cat > "$probe_dir/certificate.conf" <<'EOF'
[req]
distinguished_name = name
x509_extensions = signing
prompt = no
[name]
CN = Lunport Disposable Signing Test
[signing]
basicConstraints = critical,CA:TRUE
keyUsage = critical,digitalSignature,keyCertSign
extendedKeyUsage = codeSigning
subjectKeyIdentifier = hash
EOF
/usr/bin/openssl req -new -newkey rsa:2048 -x509 -nodes -sha256 -days 2 \
  -config "$probe_dir/certificate.conf" -keyout "$probe_dir/key.pem" -out "$probe_dir/certificate.pem" 2>/dev/null
/usr/bin/openssl pkcs12 -export -inkey "$probe_dir/key.pem" -in "$probe_dir/certificate.pem" \
  -out "$probe_dir/identity.p12" -passout "pass:$keychain_password"
security create-keychain -p "$keychain_password" "$keychain"
security unlock-keychain -p "$keychain_password" "$keychain"
security set-keychain-settings -lut 3600 "$keychain"
security import "$probe_dir/identity.p12" -k "$keychain" -P "$keychain_password" -T /usr/bin/codesign
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$keychain_password" "$keychain" >/dev/null
identity="$(/usr/bin/openssl x509 -in "$probe_dir/certificate.pem" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':')"
for version in 1 2; do
  clang -Wno-deprecated-declarations "-DPROBE_VERSION=\"$version\"" "$repo_dir/scripts/macos-keychain-probe.c" \
    -framework Security -framework CoreFoundation -o "$probe_dir/version-$version"
  codesign --force --sign "$identity" --keychain "$keychain" --timestamp=none \
    --identifier org.homelab.sshelter "$probe_dir/version-$version"
  codesign --verify --strict "$probe_dir/version-$version"
  codesign --display --requirements - "$probe_dir/version-$version" > "$probe_dir/requirement-$version.txt" 2>/dev/null
done
cmp "$probe_dir/requirement-1.txt" "$probe_dir/requirement-2.txt"
grep -F 'identifier "org.homelab.sshelter"' "$probe_dir/requirement-1.txt"
if grep -E 'cdhash|anchor trusted' "$probe_dir/requirement-1.txt"; then echo 'Unstable or system-trust-dependent requirement.' >&2; exit 1; fi
if cmp -s "$probe_dir/version-1" "$probe_dir/version-2"; then echo 'Probe builds must differ.' >&2; exit 1; fi
service='SSHelter Development'
account="lunport-ci-keychain-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
cp "$probe_dir/version-1" "$probe_dir/current"
"$probe_dir/current" write "$keychain" "$service" "$account"
cp "$probe_dir/version-2" "$probe_dir/current"
"$probe_dir/current" read "$keychain" "$service" "$account"
cp "$probe_dir/version-2" "$probe_dir/unrelated"
codesign --force --sign - --identifier org.homelab.sshelter "$probe_dir/unrelated"
"$probe_dir/unrelated" denied "$keychain" "$service" "$account"
if [[ ${1:-} == --with-rust ]]; then
  security default-keychain -d user -s "$keychain"
  SSHELTER_CI_KEYCHAIN_PROBE_ACCOUNT="$account" cargo test --locked --manifest-path "$repo_dir/src-tauri/Cargo.toml" --lib -- \
    --ignored --exact secrets::tests::native_metadata_probe --nocapture
fi
echo 'Stable certificate: changed executable retained access; unrelated signer denied; no user trust settings changed.'
