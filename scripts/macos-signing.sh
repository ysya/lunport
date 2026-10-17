#!/bin/bash
# CI-only signing keychain. Never installs a certificate in the user's trust store.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_OS:-} == macOS ]] || { echo 'Disposable macOS CI runner required.' >&2; exit 1; }
umask 077
repo_dir="$(cd "$(dirname "$0")/.." && pwd)"
state="${RUNNER_TEMP:?}/lunport-project-signing"
public_certificate="$repo_dir/src-tauri/signing/macos-project.pem"
keychain="$state/signing.keychain-db"

fingerprint() {
  /usr/bin/openssl x509 -in "$1" -inform "${2:-PEM}" -outform DER | shasum -a 256 | awk '{print $1}'
}

cleanup() {
  if [[ -f "$state/search-list.txt" ]]; then
    local previous=() line
    while IFS= read -r line; do line="${line#*\"}"; line="${line%\"*}"; previous+=("$line"); done < "$state/search-list.txt"
    security list-keychains -d user -s "${previous[@]}"
  fi
  if [[ -d "$state" ]]; then
    security delete-keychain "$keychain" >/dev/null 2>&1 || true
    rm -rf "$state"
  fi
}

verify() {
  local app="$1" scratch identifier requirement expected actual leaf_sha1 architecture
  [[ -d "$app/Contents" ]] || { echo 'App bundle is missing.' >&2; return 1; }
  identifier=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Contents/Info.plist")
  [[ "$identifier" == org.homelab.sshelter ]] || { echo 'Unexpected production bundle identifier.' >&2; return 1; }
  codesign --verify --deep --strict --all-architectures "$app"
  scratch="$(mktemp -d "${RUNNER_TEMP}/lunport-signature.XXXXXX")"
  expected="$(fingerprint "$public_certificate")"
  leaf_sha1="$(/usr/bin/openssl x509 -in "$public_certificate" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':' | tr '[:upper:]' '[:lower:]')"
  local executable
  executable=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$app/Contents/Info.plist")
  lipo "$app/Contents/MacOS/$executable" -verify_arch x86_64 arm64
  for architecture in x86_64 arm64; do
    codesign --display --arch "$architecture" --extract-certificates="$scratch/$architecture-" "$app"
    actual="$(fingerprint "$scratch/$architecture-0" DER)"
    [[ "$actual" == "$expected" ]] || { rm -rf "$scratch"; echo 'App signing certificate differs from the repository pin.' >&2; return 1; }
    requirement="$(codesign --display --arch "$architecture" --requirements - "$app" 2>/dev/null)"
    # Bind the identifier and leaf certificate, without a per-build code hash or trust-store requirement.
    [[ "$requirement" == "designated => identifier \"org.homelab.sshelter\" and certificate leaf = H\"$leaf_sha1\"" ]] || {
      rm -rf "$scratch"; echo 'App designated requirement is not the pinned stable identity.' >&2; return 1;
    }
  done
  rm -rf "$scratch"
  echo "Verified universal App identity: $expected"
}

case "${1:-}" in
  prepare)
    : "${LUNPORT_MACOS_CERTIFICATE:?Fixed macOS signing certificate is required}"
    : "${LUNPORT_MACOS_CERTIFICATE_PASSWORD:?Fixed macOS signing password is required}"
    [[ ! -e "$state" ]] || { echo 'Signing state already exists; refusing to replace it.' >&2; exit 1; }
    mkdir "$state"
    trap cleanup EXIT
    security list-keychains -d user > "$state/search-list.txt"
    printf '%s' "$LUNPORT_MACOS_CERTIFICATE" | base64 -D > "$state/identity.p12"
    /usr/bin/openssl pkcs12 -in "$state/identity.p12" -nokeys \
      -passin env:LUNPORT_MACOS_CERTIFICATE_PASSWORD -out "$state/imported.pem"
    [[ "$(fingerprint "$state/imported.pem")" == "$(fingerprint "$public_certificate")" ]] || {
      echo 'Signing secret does not match the pinned public certificate.' >&2; exit 1;
    }
    /usr/bin/openssl x509 -in "$public_certificate" -checkend 2592000 -noout
    password="$(/usr/bin/openssl rand -hex 24)"
    echo "::add-mask::$password"
    security create-keychain -p "$password" "$keychain"
    security unlock-keychain -p "$password" "$keychain"
    security set-keychain-settings -lut 21600 "$keychain"
    security import "$state/identity.p12" -k "$keychain" -P "$LUNPORT_MACOS_CERTIFICATE_PASSWORD" -T /usr/bin/codesign
    security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$password" "$keychain" >/dev/null
    previous=()
    while IFS= read -r line; do line="${line#*\"}"; line="${line%\"*}"; previous+=("$line"); done < "$state/search-list.txt"
    security list-keychains -d user -s "$keychain" "${previous[@]}"
    identity="$(/usr/bin/openssl x509 -in "$public_certificate" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':')"
    echo "APPLE_SIGNING_IDENTITY=$identity" >> "$GITHUB_ENV"
    rm "$state/identity.p12" "$state/imported.pem"
    trap - EXIT
    echo 'Pinned project signing identity prepared; no system trust setting was changed.'
    ;;
  verify) verify "${2:?App bundle path required}" ;;
  cleanup) cleanup ;;
  *) echo 'Usage: macos-signing.sh prepare | verify <App> | cleanup' >&2; exit 64 ;;
esac
