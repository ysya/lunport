#!/bin/sh
set -eu
: "${SECURITY_INSTALLATION:?set a stable 32-character installation ID}"
case "$SECURITY_INSTALLATION" in *[!0-9a-f]*|'') echo "Invalid installation ID" >&2; exit 64;; esac
[ "${#SECURITY_INSTALLATION}" -eq 32 ] || { echo "Invalid installation ID" >&2; exit 64; }
umask 077
sed "s/__INSTALLATION__/$SECURITY_INSTALLATION/g" /relay/services.capnp.in > /tmp/services.capnp
case "${1:-serve}" in
  serve) exec flock --nonblock /security-data/.runtime.lock /usr/local/bin/workerd serve -I / /relay/runtime.capnp ;;
  inspect|provision-new|raise-floor|bind-authority)
    if [ "$1" = bind-authority ]; then
      receipt=/security-data/central-authority-import.json
      [ -f "$receipt" ] && [ ! -L "$receipt" ] && [ "$(stat -c %h "$receipt")" -eq 1 ] && [ "$(wc -c < "$receipt")" -le 4194304 ] || { echo "Verified authority import receipt required" >&2; exit 65; }
      cp "$receipt" /tmp/authority-import.json
    else
      printf 'null' > /tmp/authority-import.json
    fi
    SELFHOST_CONTROL_MODE=$1; export SELFHOST_CONTROL_MODE
    exec flock --nonblock /security-data/.runtime.lock /usr/local/bin/workerd test -I / /relay/control.capnp ;;
  *) echo "Use serve, inspect, provision-new, raise-floor, or bind-authority" >&2; exit 64 ;;
esac
