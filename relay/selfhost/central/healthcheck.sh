#!/bin/sh
set -eu
: "${SELFHOST_PROXY_KEY:?proxy capability missing}"
case "${CENTRAL_ORIGIN:-}" in https://*) proxy_host=${CENTRAL_ORIGIN#https://} ;; *) exit 1 ;; esac
exec curl --fail --silent --show-error --max-time 5 --output /dev/null \
  --header "Host: $proxy_host" --header "X-Forwarded-Proto: https" \
  --header "X-Lunport-Proxy-Key: $SELFHOST_PROXY_KEY" http://127.0.0.1:8080/legacy/v1/info
