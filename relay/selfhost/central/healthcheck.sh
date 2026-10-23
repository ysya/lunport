#!/bin/sh
set -eu
: "${SELFHOST_PROXY_KEY:?proxy capability missing}"
case "${CENTRAL_ORIGIN:-}" in https://*) proxy_host=${CENTRAL_ORIGIN#https://} ;; *) exit 1 ;; esac
code=$(curl --silent --show-error --max-time 5 --output /dev/null --write-out '%{http_code}' \
  --header "Host: $proxy_host" --header "X-Forwarded-Proto: https" \
  --header "X-Lunport-Proxy-Key: $SELFHOST_PROXY_KEY" http://127.0.0.1:8080/v1/info)
case "${CENTRAL_ENABLED:-0}:$code" in
  1:200|0:503) exit 0 ;;
  *) exit 1 ;;
esac
