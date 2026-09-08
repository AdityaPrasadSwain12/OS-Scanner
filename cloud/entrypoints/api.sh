#!/bin/sh
set -eu

exec python -m uvicorn cloud_service.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --no-server-header \
  --proxy-headers \
  --forwarded-allow-ips="${SCANNER_TRUSTED_PROXY_IPS:-127.0.0.1}"

