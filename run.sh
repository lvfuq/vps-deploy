#!/usr/bin/env bash
set -Eeuo pipefail

RAW_BASE="https://raw.githubusercontent.com/lvfuq/vps-deploy/main"

[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "[run][ERROR] 请用 root 运行（sudo -i）" >&2; exit 1; }

if ! command -v curl >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y --no-install-recommends curl ca-certificates >/dev/null 2>&1 || true
fi

bash <(curl -fsSL "${RAW_BASE}/deploy.sh")

unset GH_TOKEN || true
