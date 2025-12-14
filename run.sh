#!/usr/bin/env bash
set -euo pipefail

DEPLOY_URL="https://raw.githubusercontent.com/lvfuq/vps-deploy/main/deploy.sh"
RUN_LOG="/root/run.log"
SUB_TXT="/root/sub.txt"
SUB_B64="/root/sub.b64"
SHARE_LINKS="/root/share_links.txt"

ok(){ printf "PASS  %s\n" "$*"; }
bad(){ printf "FAIL  %s\n" "$*"; }
info(){ printf "INFO  %s\n" "$*"; }

is_listen_tcp(){ ss -lnt 2>/dev/null | awk '{print $4}' | grep -Eq "(:|\\])${1}$"; }
is_listen_udp(){ ss -lnu 2>/dev/null | awk '{print $4}' | grep -Eq "(:|\\])${1}$"; }

if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR: run as root (sudo -i)" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update -y >/dev/null 2>&1 || true
apt-get install -y curl ca-certificates jq iproute2 coreutils >/dev/null 2>&1 || true

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
curl -fsSL "$DEPLOY_URL" -o "$tmpdir/deploy.sh"
chmod +x "$tmpdir/deploy.sh"

: >"$RUN_LOG" || true
(
  : "${GIST_ID:=}"
  : "${GH_TOKEN:=}"
  export GIST_ID GH_TOKEN
  bash "$tmpdir/deploy.sh"
) >"$RUN_LOG" 2>&1 || {
  echo "ERROR: deploy.sh failed. Last 120 lines:" >&2
  tail -n 120 "$RUN_LOG" >&2 || true
  exit 2
}

echo "========== SELF-TEST =========="

if systemctl is-active --quiet sing-box; then ok "sing-box running"; else bad "sing-box NOT running"; fi

CFG="/etc/sing-box/config.json"
if [[ -f "$CFG" ]]; then
  ok "found $CFG"
  mapfile -t inbounds < <(jq -r '.inbounds[] | "\(.type) \(.listen_port)"' "$CFG" 2>/dev/null || true)
  for item in "${inbounds[@]}"; do
    t="$(awk '{print $1}' <<<"$item")"
    p="$(awk '{print $2}' <<<"$item")"
    [[ -z "$p" ]] && continue
    case "$t" in
      hysteria2|tuic)  is_listen_udp "$p" && ok "UDP ${p} (${t})" || bad "UDP ${p} (${t})" ;;
      shadowsocks)     is_listen_tcp "$p" && ok "TCP ${p} (ss)" || bad "TCP ${p} (ss)"
                      is_listen_udp "$p" && ok "UDP ${p} (ss)" || bad "UDP ${p} (ss)" ;;
      *)               is_listen_tcp "$p" && ok "TCP ${p} (${t})" || bad "TCP ${p} (${t})" ;;
    esac
  done
else
  bad "missing $CFG"
fi

ip_now="$(curl -fsSL https://api.ipify.org 2>/dev/null || true)"
[[ -n "$ip_now" ]] && ok "egress ip: $ip_now" || bad "cannot fetch egress ip"

echo "========== SHARE LINKS =========="
grep -E '^(vless|vmess|trojan|hy2|ss|tuic)://' "$SUB_TXT" 2>/dev/null && exit 0
base64 -d "$SUB_B64" 2>/dev/null | grep -E '^(vless|vmess|trojan|hy2|ss|tuic)://' && exit 0
grep -E '^(vless|vmess|trojan|hy2|ss|tuic)://' "$SHARE_LINKS" 2>/dev/null && exit 0

echo "ERROR: no links found (expect /root/sub.txt)." >&2
exit 3
