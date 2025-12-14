#!/usr/bin/env bash
set -euo pipefail

# ---- repo deploy.sh raw url (NO ?token=...) ----
DEPLOY_URL="https://raw.githubusercontent.com/lvfuq/vps-deploy/main/deploy.sh"

# ---- files ----
RUN_LOG="/root/run.log"
DEPLOY_LOG="/root/deploy.log"         # deploy.sh 如果自己写日志就会用到；没有也不影响
SUB_TXT="/root/sub.txt"              # 推荐：deploy.sh 写出所有节点链接到这里（一行一个）
SUB_B64="/root/sub.b64"              # 可选：deploy.sh 写出 base64 订阅内容
SHARE_LINKS="/root/share_links.txt"  # 兜底：deploy.sh 写出分享链接

# ---- self-test helpers ----
ok()   { printf "PASS  %s\n" "$*"; }
bad()  { printf "FAIL  %s\n" "$*"; }
info() { printf "INFO  %s\n" "$*"; }

is_listen_tcp() {
  local p="$1"
  ss -lnt 2>/dev/null | awk '{print $4}' | grep -Eq "(:|\\])${p}$"
}

is_listen_udp() {
  local p="$1"
  ss -lnu 2>/dev/null | awk '{print $4}' | grep -Eq "(:|\\])${p}$"
}

# ---- root check ----
if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR: 请用 root 执行（sudo -i）" >&2
  exit 1
fi

# ---- deps (Debian) ----
export DEBIAN_FRONTEND=noninteractive
apt-get update -y >/dev/null 2>&1 || true
apt-get install -y curl ca-certificates jq iproute2 coreutils >/dev/null 2>&1 || true

# ---- download deploy.sh ----
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
curl -fsSL "$DEPLOY_URL" -o "$tmpdir/deploy.sh"
chmod +x "$tmpdir/deploy.sh"

# ---- run deploy.sh (capture ALL output; do not print subscription URL) ----
: >"$RUN_LOG" || true
(
  # 允许你在“一条命令”里粘贴传入；不要求必须提供，没提供也能跑（只是不会更新订阅）
  : "${GIST_ID:=}"
  : "${GH_TOKEN:=}"
  export GIST_ID GH_TOKEN

  bash "$tmpdir/deploy.sh"
) >"$RUN_LOG" 2>&1 || {
  echo "ERROR: deploy.sh 执行失败，下面是最后 120 行日志：" >&2
  tail -n 120 "$RUN_LOG" >&2 || true
  exit 2
}

# ---- self-test ----
echo "========== SELF-TEST =========="

if systemctl is-active --quiet sing-box; then
  ok "sing-box service is running"
else
  bad "sing-box service NOT running"
  info "last 80 lines: journalctl -u sing-box -n 80 --no-pager"
fi

# Parse ports from /etc/sing-box/config.json if exists
CFG="/etc/sing-box/config.json"
if [[ -f "$CFG" ]]; then
  ok "found $CFG"
  # Extract (type, port)
  mapfile -t inbounds < <(jq -r '.inbounds[] | "\(.type) \(.listen_port)"' "$CFG" 2>/dev/null || true)

  if [[ "${#inbounds[@]}" -gt 0 ]]; then
    for item in "${inbounds[@]}"; do
      t="$(awk '{print $1}' <<<"$item")"
      p="$(awk '{print $2}' <<<"$item")"
      [[ -z "$p" ]] && continue

      case "$t" in
        hysteria2|tuic)
          if is_listen_udp "$p"; then ok "UDP listen ${p} (${t})"; else bad "UDP NOT listening ${p} (${t})"; fi
          ;;
        shadowsocks)
          # SS 通常 TCP+UDP 同端口
          if is_listen_tcp "$p"; then ok "TCP listen ${p} (shadowsocks)"; else bad "TCP NOT listening ${p} (shadowsocks)"; fi
          if is_listen_udp "$p"; then ok "UDP listen ${p} (shadowsocks)"; else bad "UDP NOT listening ${p} (shadowsocks)"; fi
          ;;
        *)
          if is_listen_tcp "$p"; then ok "TCP listen ${p} (${t})"; else bad "TCP NOT listening ${p} (${t})"; fi
          ;;
      esac
    done
  else
    bad "cannot parse inbounds from $CFG"
  fi
else
  bad "missing $CFG (deploy.sh 可能没生成配置)"
fi

# Outbound / WARP check (does not prove inbound reachable; only shows current egress)
ip_now="$(curl -fsSL https://api.ipify.org 2>/dev/null || true)"
if [[ -n "$ip_now" ]]; then
  ok "egress public ip: ${ip_now}"
else
  bad "cannot fetch egress public ip (outbound network?)"
fi

trace="$(curl -fsSL https://www.cloudflare.com/cdn-cgi/trace/ 2>/dev/null || true)"
warp_state="$(echo "$trace" | awk -F= '/^warp=/{print $2}' | head -n1)"
if [[ "$warp_state" == "on" ]]; then
  ok "WARP state: warp=on"
elif [[ -n "$warp_state" ]]; then
  info "WARP state: warp=${warp_state}"
else
  info "WARP state: unknown (trace unavailable)"
fi

echo "========== SHARE LINKS =========="

# ---- print ALL protocol links (no subscription URL) ----
print_links() {
  local src="$1"

  # Only print lines starting with protocol schemes
  # (vless/vmess/trojan/hy2/ss/tuic)
  grep -E '^(vless|vmess|trojan|hy2|ss|tuic)://' "$src" || true
}

if [[ -s "$SUB_TXT" ]]; then
  print_links "$SUB_TXT"
  exit 0
fi

if [[ -s "$SUB_B64" ]]; then
  # decode and print
  base64 -d "$SUB_B64" 2>/dev/null | grep -E '^(vless|vmess|trojan|hy2|ss|tuic)://' || true
  exit 0
fi

# fallback: parse deploy output log
if grep -qE '^(vless|vmess|trojan|hy2|ss|tuic)://' "$RUN_LOG"; then
  print_links "$RUN_LOG"
  exit 0
fi

# last fallback: share_links.txt
if [[ -s "$SHARE_LINKS" ]]; then
  print_links "$SHARE_LINKS"
  exit 0
fi

echo "ERROR: 没找到任何分享链接。" >&2
echo "建议让 deploy.sh 写出 /root/sub.txt（每行一个链接），run.sh 才能稳定打印全部协议。" >&2
exit 3
