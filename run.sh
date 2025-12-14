#!/usr/bin/env bash
set -euo pipefail

# ===== Repo deploy.sh raw URL (no ?token=...) =====
DEPLOY_URL="https://raw.githubusercontent.com/lvfuq/vps-deploy/main/deploy.sh"

# ===== Files =====
RUN_LOG="/root/run.log"
SUB_TXT="/root/sub.txt"
SUB_B64="/root/sub.b64"
SHARE_LINKS="/root/share_links.txt"
CFG="/etc/sing-box/config.json"

ok(){  printf "PASS  %s\n" "$*"; }
bad(){ printf "FAIL  %s\n" "$*"; }
info(){ printf "INFO  %s\n" "$*"; }

is_listen_tcp(){ ss -lnt 2>/dev/null | awk '{print $4}' | grep -Eq "(:|\\])${1}$"; }
is_listen_udp(){ ss -lnu 2>/dev/null | awk '{print $4}' | grep -Eq "(:|\\])${1}$"; }

# ----- root -----
if [[ "${EUID}" -ne 0 ]]; then
  echo "ERROR: 请用 root 执行（sudo -i）" >&2
  exit 1
fi

# ----- deps (Debian) -----
export DEBIAN_FRONTEND=noninteractive
apt-get update -y >/dev/null 2>&1 || true
apt-get install -y curl ca-certificates jq python3 iproute2 coreutils >/dev/null 2>&1 || true

# ----- download deploy.sh (cache-bust) -----
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

curl -fsSL "${DEPLOY_URL}?ts=$(date +%s)" -o "$tmpdir/deploy.sh"
chmod +x "$tmpdir/deploy.sh"

# ----- auto-fix known bad urlencode/b64url_nopad blocks -----
# If deploy.sh contains "urllib.parse.quote", it is the buggy version; patch it in-place before bash parses it.
if grep -q "urllib.parse.quote" "$tmpdir/deploy.sh"; then
  python3 - "$tmpdir/deploy.sh" <<'PY'
import re, sys, pathlib

p = pathlib.Path(sys.argv[1])
lines = p.read_text(errors="ignore").splitlines(True)

def replace_func(lines, func_name, replacement):
  out = []
  i = 0
  replaced = False
  start_re = re.compile(r'^\s*' + re.escape(func_name) + r'\(\)\s*\{')
  end_re = re.compile(r'^\s*\}\s*$')
  while i < len(lines):
    if start_re.match(lines[i]):
      # skip until closing brace line
      i += 1
      while i < len(lines) and not end_re.match(lines[i]):
        i += 1
      if i < len(lines) and end_re.match(lines[i]):
        i += 1  # skip the closing brace
      out.append(replacement + "\n")
      replaced = True
      continue
    out.append(lines[i])
    i += 1
  return out, replaced

url_rep = "urlencode() { python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.stdin.read().strip(), safe=\"\"))'; }"
b64_rep = "b64url_nopad() { python3 -c 'import base64,sys;print(base64.urlsafe_b64encode(sys.stdin.buffer.read()).decode().rstrip(\"=\"))'; }"

lines, r1 = replace_func(lines, "urlencode", url_rep)
lines, r2 = replace_func(lines, "b64url_nopad", b64_rep)

# If functions weren't found (rare), inject near top after shebang
if not (r1 and r2):
  new_lines = []
  inserted = False
  for idx, ln in enumerate(lines):
    new_lines.append(ln)
    if (not inserted) and ln.startswith("#!") :
      # insert after shebang
      new_lines.append(url_rep + "\n")
      new_lines.append(b64_rep + "\n")
      inserted = True
  lines = new_lines

p.write_text("".join(lines))
PY
fi

# ----- run deploy.sh (capture all output; do not print subscription link) -----
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

# ----- self-test -----
echo "========== SELF-TEST =========="

if systemctl is-active --quiet sing-box; then
  ok "sing-box service is running"
else
  bad "sing-box service NOT running"
  info "journalctl -u sing-box -n 120 --no-pager"
fi

if [[ -f "$CFG" ]]; then
  ok "found $CFG"
  mapfile -t inbounds < <(jq -r '.inbounds[] | "\(.type) \(.listen_port)"' "$CFG" 2>/dev/null || true)
  if [[ "${#inbounds[@]}" -gt 0 ]]; then
    for item in "${inbounds[@]}"; do
      t="$(awk '{print $1}' <<<"$item")"
      p="$(awk '{print $2}' <<<"$item")"
      [[ -z "$p" ]] && continue
      case "$t" in
        hysteria2|tuic)
          is_listen_udp "$p" && ok "UDP listening ${p} (${t})" || bad "UDP NOT listening ${p} (${t})"
          ;;
        shadowsocks)
          is_listen_tcp "$p" && ok "TCP listening ${p} (shadowsocks)" || bad "TCP NOT listening ${p} (shadowsocks)"
          is_listen_udp "$p" && ok "UDP listening ${p} (shadowsocks)" || bad "UDP NOT listening ${p} (shadowsocks)"
          ;;
        *)
          is_listen_tcp "$p" && ok "TCP listening ${p} (${t})" || bad "TCP NOT listening ${p} (${t})"
          ;;
      esac
    done
  else
    bad "cannot parse inbounds from $CFG"
  fi
else
  bad "missing $CFG"
fi

ip_now="$(curl -fsSL https://api.ipify.org 2>/dev/null || true)"
[[ -n "$ip_now" ]] && ok "egress public ip: ${ip_now}" || bad "cannot fetch egress public ip"

# WARP state (optional informational)
trace="$(curl -fsSL https://www.cloudflare.com/cdn-cgi/trace/ 2>/dev/null || true)"
warp_state="$(echo "$trace" | awk -F= '/^warp=/{print $2}_
