#!/usr/bin/env bash
set -euo pipefail
umask 077

# -----------------------------
# Settings (you can keep defaults)
# -----------------------------
SNI="${SNI:-www.microsoft.com}"
FP="${FP:-chrome}"
GRPC_SERVICE="${GRPC_SERVICE:-grpc}"
WS_PATH="${WS_PATH:-/vm}"

# Ports (match firewall + config)
PORT_VLESS_TCP=443
PORT_VLESS_GRPC=8443
PORT_TROJAN_TCP=2053
PORT_VMESS_WS=16026
PORT_SS2022=34443
PORT_SS=35165
PORT_HY2_UDP=443
PORT_HY2_OBFS_UDP=20109
PORT_TUIC_UDP=33562

# Local firewall (UFW) - open these
PORTS_TCP=("$PORT_VLESS_TCP" "$PORT_VLESS_GRPC" "$PORT_TROJAN_TCP" "$PORT_VMESS_WS" "$PORT_SS2022" "$PORT_SS")
PORTS_UDP=("$PORT_HY2_UDP" "$PORT_HY2_OBFS_UDP" "$PORT_TUIC_UDP" "$PORT_SS2022" "$PORT_SS")

LOG_FILE="/root/deploy.log"
LINK_FILE="/root/share_links.txt"
SUB_FILE="/root/sub.txt"       # plain list
SUB_B64_FILE="/root/sub.b64"   # base64 subscription content

# -----------------------------
# Helpers
# -----------------------------
log() { echo "[$(date -Is)] $*" >>"$LOG_FILE"; }

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: please run as root (sudo -i)" >&2
    exit 1
  fi
}

apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >>"$LOG_FILE" 2>&1
  apt-get install -y "$@" >>"$LOG_FILE" 2>&1
}

get_public_ip() {
  curl -fsSL https://api.ipify.org 2>>"$LOG_FILE" || true
}

setup_ufw() {
  # Install ufw + ensure ssh allowed first to avoid lockout
  apt_install ufw

  local ssh_ports
  ssh_ports="$(grep -E '^\s*Port\s+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | tr '\n' ' ' || true)"
  [[ -z "${ssh_ports// }" ]] && ssh_ports="22"

  # If inactive, set safe defaults
  if ufw status | grep -qi "Status: inactive"; then
    ufw default deny incoming >>"$LOG_FILE" 2>&1 || true
    ufw default allow outgoing >>"$LOG_FILE" 2>&1 || true
  fi

  # Allow ssh
  for p in $ssh_ports; do
    ufw allow "${p}/tcp" >>"$LOG_FILE" 2>&1 || true
  done

  # Allow required ports
  for p in "${PORTS_TCP[@]}"; do ufw allow "${p}/tcp" >>"$LOG_FILE" 2>&1 || true; done
  for p in "${PORTS_UDP[@]}"; do ufw allow "${p}/udp" >>"$LOG_FILE" 2>&1 || true; done

  ufw --force enable >>"$LOG_FILE" 2>&1 || true
  log "UFW configured. (Cloud provider security group still needs matching rules.)"
}

install_warp_and_connect() {
  # Cloudflare WARP (consumer). If it fails, we just mark warp off and continue.
  # Repo + install commands follow Cloudflare package page. :contentReference[oaicite:5]{index=5}
  apt_install curl ca-certificates gpg lsb-release

  if ! command -v warp-cli >/dev/null 2>&1; then
    curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg \
      | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg >>"$LOG_FILE" 2>&1 || true

    echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" \
      > /etc/apt/sources.list.d/cloudflare-client.list

    apt-get update -y >>"$LOG_FILE" 2>&1 || true
    apt-get install -y cloudflare-warp >>"$LOG_FILE" 2>&1 || true
  fi

  if ! command -v warp-cli >/dev/null 2>&1; then
    log "WARP: warp-cli not available; skip."
    echo "0"
    return
  fi

  # Initial connection per Cloudflare docs. :contentReference[oaicite:6]{index=6}
  warp-cli registration new >>"$LOG_FILE" 2>&1 || true
  warp-cli mode warp+doh >>"$LOG_FILE" 2>&1 || true
  warp-cli connect >>"$LOG_FILE" 2>&1 || true

  # Verify
  local trace
  trace="$(curl -fsSL https://www.cloudflare.com/cdn-cgi/trace/ 2>>"$LOG_FILE" || true)"
  if echo "$trace" | grep -q '^warp=on'; then
    log "WARP: warp=on confirmed."
    echo "1"
  else
    log "WARP: not confirmed (warp!=on)."
    echo "0"
  fi
}

install_singbox() {
  # Official install script. :contentReference[oaicite:7]{index=7}
  apt_install curl jq openssl python3 ca-certificates
  curl -fsSL https://sing-box.app/install.sh | sh >>"$LOG_FILE" 2>&1
}

ensure_cert() {
  mkdir -p /etc/sing-box
  if [[ ! -f /etc/sing-box/self.crt ]]; then
    openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
      -subj "/CN=${SNI}" \
      -keyout /etc/sing-box/self.key \
      -out /etc/sing-box/self.crt >>"$LOG_FILE" 2>&1
    chmod 600 /etc/sing-box/self.key
  fi
}

write_singbox_config() {
  local sb_bin="$1"
  local uuid="$2"
  local reality_private="$3"
  local short_id="$4"
  local hy2_pass="$5"
  local hy2_obfs_pass="$6"
  local ss2022_pass="$7"
  local ss_pass="$8"

  cat >/etc/sing-box/config.json <<JSON
{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality-tcp",
      "listen": "::",
      "listen_port": ${PORT_VLESS_TCP},
      "users": [{ "uuid": "${uuid}", "flow": "xtls-rprx-vision" }],
      "tls": {
        "enabled": true,
        "server_name": "${SNI}",
        "reality": {
          "enabled": true,
          "handshake": { "server": "${SNI}", "server_port": 443 },
          "private_key": "${reality_private}",
          "short_id": ["${short_id}"]
        }
      }
    },
    {
      "type": "vless",
      "tag": "vless-reality-grpc",
      "listen": "::",
      "listen_port": ${PORT_VLESS_GRPC},
      "users": [{ "uuid": "${uuid}" }],
      "tls": {
        "enabled": true,
        "server_name": "${SNI}",
        "reality": {
          "enabled": true,
          "handshake": { "server": "${SNI}", "server_port": 443 },
          "private_key": "${reality_private}",
          "short_id": ["${short_id}"]
        }
      },
      "transport": { "type": "grpc", "service_name": "${GRPC_SERVICE}" }
    },
    {
      "type": "trojan",
      "tag": "trojan-reality",
      "listen": "::",
      "listen_port": ${PORT_TROJAN_TCP},
      "users": [{ "password": "${uuid}" }],
      "tls": {
        "enabled": true,
        "server_name": "${SNI}",
        "reality": {
          "enabled": true,
          "handshake": { "server": "${SNI}", "server_port": 443 },
          "private_key": "${reality_private}",
          "short_id": ["${short_id}"]
        }
      }
    },
    {
      "type": "vmess",
      "tag": "vmess-ws",
      "listen": "::",
      "listen_port": ${PORT_VMESS_WS},
      "users": [{ "uuid": "${uuid}", "alter_id": 0 }],
      "transport": { "type": "ws", "path": "${WS_PATH}" }
    },
    {
      "type": "hysteria2",
      "tag": "hy2",
      "listen": "::",
      "listen_port": ${PORT_HY2_UDP},
      "users": [{ "password": "${hy2_pass}" }],
      "tls": {
        "enabled": true,
        "certificate_path": "/etc/sing-box/self.crt",
        "key_path": "/etc/sing-box/self.key"
      }
    },
    {
      "type": "hysteria2",
      "tag": "hy2-obfs",
      "listen": "::",
      "listen_port": ${PORT_HY2_OBFS_UDP},
      "users": [{ "password": "${hy2_pass}" }],
      "obfs": { "type": "salamander", "password": "${hy2_obfs_pass}" },
      "tls": {
        "enabled": true,
        "certificate_path": "/etc/sing-box/self.crt",
        "key_path": "/etc/sing-box/self.key"
      }
    },
    {
      "type": "tuic",
      "tag": "tuic",
      "listen": "::",
      "listen_port": ${PORT_TUIC_UDP},
      "users": [{ "uuid": "${uuid}", "password": "${uuid}" }],
      "congestion_control": "bbr",
      "tls": {
        "enabled": true,
        "certificate_path": "/etc/sing-box/self.crt",
        "key_path": "/etc/sing-box/self.key"
      }
    },
    {
      "type": "shadowsocks",
      "tag": "ss2022",
      "listen": "::",
      "listen_port": ${PORT_SS2022},
      "method": "2022-blake3-aes-256-gcm",
      "password": "${ss2022_pass}"
    },
    {
      "type": "shadowsocks",
      "tag": "ss",
      "listen": "::",
      "listen_port": ${PORT_SS},
      "method": "aes-256-gcm",
      "password": "${ss_pass}"
    }
  ],
  "outbounds": [{ "type": "direct", "tag": "direct" }],
  "route": { "final": "direct" }
}
JSON

  cat >/etc/systemd/system/sing-box.service <<SERVICE
[Unit]
Description=sing-box
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${sb_bin} run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
SERVICE
}

build_links_and_write_files() {
  local vps_ip="$1"
  local uuid="$2"
  local reality_pub="$3"
  local short_id="$4"
  local warp_on="$5"
  local hy2_pass="$6"
  local hy2_obfs_pass="$7"
  local ss2022_pass="$8"
  local ss_pass="$9"

  urlencode() { python3 - <<'PY' ;import sys,urllib.parse;print(urllib.parse.quote(sys.stdin.read().strip(),safe="")) ;PY }
  b64url_nopad() { python3 - <<'PY' ;import base64,sys;print(base64.urlsafe_b64encode(sys.stdin.buffer.read()).decode().rstrip("=")) ;PY }

  local tag_suffix=""
  [[ "$warp_on" == "1" ]] && tag_suffix="-warp"

  local vless_tcp="vless://${uuid}@${vps_ip}:${PORT_VLESS_TCP}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=${FP}&pbk=${reality_pub}&sid=${short_id}&type=tcp#vless-reality${tag_suffix}"
  local vless_grpc="vless://${uuid}@${vps_ip}:${PORT_VLESS_GRPC}?encryption=none&security=reality&sni=${SNI}&fp=${FP}&pbk=${reality_pub}&sid=${short_id}&type=grpc&serviceName=${GRPC_SERVICE}#vless-grpc-reality${tag_suffix}"
  local trojan="trojan://${uuid}@${vps_ip}:${PORT_TROJAN_TCP}?security=reality&sni=${SNI}&fp=${FP}&pbk=${reality_pub}&sid=${short_id}&type=tcp#trojan-reality${tag_suffix}"

  local hy2_pass_enc; hy2_pass_enc="$(printf '%s' "${hy2_pass}" | urlencode)"
  local hy2="hy2://${hy2_pass_enc}@${vps_ip}:${PORT_HY2_UDP}?insecure=1&allowInsecure=1&sni=${SNI}#hysteria2${tag_suffix}"

  local hy2_obfs_enc; hy2_obfs_enc="$(printf '%s' "${hy2_obfs_pass}" | urlencode)"
  local hy2_obfs="hy2://${hy2_pass_enc}@${vps_ip}:${PORT_HY2_OBFS_UDP}?insecure=1&allowInsecure=1&sni=${SNI}&alpn=h3&obfs=salamander&obfs-password=${hy2_obfs_enc}#hysteria2-obfs${tag_suffix}"

  local vmess_json; vmess_json="$(python3 - <<PY
import json
print(json.dumps({"v":"2","ps":"vmess-ws${tag_suffix}","add":"${vps_ip}","port":"${PORT_VMESS_WS}","id":"${uuid}","aid":"0","net":"ws","type":"none","host":"","path":"${WS_PATH}","tls":""},separators=(',',':')))
PY
)"
  local vmess="vmess://$(printf '%s' "${vmess_json}" | base64 -w 0)"

  local ss2022_userinfo; ss2022_userinfo="$(printf '%s' "2022-blake3-aes-256-gcm:${ss2022_pass}" | b64url_nopad)"
  local ss2022="ss://${ss2022_userinfo}@${vps_ip}:${PORT_SS2022}#ss2022${tag_suffix}"

  local ss_userinfo; ss_userinfo="$(printf '%s' "aes-256-gcm:${ss_pass}" | b64url_nopad)"
  local ss="ss://${ss_userinfo}@${vps_ip}:${PORT_SS}#ss${tag_suffix}"

  local tuic="tuic://${uuid}:${uuid}@${vps_ip}:${PORT_TUIC_UDP}?congestion_control=bbr&alpn=h3&insecure=1&allowInsecure=1&sni=${SNI}#tuic-v5${tag_suffix}"

  # 1) 给 run.sh 用：只要一条（你要求的那种）
  echo "${vless_tcp}" > "$LINK_FILE"

  # 2) 订阅内容（给你自己用，不打印）
  cat >"$SUB_FILE" <<EOF
${vless_tcp}
${vless_grpc}
${trojan}
${hy2}
${hy2_obfs}
${vmess}
${ss2022}
${ss}
${tuic}
EOF
  base64 -w 0 "$SUB_FILE" >"$SUB_B64_FILE"
}

update_gist_if_provided() {
  # Optional: only if user provided env vars.
  local gist_id="${GIST_ID:-}"
  local gh_token="${GH_TOKEN:-}"

  if [[ -z "$gist_id" || -z "$gh_token" ]]; then
    log "Gist update skipped (GIST_ID/GH_TOKEN not set)."
    return 0
  fi

  # Update a gist via GitHub REST API. :contentReference[oaicite:8]{index=8}
  local owner
  owner="$(curl -fsSL -H "Authorization: Bearer ${gh_token}" -H "Accept: application/vnd.github+json" \
    "https://api.github.com/gists/${gist_id}" | jq -r '.owner.login' 2>>"$LOG_FILE" || true)"

  if [[ -z "$owner" || "$owner" == "null" ]]; then
    log "Gist update failed: cannot read gist owner (check token scope 'gist' and GIST_ID)."
    return 1
  fi

  jq -n --arg content "$(cat "$SUB_B64_FILE")" '{files: {"sub.txt": {content: $content}}}' >/tmp/gist_patch.json
  curl -fsSL -X PATCH \
    -H "Authorization: Bearer ${gh_token}" \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/gists/${gist_id}" \
    -d @/tmp/gist_patch.json >>"$LOG_FILE" 2>&1

  log "Gist updated: https://gist.githubusercontent.com/${owner}/${gist_id}/raw/sub.txt"
}

main() {
  : >"$LOG_FILE" || true
  need_root

  log "Start deploy"
  setup_ufw

  # Try enable WARP (system-wide). Only tag -warp if verified warp=on. :contentReference[oaicite:9]{index=9}
  WARP_ON="$(install_warp_and_connect)"

  install_singbox
  ensure_cert

  local sb_bin
  sb_bin="$(command -v sing-box || true)"
  [[ -n "$sb_bin" ]] || { echo "ERROR: sing-box not found" >&2; exit 1; }

  local vps_ip
  vps_ip="$(get_public_ip)"
  [[ -n "$vps_ip" ]] || { echo "ERROR: cannot detect public IP" >&2; exit 1; }

  local uuid keys reality_private reality_public short_id
  uuid="$("$sb_bin" generate uuid)"
  keys="$("$sb_bin" generate reality-keypair)"
  reality_private="$(echo "$keys" | awk '/PrivateKey/ {print $2}')"
  reality_public="$(echo "$keys" | awk '/PublicKey/ {print $2}')"
  short_id="$("$sb_bin" generate rand --hex 8)"

  local hy2_pass hy2_obfs_pass ss2022_pass ss_pass
  hy2_pass="$(openssl rand -base64 24)"
  hy2_obfs_pass="$(openssl rand -base64 24)"
  ss2022_pass="$(openssl rand -base64 24)"
  ss_pass="$(openssl rand -base64 24)"

  write_singbox_config "$sb_bin" "$uuid" "$reality_private" "$short_id" "$hy2_pass" "$hy2_obfs_pass" "$ss2022_pass" "$ss_pass"

  systemctl daemon-reload >>"$LOG_FILE" 2>&1
  systemctl enable --now sing-box >>"$LOG_FILE" 2>&1

  build_links_and_write_files "$vps_ip" "$uuid" "$reality_public" "$short_id" "$WARP_ON" "$hy2_pass" "$hy2_obfs_pass" "$ss2022_pass" "$ss_pass"

  # Update subscription gist (optional)
  update_gist_if_provided || true

  log "Deploy done. WARP_ON=${WARP_ON}. Link file: ${LINK_FILE}"
}

main
