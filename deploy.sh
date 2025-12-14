#!/usr/bin/env bash
set -euo pipefail
umask 077

# ========== Basic settings ==========
SNI="${SNI:-www.microsoft.com}"
FP="${FP:-chrome}"
GRPC_SERVICE="${GRPC_SERVICE:-grpc}"
WS_PATH="${WS_PATH:-/vm}"

# Ports
PORT_VLESS_TCP=443
PORT_VLESS_GRPC=8443
PORT_TROJAN_TCP=2053
PORT_VMESS_WS=16026
PORT_SS2022=34443
PORT_SS=35165
PORT_HY2_UDP=443
PORT_HY2_OBFS_UDP=20109
PORT_TUIC_UDP=33562

# Files
LOG_FILE="/root/deploy.log"
SUB_TXT="/root/sub.txt"
SUB_B64="/root/sub.b64"
SHARE_LINKS="/root/share_links.txt"

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

# ---- FIXED helpers (no heredoc, no shell syntax issue) ----
urlencode() {
  python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read().strip(), safe=""))'
}
b64url_nopad() {
  python3 -c 'import base64,sys; print(base64.urlsafe_b64encode(sys.stdin.buffer.read()).decode().rstrip("="))'
}

setup_ufw() {
  apt_install ufw

  local ssh_ports
  ssh_ports="$(grep -E '^\s*Port\s+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | tr '\n' ' ' || true)"
  [[ -z "${ssh_ports// }" ]] && ssh_ports="22"

  if ufw status | grep -qi "Status: inactive"; then
    ufw default deny incoming >>"$LOG_FILE" 2>&1 || true
    ufw default allow outgoing >>"$LOG_FILE" 2>&1 || true
  fi

  # Allow SSH first
  for p in $ssh_ports; do ufw allow "${p}/tcp" >>"$LOG_FILE" 2>&1 || true; done

  # Allow service ports
  ufw allow "${PORT_VLESS_TCP}/tcp" >>"$LOG_FILE" 2>&1 || true
  ufw allow "${PORT_VLESS_GRPC}/tcp" >>"$LOG_FILE" 2>&1 || true
  ufw allow "${PORT_TROJAN_TCP}/tcp" >>"$LOG_FILE" 2>&1 || true
  ufw allow "${PORT_VMESS_WS}/tcp" >>"$LOG_FILE" 2>&1 || true
  ufw allow "${PORT_SS2022}/tcp" >>"$LOG_FILE" 2>&1 || true
  ufw allow "${PORT_SS}/tcp" >>"$LOG_FILE" 2>&1 || true

  ufw allow "${PORT_HY2_UDP}/udp" >>"$LOG_FILE" 2>&1 || true
  ufw allow "${PORT_HY2_OBFS_UDP}/udp" >>"$LOG_FILE" 2>&1 || true
  ufw allow "${PORT_TUIC_UDP}/udp" >>"$LOG_FILE" 2>&1 || true
  ufw allow "${PORT_SS2022}/udp" >>"$LOG_FILE" 2>&1 || true
  ufw allow "${PORT_SS}/udp" >>"$LOG_FILE" 2>&1 || true

  ufw --force enable >>"$LOG_FILE" 2>&1 || true
  log "UFW configured (provider security-group still needed)."
}

install_singbox() {
  apt_install curl jq openssl python3 ca-certificates
  curl -fsSL https://sing-box.app/install.sh | sh >>"$LOG_FILE" 2>&1
  log "sing-box installed"
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

write_config_and_service() {
  local sb_bin="$1"
  local uuid="$2"
  local reality_priv="$3"
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
          "private_key": "${reality_priv}",
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
          "private_key": "${reality_priv}",
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
          "private_key": "${reality_priv}",
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

  systemctl daemon-reload >>"$LOG_FILE" 2>&1
  systemctl enable --now sing-box >>"$LOG_FILE" 2>&1
}

build_links_and_write_files() {
  local vps_ip="$1"
  local uuid="$2"
  local reality_pub="$3"
  local short_id="$4"
  local hy2_pass="$5"
  local hy2_obfs_pass="$6"
  local ss2022_pass="$7"
  local ss_pass="$8"

  local vless_tcp="vless://${uuid}@${vps_ip}:${PORT_VLESS_TCP}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=${FP}&pbk=${reality_pub}&sid=${short_id}&type=tcp#vless-reality"
  local vless_grpc="vless://${uuid}@${vps_ip}:${PORT_VLESS_GRPC}?encryption=none&security=reality&sni=${SNI}&fp=${FP}&pbk=${reality_pub}&sid=${short_id}&type=grpc&serviceName=${GRPC_SERVICE}#vless-grpc-reality"
  local trojan="trojan://${uuid}@${vps_ip}:${PORT_TROJAN_TCP}?security=reality&sni=${SNI}&fp=${FP}&pbk=${reality_pub}&sid=${short_id}&type=tcp#trojan-reality"

  local hy2_pass_enc; hy2_pass_enc="$(printf '%s' "${hy2_pass}" | urlencode)"
  local hy2="hy2://${hy2_pass_enc}@${vps_ip}:${PORT_HY2_UDP}?insecure=1&allowInsecure=1&sni=${SNI}#hysteria2"

  local hy2_obfs_enc; hy2_obfs_enc="$(printf '%s' "${hy2_obfs_pass}" | urlencode)"
  local hy2_obfs="hy2://${hy2_pass_enc}@${vps_ip}:${PORT_HY2_OBFS_UDP}?insecure=1&allowInsecure=1&sni=${SNI}&alpn=h3&obfs=salamander&obfs-password=${hy2_obfs_enc}#hysteria2-obfs"

  local vmess_json; vmess_json="$(python3 -c "import json; print(json.dumps({'v':'2','ps':'vmess-ws','add':'${vps_ip}','port':'${PORT_VMESS_WS}','id':'${uuid}','aid':'0','net':'ws','type':'none','host':'','path':'${WS_PATH}','tls':''},separators=(',',':')))")"
  local vmess="vmess://$(printf '%s' "${vmess_json}" | base64 -w 0)"

  local ss2022_userinfo; ss2022_userinfo="$(printf '%s' "2022-blake3-aes-256-gcm:${ss2022_pass}" | b64url_nopad)"
  local ss2022="ss://${ss2022_userinfo}@${vps_ip}:${PORT_SS2022}#ss2022"

  local ss_userinfo; ss_userinfo="$(printf '%s' "aes-256-gcm:${ss_pass}" | b64url_nopad)"
  local ss="ss://${ss_userinfo}@${vps_ip}:${PORT_SS}#ss"

  local tuic="tuic://${uuid}:${uuid}@${vps_ip}:${PORT_TUIC_UDP}?congestion_control=bbr&alpn=h3&insecure=1&allowInsecure=1&sni=${SNI}#tuic-v5"

  # Write files for run.sh
  cat >"$SUB_TXT" <<EOF
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
  base64 -w 0 "$SUB_TXT" >"$SUB_B64"
  cp "$SUB_TXT" "$SHARE_LINKS"
}

update_gist_if_provided() {
  local gist_id="${GIST_ID:-}"
  local gh_token="${GH_TOKEN:-}"
  [[ -z "$gist_id" || -z "$gh_token" ]] && return 0

  local owner
  owner="$(curl -fsSL -H "Authorization: Bearer ${gh_token}" -H "Accept: application/vnd.github+json" \
    "https://api.github.com/gists/${gist_id}" | jq -r '.owner.login' 2>>"$LOG_FILE" || true)"
  [[ -z "$owner" || "$owner" == "null" ]] && { log "Gist update failed (bad token scope or GIST_ID)"; return 1; }

  jq -n --arg content "$(cat "$SUB_B64")" '{files: {"sub.txt": {content: $content}}}' >/tmp/gist_patch.json
  curl -fsSL -X PATCH \
    -H "Authorization: Bearer ${gh_token}" \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/gists/${gist_id}" \
    -d @/tmp/gist_patch.json >>"$LOG_FILE" 2>&1 || true

  log "Gist updated: https://gist.githubusercontent.com/${owner}/${gist_id}/raw/sub.txt"
}

main() {
  : >"$LOG_FILE" || true
  need_root

  setup_ufw
  install_singbox
  ensure_cert

  local sb_bin; sb_bin="$(command -v sing-box || true)"
  [[ -n "$sb_bin" ]] || { echo "ERROR: sing-box not found" >&2; exit 1; }

  local vps_ip; vps_ip="$(get_public_ip)"
  [[ -n "$vps_ip" ]] || { echo "ERROR: cannot detect public IP" >&2; exit 1; }

  local uuid keys reality_priv reality_pub short_id
  uuid="$("$sb_bin" generate uuid)"
  keys="$("$sb_bin" generate reality-keypair)"
  reality_priv="$(echo "$keys" | awk '/PrivateKey/ {print $2}')"
  reality_pub="$(echo "$keys" | awk '/PublicKey/ {print $2}')"
  short_id="$("$sb_bin" generate rand --hex 8)"

  local hy2_pass hy2_obfs_pass ss2022_pass ss_pass
  hy2_pass="$(openssl rand -base64 24)"
  hy2_obfs_pass="$(openssl rand -base64 24)"
  ss2022_pass="$(openssl rand -base64 24)"
  ss_pass="$(openssl rand -base64 24)"

  write_config_and_service "$sb_bin" "$uuid" "$reality_priv" "$short_id" "$hy2_pass" "$hy2_obfs_pass" "$ss2022_pass" "$ss_pass"
  build_links_and_write_files "$vps_ip" "$uuid" "$reality_pub" "$short_id" "$hy2_pass" "$hy2_obfs_pass" "$ss2022_pass" "$ss_pass"
  update_gist_if_provided || true
}

main
