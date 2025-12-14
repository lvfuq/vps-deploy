#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root."
  exit 1
fi

: "${GIST_ID:?GIST_ID is required}"
: "${GH_TOKEN:?GH_TOKEN is required}"

SNI="${SNI:-www.microsoft.com}"
WS_PATH="${WS_PATH:-/vm}"
GRPC_SERVICE="${GRPC_SERVICE:-grpc}"

PORT_VLESS_TCP=443
PORT_VLESS_GRPC=8443
PORT_TROJAN_TCP=2053
PORT_VMESS_WS=16026
PORT_SS2022=34443
PORT_SS=35165
PORT_HY2=443
PORT_HY2_OBFS=20109
PORT_TUIC=33562

install_deps() {
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y curl jq openssl python3 ca-certificates
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl jq openssl python3 ca-certificates
  else
    echo "Unsupported package manager."
    exit 1
  fi
}

install_singbox() {
  # Official installer
  curl -fsSL https://sing-box.app/install.sh | sh
}

urlencode() {
  python3 - <<'PY'
import sys, urllib.parse
print(urllib.parse.quote(sys.stdin.read().strip(), safe=""))
PY
}

b64url_nopad() {
  python3 - <<'PY'
import base64, sys
data = sys.stdin.buffer.read()
print(base64.urlsafe_b64encode(data).decode().rstrip("="))
PY
}

main() {
  install_deps
  install_singbox

  SB_BIN="$(command -v sing-box)"
  [[ -n "${SB_BIN}" ]] || { echo "sing-box not found after install."; exit 1; }

  VPS_IP="$(curl -fsSL https://api.ipify.org || true)"
  [[ -n "${VPS_IP}" ]] || { echo "Failed to detect public IP."; exit 1; }

  UUID="$(${SB_BIN} generate uuid)"
  KEYS="$(${SB_BIN} generate reality-keypair)"
  REALITY_PRIVATE="$(echo "${KEYS}" | awk '/PrivateKey/ {print $2}')"
  REALITY_PUBLIC="$(echo "${KEYS}" | awk '/PublicKey/ {print $2}')"
  SHORT_ID="$(${SB_BIN} generate rand --hex 8)"

  HY2_PASS="$(openssl rand -base64 24)"
  HY2_OBFS_PASS="$(openssl rand -base64 24)"
  SS2022_PASS="$(openssl rand -base64 24)"
  SS_PASS="$(openssl rand -base64 24)"

  mkdir -p /etc/sing-box

  if [[ ! -f /etc/sing-box/self.crt ]]; then
    openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
      -subj "/CN=${SNI}" \
      -keyout /etc/sing-box/self.key \
      -out /etc/sing-box/self.crt
    chmod 600 /etc/sing-box/self.key
  fi

  cat >/etc/sing-box/config.json <<JSON
{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality-tcp",
      "listen": "::",
      "listen_port": ${PORT_VLESS_TCP},
      "users": [{ "uuid": "${UUID}", "flow": "xtls-rprx-vision" }],
      "tls": {
        "enabled": true,
        "server_name": "${SNI}",
        "reality": {
          "enabled": true,
          "handshake": { "server": "${SNI}", "server_port": 443 },
          "private_key": "${REALITY_PRIVATE}",
          "short_id": ["${SHORT_ID}"]
        }
      }
    },
    {
      "type": "vless",
      "tag": "vless-reality-grpc",
      "listen": "::",
      "listen_port": ${PORT_VLESS_GRPC},
      "users": [{ "uuid": "${UUID}" }],
      "tls": {
        "enabled": true,
        "server_name": "${SNI}",
        "reality": {
          "enabled": true,
          "handshake": { "server": "${SNI}", "server_port": 443 },
          "private_key": "${REALITY_PRIVATE}",
          "short_id": ["${SHORT_ID}"]
        }
      },
      "transport": { "type": "grpc", "service_name": "${GRPC_SERVICE}" }
    },
    {
      "type": "trojan",
      "tag": "trojan-reality",
      "listen": "::",
      "listen_port": ${PORT_TROJAN_TCP},
      "users": [{ "password": "${UUID}" }],
      "tls": {
        "enabled": true,
        "server_name": "${SNI}",
        "reality": {
          "enabled": true,
          "handshake": { "server": "${SNI}", "server_port": 443 },
          "private_key": "${REALITY_PRIVATE}",
          "short_id": ["${SHORT_ID}"]
        }
      }
    },
    {
      "type": "vmess",
      "tag": "vmess-ws",
      "listen": "::",
      "listen_port": ${PORT_VMESS_WS},
      "users": [{ "uuid": "${UUID}", "alter_id": 0 }],
      "transport": { "type": "ws", "path": "${WS_PATH}" }
    },
    {
      "type": "hysteria2",
      "tag": "hy2",
      "listen": "::",
      "listen_port": ${PORT_HY2},
      "users": [{ "password": "${HY2_PASS}" }],
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
      "listen_port": ${PORT_HY2_OBFS},
      "users": [{ "password": "${HY2_PASS}" }],
      "obfs": { "type": "salamander", "password": "${HY2_OBFS_PASS}" },
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
      "listen_port": ${PORT_TUIC},
      "users": [{ "uuid": "${UUID}", "password": "${UUID}" }],
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
      "password": "${SS2022_PASS}"
    },
    {
      "type": "shadowsocks",
      "tag": "ss",
      "listen": "::",
      "listen_port": ${PORT_SS},
      "method": "aes-256-gcm",
      "password": "${SS_PASS}"
    }
  ],
  "outbounds": [{ "type": "direct", "tag": "direct" }],
  "route": { "final": "direct" }
}
JSON

  cat >/etc/systemd/system/sing-box.service <<'SERVICE'
[Unit]
Description=sing-box
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
SERVICE

  if [[ "${SB_BIN}" != "/usr/local/bin/sing-box" ]]; then
    sed -i "s|/usr/local/bin/sing-box|${SB_BIN}|g" /etc/systemd/system/sing-box.service
  fi

  systemctl daemon-reload
  systemctl enable --now sing-box

  VLESS_TCP="vless://${UUID}@${VPS_IP}:${PORT_VLESS_TCP}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=chrome&pbk=${REALITY_PUBLIC}&sid=${SHORT_ID}&type=tcp#vless-reality"
  VLESS_GRPC="vless://${UUID}@${VPS_IP}:${PORT_VLESS_GRPC}?encryption=none&security=reality&sni=${SNI}&fp=chrome&pbk=${REALITY_PUBLIC}&sid=${SHORT_ID}&type=grpc&serviceName=${GRPC_SERVICE}#vless-grpc-reality"
  TROJAN="trojan://${UUID}@${VPS_IP}:${PORT_TROJAN_TCP}?security=reality&sni=${SNI}&fp=chrome&pbk=${REALITY_PUBLIC}&sid=${SHORT_ID}&type=tcp#trojan-reality"

  HY2_PASS_ENC="$(printf '%s' "${HY2_PASS}" | urlencode)"
  HY2="hy2://${HY2_PASS_ENC}@${VPS_IP}:${PORT_HY2}?insecure=1&allowInsecure=1&sni=${SNI}#hysteria2"

  HY2_OBFS_PASS_ENC="$(printf '%s' "${HY2_OBFS_PASS}" | urlencode)"
  HY2_OBFS="hy2://${HY2_PASS_ENC}@${VPS_IP}:${PORT_HY2_OBFS}?insecure=1&allowInsecure=1&sni=${SNI}&alpn=h3&obfs=salamander&obfs-password=${HY2_OBFS_PASS_ENC}#hysteria2-obfs"

  VMESS_JSON="$(python3 - <<PY
import json
print(json.dumps({
  "v":"2","ps":"vmess-ws","add":"${VPS_IP}","port":"${PORT_VMESS_WS}",
  "id":"${UUID}","aid":"0","net":"ws","type":"none","host":"",
  "path":"${WS_PATH}","tls":""
}, separators=(',',':')))
PY
)"
  VMESS="vmess://$(printf '%s' "${VMESS_JSON}" | base64 -w 0 2>/dev/null || printf '%s' "${VMESS_JSON}" | base64 | tr -d '\n')"

  SS2022_USERINFO="$(printf '%s' "2022-blake3-aes-256-gcm:${SS2022_PASS}" | b64url_nopad)"
  SS2022="ss://${SS2022_USERINFO}@${VPS_IP}:${PORT_SS2022}#ss2022"

  SS_USERINFO="$(printf '%s' "aes-256-gcm:${SS_PASS}" | b64url_nopad)"
  SS="ss://${SS_USERINFO}@${VPS_IP}:${PORT_SS}#ss"

  TUIC="tuic://${UUID}:${UUID}@${VPS_IP}:${PORT_TUIC}?congestion_control=bbr&alpn=h3&insecure=1&allowInsecure=1&sni=${SNI}#tuic-v5"

  SUB_PLAIN="$(cat <<EOF
${VLESS_TCP}
${VLESS_GRPC}
${TROJAN}
${HY2}
${HY2_OBFS}
${VMESS}
${SS2022}
${SS}
${TUIC}
EOF
)"
  SUB_B64="$(printf '%s' "${SUB_PLAIN}" | base64 -w 0 2>/dev/null || printf '%s' "${SUB_PLAIN}" | base64 | tr -d '\n')"

  OWNER="$(curl -fsSL -H "Authorization: Bearer ${GH_TOKEN}" -H "Accept: application/vnd.github+json" \
    "https://api.github.com/gists/${GIST_ID}" | jq -r '.owner.login')"
  [[ -n "${OWNER}" && "${OWNER}" != "null" ]] || { echo "Token permission issue or wrong GIST_ID."; exit 1; }

  jq -n --arg content "${SUB_B64}" '{files: {"sub.txt": {content: $content}}}' >/tmp/gist_patch.json
  curl -fsSL -X PATCH \
    -H "Authorization: Bearer ${GH_TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/gists/${GIST_ID}" \
    -d @/tmp/gist_patch.json >/dev/null

  echo
  echo "OK. Subscription URL (open your gist and click Raw to copy):"
  echo "https://gist.githubusercontent.com/${OWNER}/${GIST_ID}/raw/sub.txt"
}

main
