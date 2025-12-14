#!/usr/bin/env bash
set -Eeuo pipefail

DEPLOY_URL="${DEPLOY_URL:-https://raw.githubusercontent.com/lvfuq/vps-deploy/main/deploy.sh}"

SB_DIR="/opt/sing-box"
PORTS_ENV="${SB_DIR}/ports.env"
CREDS_ENV="${SB_DIR}/creds.env"
WARP_ENV="${SB_DIR}/warp.env"

REALITY_SERVER="${REALITY_SERVER:-www.microsoft.com}"
GRPC_SERVICE="${GRPC_SERVICE:-grpc}"
VMESS_WS_PATH="${VMESS_WS_PATH:-/vm}"

need_root(){ [ "${EUID:-0}" -eq 0 ] || { echo "ERROR: 请用 root 执行"; exit 1; }; }

b64enc(){ base64 -w0 2>/dev/null || base64; }

urlenc(){ python3 - <<'PY' "$1"
import sys,urllib.parse
print(urllib.parse.quote(sys.argv[1], safe=""))
PY
}

get_ip(){
  local ip
  ip="$(curl -fsSL https://api.ipify.org || true)"
  [ -n "${ip}" ] || ip="$(curl -fsSL ipv4.icanhazip.com || true)"
  echo "${ip:-127.0.0.1}"
}

# ====== 执行部署 ======
need_root
if [ -z "${GIST_ID:-}" ] || [ -z "${GH_TOKEN:-}" ]; then
  echo "ERROR: 需要在同一行命令里提供 GIST_ID 和 GH_TOKEN（仅 gist 权限）"
  echo '示例：GIST_ID=xxxx GH_TOKEN=yyyy bash <(curl -fsSL https://raw.githubusercontent.com/lvfuq/vps-deploy/main/run.sh)'
  exit 1
fi

tmp="$(mktemp -d)"
curl -fsSL "${DEPLOY_URL}" -o "${tmp}/deploy.sh"
chmod +x "${tmp}/deploy.sh"
bash "${tmp}/deploy.sh"
rm -rf "${tmp}"

# ====== 读取落盘参数 ======
set +u
source "${CREDS_ENV}"
source "${PORTS_ENV}"
[ -f "${WARP_ENV}" ] && source "${WARP_ENV}" || true
set -u

ip="$(get_ip)"

# ====== 生成链接（18 个）=====
VMESS_JSON=$(cat <<JSON
{"v":"2","ps":"vmess-ws","add":"${ip}","port":"${PORT_VMESS_WS}","id":"${UUID}","aid":"0","net":"ws","type":"none","host":"","path":"${VMESS_WS_PATH}","tls":""}
JSON
)
VMESS_JSON_W=$(cat <<JSON
{"v":"2","ps":"vmess-ws-warp","add":"${ip}","port":"${PORT_VMESS_WS_W}","id":"${UUID}","aid":"0","net":"ws","type":"none","host":"","path":"${VMESS_WS_PATH}","tls":""}
JSON
)

links=()
links+=("vless://${UUID}@${ip}:${PORT_VLESSR}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#vless-reality")
links+=("vless://${UUID}@${ip}:${PORT_VLESS_GRPCR}?encryption=none&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=grpc&serviceName=${GRPC_SERVICE}#vless-grpc-reality")
links+=("trojan://${UUID}@${ip}:${PORT_TROJANR}?security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#trojan-reality")
links+=("hy2://$(urlenc "${HY2_PWD}")@${ip}:${PORT_HY2}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}#hysteria2")
links+=("vmess://$(printf "%s" "${VMESS_JSON}" | b64enc)")
links+=("hy2://$(urlenc "${HY2_PWD2}")@${ip}:${PORT_HY2_OBFS}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}&alpn=h3&obfs=salamander&obfs-password=$(urlenc "${HY2_OBFS_PWD}")#hysteria2-obfs")
links+=("ss://$(printf "%s" "2022-blake3-aes-256-gcm:${SS2022_KEY}" | b64enc)@${ip}:${PORT_SS2022}#ss2022")
links+=("ss://$(printf "%s" "aes-256-gcm:${SS_PWD}" | b64enc)@${ip}:${PORT_SS}#ss")
links+=("tuic://${UUID}:$(urlenc "${UUID}")@${ip}:${PORT_TUIC}?congestion_control=bbr&alpn=h3&insecure=1&allowInsecure=1&sni=${REALITY_SERVER}#tuic-v5")

links+=("vless://${UUID}@${ip}:${PORT_VLESSR_W}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#vless-reality-warp")
links+=("vless://${UUID}@${ip}:${PORT_VLESS_GRPCR_W}?encryption=none&security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=grpc&serviceName=${GRPC_SERVICE}#vless-grpc-reality-warp")
links+=("trojan://${UUID}@${ip}:${PORT_TROJANR_W}?security=reality&sni=${REALITY_SERVER}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#trojan-reality-warp")
links+=("hy2://$(urlenc "${HY2_PWD}")@${ip}:${PORT_HY2_W}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}#hysteria2-warp")
links+=("vmess://$(printf "%s" "${VMESS_JSON_W}" | b64enc)")
links+=("hy2://$(urlenc "${HY2_PWD2}")@${ip}:${PORT_HY2_OBFS_W}?insecure=1&allowInsecure=1&sni=${REALITY_SERVER}&alpn=h3&obfs=salamander&obfs-password=$(urlenc "${HY2_OBFS_PWD}")#hysteria2-obfs-warp")
links+=("ss://$(printf "%s" "2022-blake3-aes-256-gcm:${SS2022_KEY}" | b64enc)@${ip}:${PORT_SS2022_W}#ss2022-warp")
links+=("ss://$(printf "%s" "aes-256-gcm:${SS_PWD}" | b64enc)@${ip}:${PORT_SS_W}#ss-warp")
links+=("tuic://${UUID}:$(urlenc "${UUID}")@${ip}:${PORT_TUIC_W}?congestion_control=bbr&alpn=h3&insecure=1&allowInsecure=1&sni=${REALITY_SERVER}#tuic-v5-warp")

# ====== 自检：服务 + 端口监听 ======
echo "==== sing-box 状态 ===="
systemctl is-active sing-box.service || true
echo

echo "==== 监听端口（只看 sing-box）===="
ss -lntup | grep sing-box || true
ss -lnu  | grep sing-box || true
echo

echo "==== 节点链接（18 个）===="
for l in "${links[@]}"; do
  echo "${l}"
done
echo

# ====== 更新 Gist 订阅（不打印订阅 URL）=====
sub_content="$(printf "%s\n" "${links[@]}")"
payload="$(jq -n --arg c "$sub_content" '{files: {"sub.txt": {content:$c}}}')"
curl -fsSL -X PATCH \
  -H "Authorization: token '"${GH_TOKEN}"'" \
  -H "Accept: application/vnd.github+json" \
  -d "$payload" \
  "https://api.github.com/gists/${GIST_ID}" >/dev/null

echo "==== 订阅已更新到 Gist（未打印订阅链接）===="
