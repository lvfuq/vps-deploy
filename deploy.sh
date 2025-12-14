#!/usr/bin/env bash
set -Eeuo pipefail

# ====== 基本参数（按 SBP 风格固定路径） ======
SB_DIR="/opt/sing-box"
CONF_JSON="${SB_DIR}/config.json"
DATA_DIR="${SB_DIR}/data"
CERT_DIR="${SB_DIR}/cert"
PORTS_ENV="${SB_DIR}/ports.env"
CREDS_ENV="${SB_DIR}/creds.env"
WARP_ENV="${SB_DIR}/warp.env"
BIN_PATH="/usr/local/bin/sing-box"
SYSTEMD_SERVICE="sing-box.service"

REALITY_SERVER="${REALITY_SERVER:-www.microsoft.com}"
REALITY_SERVER_PORT="${REALITY_SERVER_PORT:-443}"
GRPC_SERVICE="${GRPC_SERVICE:-grpc}"
VMESS_WS_PATH="${VMESS_WS_PATH:-/vm}"
ENABLE_WARP="${ENABLE_WARP:-true}"   # 尝试启用；失败自动降级为不启用

need_root() { [ "${EUID:-0}" -eq 0 ] || { echo "ERROR: 请用 root 执行"; exit 1; }; }
log() { echo "[deploy] $*"; }

apt_deps() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y --no-install-recommends \
    ca-certificates curl jq openssl uuid-runtime tar unzip iproute2 iptables >/dev/null 2>&1
}

arch_map() {
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    armv7l|armv7) echo "armv7" ;;
    i386|i686) echo "386" ;;
    *) echo "amd64" ;;
  esac
}

gh_api() {
  # 若提供 GH_TOKEN，顺便用它避免 GitHub API rate limit；否则匿名请求
  if [ -n "${GH_TOKEN:-}" ]; then
    curl -fsSL -H "Authorization: token ${GH_TOKEN}" -H "Accept: application/vnd.github+json" "$@"
  else
    curl -fsSL -H "Accept: application/vnd.github+json" "$@"
  fi
}

install_singbox() {
  if command -v "${BIN_PATH}" >/dev/null 2>&1; then
    log "sing-box 已存在：$(${BIN_PATH} version | head -n1)"
    return 0
  fi

  local arch re url tmp pkg
  arch="$(arch_map)"
  re="^sing-box-.*-linux-${arch}\\.(tar\\.(gz|xz)|zip)$"

  log "下载 sing-box (${arch}) ..."
  url="$(gh_api "https://api.github.com/repos/SagerNet/sing-box/releases/latest" \
    | jq -r --arg re "$re" '.assets[] | select(.name|test($re)) | .browser_download_url' | head -n1)"

  [ -n "${url}" ] || { echo "ERROR: 未匹配到 sing-box release 资产"; exit 1; }

  tmp="$(mktemp -d)"
  pkg="${tmp}/pkg"
  curl -fL "${url}" -o "${pkg}"

  if echo "${url}" | grep -qE '\.tar\.gz$|\.tgz$'; then
    tar -xzf "${pkg}" -C "${tmp}"
  elif echo "${url}" | grep -qE '\.tar\.xz$'; then
    tar -xJf "${pkg}" -C "${tmp}"
  elif echo "${url}" | grep -qE '\.zip$'; then
    unzip -q "${pkg}" -d "${tmp}"
  else
    echo "ERROR: 未知包格式：${url}"
    exit 1
  fi

  local bin
  bin="$(find "${tmp}" -type f -name sing-box | head -n1)"
  [ -n "${bin}" ] || { echo "ERROR: 解压后找不到 sing-box"; exit 1; }

  install -m 0755 "${bin}" "${BIN_PATH}"
  rm -rf "${tmp}"
  log "安装完成：$(${BIN_PATH} version | head -n1)"
}

ensure_dirs() {
  mkdir -p "${SB_DIR}" "${DATA_DIR}" "${CERT_DIR}"
}

mk_cert() {
  local crt="${CERT_DIR}/fullchain.pem" key="${CERT_DIR}/key.pem"
  if [ ! -s "${crt}" ] || [ ! -s "${key}" ]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 3650 -nodes \
      -keyout "${key}" -out "${crt}" -subj "/CN=${REALITY_SERVER}" \
      -addext "subjectAltName=DNS:${REALITY_SERVER}" >/dev/null 2>&1
  fi
}

rand_hex8() { openssl rand -hex 8 | tr -d "\n"; }
rand_b64_32() { openssl rand -base64 32 | tr -d "\n"; }
gen_uuid() { cat /proc/sys/kernel/random/uuid | head -n1 | tr -d "\r\n"; }

save_env_file() {
  cat >"${CREDS_ENV}" <<EOF
UUID=${UUID}
HY2_PWD=${HY2_PWD}
HY2_PWD2=${HY2_PWD2}
HY2_OBFS_PWD=${HY2_OBFS_PWD}
REALITY_PRIV=${REALITY_PRIV}
REALITY_PUB=${REALITY_PUB}
REALITY_SID=${REALITY_SID}
SS2022_KEY=${SS2022_KEY}
SS_PWD=${SS_PWD}
EOF
}

load_env_file() {
  [ -f "${CREDS_ENV}" ] && set +u && source "${CREDS_ENV}" && set -u || true
}

gen_reality() {
  # 输出形如：
  # PrivateKey: xxx
  # PublicKey:  xxx
  local out priv pub
  out="$(${BIN_PATH} generate reality-keypair)"
  priv="$(echo "$out" | awk '/PrivateKey/{print $2}')"
  pub="$(echo "$out"  | awk '/PublicKey/{print $2}')"
  echo "${priv}|${pub}"
}

ensure_creds() {
  load_env_file

  UUID="${UUID:-$(gen_uuid)}"
  HY2_PWD="${HY2_PWD:-$(rand_b64_32)}"
  HY2_PWD2="${HY2_PWD2:-$(rand_b64_32)}"
  HY2_OBFS_PWD="${HY2_OBFS_PWD:-$(openssl rand -base64 16 | tr -d "\n")}"
  SS2022_KEY="${SS2022_KEY:-$(rand_b64_32)}"
  # SS 密码：纯字符串即可；为兼容各种导入器，尽量用 URL-safe 字符
  SS_PWD="${SS_PWD:-$(openssl rand -base64 24 | tr -d "=\n" | tr "+/" "-_")}"

  if [ -z "${REALITY_PRIV:-}" ] || [ -z "${REALITY_PUB:-}" ] || [ -z "${REALITY_SID:-}" ]; then
    IFS="|" read -r REALITY_PRIV REALITY_PUB < <(gen_reality)
    REALITY_SID="$(rand_hex8)"
  fi

  save_env_file
}

# ===== 端口：18 个（直连 9 + WARP 9） =====
PORTS=()
gen_port() {
  while :; do
    local p=$(( (RANDOM % 55536) + 10000 ))
    [[ " ${PORTS[*]-} " != *" ${p} "* ]] && { PORTS+=("${p}"); echo "${p}"; return; }
  done
}

save_ports() {
  cat >"${PORTS_ENV}" <<EOF
PORT_VLESSR=${PORT_VLESSR}
PORT_VLESS_GRPCR=${PORT_VLESS_GRPCR}
PORT_TROJANR=${PORT_TROJANR}
PORT_HY2=${PORT_HY2}
PORT_VMESS_WS=${PORT_VMESS_WS}
PORT_HY2_OBFS=${PORT_HY2_OBFS}
PORT_SS2022=${PORT_SS2022}
PORT_SS=${PORT_SS}
PORT_TUIC=${PORT_TUIC}
PORT_VLESSR_W=${PORT_VLESSR_W}
PORT_VLESS_GRPCR_W=${PORT_VLESS_GRPCR_W}
PORT_TROJANR_W=${PORT_TROJANR_W}
PORT_HY2_W=${PORT_HY2_W}
PORT_VMESS_WS_W=${PORT_VMESS_WS_W}
PORT_HY2_OBFS_W=${PORT_HY2_OBFS_W}
PORT_SS2022_W=${PORT_SS2022_W}
PORT_SS_W=${PORT_SS_W}
PORT_TUIC_W=${PORT_TUIC_W}
EOF
}

load_ports() {
  [ -f "${PORTS_ENV}" ] && set +u && source "${PORTS_ENV}" && set -u || true
}

ensure_ports() {
  load_ports
  # 如果不存在就生成；存在就复用（保证同一台机器重跑不变）
  : "${PORT_VLESSR:=$(gen_port)}"
  : "${PORT_VLESS_GRPCR:=$(gen_port)}"
  : "${PORT_TROJANR:=$(gen_port)}"
  : "${PORT_HY2:=$(gen_port)}"
  : "${PORT_VMESS_WS:=$(gen_port)}"
  : "${PORT_HY2_OBFS:=$(gen_port)}"
  : "${PORT_SS2022:=$(gen_port)}"
  : "${PORT_SS:=$(gen_port)}"
  : "${PORT_TUIC:=$(gen_port)}"

  : "${PORT_VLESSR_W:=$(gen_port)}"
  : "${PORT_VLESS_GRPCR_W:=$(gen_port)}"
  : "${PORT_TROJANR_W:=$(gen_port)}"
  : "${PORT_HY2_W:=$(gen_port)}"
  : "${PORT_VMESS_WS_W:=$(gen_port)}"
  : "${PORT_HY2_OBFS_W:=$(gen_port)}"
  : "${PORT_SS2022_W:=$(gen_port)}"
  : "${PORT_SS_W:=$(gen_port)}"
  : "${PORT_TUIC_W:=$(gen_port)}"

  save_ports
}

# ===== WARP：尽力生成，失败就禁用 =====
pad_b64() {
  local s="${1:-}"
  s="$(printf '%s' "$s" | tr -d '\r\n\" ')"
  s="${s%%=*}"
  local rem=$(( ${#s} % 4 ))
  if   (( rem == 2 )); then s="${s}=="
  elif (( rem == 3 )); then s="${s}="
  fi
  printf '%s' "$s"
}

install_wgcf() {
  command -v wgcf >/dev/null 2>&1 && return 0
  local arch url tmp
  arch="$(arch_map)"
  url="$(gh_api "https://api.github.com/repos/ViRb3/wgcf/releases/latest" \
    | jq -r --arg a "${arch}" '.assets[] | select(.name|test("linux_" + $a + "$")) | .browser_download_url' | head -n1)"
  [ -n "${url}" ] || return 1
  tmp="$(mktemp -d)"
  curl -fsSL "${url}" -o "${tmp}/wgcf"
  install -m 0755 "${tmp}/wgcf" /usr/local/bin/wgcf
  rm -rf "${tmp}"
}

ensure_warp_profile() {
  [ "${ENABLE_WARP}" = "true" ] || return 0
  if [ -f "${WARP_ENV}" ]; then
    return 0
  fi

  install_wgcf || { log "wgcf 安装失败，禁用 WARP"; ENABLE_WARP=false; return 0; }

  local wd="${SB_DIR}/wgcf"; mkdir -p "${wd}"
  if [ ! -f "${wd}/wgcf-account.toml" ]; then
    wgcf register --accept-tos --config "${wd}/wgcf-account.toml" >/dev/null 2>&1 || { ENABLE_WARP=false; return 0; }
  fi
  wgcf generate --config "${wd}/wgcf-account.toml" --profile "${wd}/wgcf-profile.conf" >/dev/null 2>&1 || { ENABLE_WARP=false; return 0; }

  local prof="${wd}/wgcf-profile.conf"
  local priv pub ep host port ad rs r1 r2 r3
  priv="$(pad_b64 "$(awk -F'= *' '/^PrivateKey/{print $2; exit}' "${prof}")")"
  pub="$(pad_b64 "$(awk -F'= *' '/^PublicKey/{print $2; exit}' "${prof}")")"
  ep="$(awk -F'= *' '/^Endpoint/{print $2; exit}' "${prof}" | tr -d '" ')"
  if [[ "${ep}" =~ ^\[(.+)\]:(.+)$ ]]; then host="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[2]}"; else host="${ep%:*}"; port="${ep##*:}"; fi
  ad="$(awk -F'= *' '/^Address/{print $2; exit}' "${prof}" | tr -d '" ')"
  rs="$(awk -F'= *' '/^Reserved/{print $2; exit}' "${prof}" | tr -d '" ')"
  r1="${rs%%,*}"; rs="${rs#*,}"; r2="${rs%%,*}"; r3="${rs##*,}"

  cat >"${WARP_ENV}" <<EOF
WARP_PRIVATE_KEY=${priv}
WARP_PEER_PUBLIC_KEY=${pub}
WARP_ENDPOINT_HOST=${host}
WARP_ENDPOINT_PORT=${port}
WARP_ADDRESS_V4=${ad%%,*}
WARP_ADDRESS_V6=${ad##*,}
WARP_RESERVED_1=${r1:-0}
WARP_RESERVED_2=${r2:-0}
WARP_RESERVED_3=${r3:-0}
EOF
}

write_config() {
  # load warp env if exists
  if [ -f "${WARP_ENV}" ]; then set +u; source "${WARP_ENV}"; set -u; fi

  local CRT="${CERT_DIR}/fullchain.pem" KEY="${CERT_DIR}/key.pem"

  jq -n \
    --arg RS "${REALITY_SERVER}" --argjson RSP "${REALITY_SERVER_PORT}" \
    --arg UID "${UUID}" --arg RPR "${REALITY_PRIV}" --arg RPB "${REALITY_PUB}" --arg SID "${REALITY_SID}" \
    --arg GRPC "${GRPC_SERVICE}" --arg VMWS "${VMESS_WS_PATH}" --arg CRT "${CRT}" --arg KEY "${KEY}" \
    --arg HY2 "${HY2_PWD}" --arg HY22 "${HY2_PWD2}" --arg HY2O "${HY2_OBFS_PWD}" \
    --arg SS2022 "${SS2022_KEY}" --arg SSPWD "${SS_PWD}" \
    --argjson P1 "${PORT_VLESSR}" --argjson P2 "${PORT_VLESS_GRPCR}" --argjson P3 "${PORT_TROJANR}" \
    --argjson P4 "${PORT_HY2}" --argjson P5 "${PORT_VMESS_WS}" --argjson P6 "${PORT_HY2_OBFS}" \
    --argjson P7 "${PORT_SS2022}" --argjson P8 "${PORT_SS}" --argjson P9 "${PORT_TUIC}" \
    --argjson PW1 "${PORT_VLESSR_W}" --argjson PW2 "${PORT_VLESS_GRPCR_W}" --argjson PW3 "${PORT_TROJANR_W}" \
    --argjson PW4 "${PORT_HY2_W}" --argjson PW5 "${PORT_VMESS_WS_W}" --argjson PW6 "${PORT_HY2_OBFS_W}" \
    --argjson PW7 "${PORT_SS2022_W}" --argjson PW8 "${PORT_SS_W}" --argjson PW9 "${PORT_TUIC_W}" \
    --arg ENABLE_WARP "${ENABLE_WARP}" \
    --arg WPRIV "${WARP_PRIVATE_KEY:-}" --arg WPPUB "${WARP_PEER_PUBLIC_KEY:-}" \
    --arg WHOST "${WARP_ENDPOINT_HOST:-}" --argjson WPORT "${WARP_ENDPOINT_PORT:-0}" \
    --arg W4 "${WARP_ADDRESS_V4:-}" --arg W6 "${WARP_ADDRESS_V6:-}" \
    --argjson WR1 "${WARP_RESERVED_1:-0}" --argjson WR2 "${WARP_RESERVED_2:-0}" --argjson WR3 "${WARP_RESERVED_3:-0}" \
  '
  def inbound_vless($port): {type:"vless", listen:"0.0.0.0", listen_port:$port, users:[{uuid:$UID}],
    tls:{enabled:true, server_name:$RS, reality:{enabled:true, handshake:{server:$RS, server_port:$RSP}, private_key:$RPR, short_id:[$SID]}}};
  def inbound_vless_flow($port): {type:"vless", listen:"0.0.0.0", listen_port:$port, users:[{uuid:$UID, flow:"xtls-rprx-vision"}],
    tls:{enabled:true, server_name:$RS, reality:{enabled:true, handshake:{server:$RS, server_port:$RSP}, private_key:$RPR, short_id:[$SID]}}};
  def inbound_trojan($port): {type:"trojan", listen:"0.0.0.0", listen_port:$port, users:[{password:$UID}],
    tls:{enabled:true, server_name:$RS, reality:{enabled:true, handshake:{server:$RS, server_port:$RSP}, private_key:$RPR, short_id:[$SID]}}};
  def inbound_hy2($port): {type:"hysteria2", listen:"0.0.0.0", listen_port:$port, users:[{name:"hy2", password:$HY2}],
    tls:{enabled:true, certificate_path:$CRT, key_path:$KEY}};
  def inbound_vmess_ws($port): {type:"vmess", listen:"0.0.0.0", listen_port:$port, users:[{uuid:$UID}], transport:{type:"ws", path:$VMWS}};
  def inbound_hy2_obfs($port): {type:"hysteria2", listen:"0.0.0.0", listen_port:$port, users:[{name:"hy2", password:$HY22}],
    obfs:{type:"salamander", password:$HY2O}, tls:{enabled:true, certificate_path:$CRT, key_path:$KEY, alpn:["h3"]}};
  def inbound_ss2022($port): {type:"shadowsocks", listen:"0.0.0.0", listen_port:$port, method:"2022-blake3-aes-256-gcm", password:$SS2022};
  def inbound_ss($port): {type:"shadowsocks", listen:"0.0.0.0", listen_port:$port, method:"aes-256-gcm", password:$SSPWD};
  def inbound_tuic($port): {type:"tuic", listen:"0.0.0.0", listen_port:$port, users:[{uuid:$UID, password:$UID}],
    congestion_control:"bbr", tls:{enabled:true, certificate_path:$CRT, key_path:$KEY, alpn:["h3"]}};

  def warp_outbound:
    {type:"wireguard", tag:"warp", local_address: ( [ $W4, $W6 ] | map(select(. != "")) ), system_interface:false,
     private_key:$WPRIV, peers:[{server:$WHOST, server_port:$WPORT, public_key:$WPPUB, reserved:[$WR1,$WR2,$WR3], allowed_ips:["0.0.0.0/0","::/0"]}], mtu:1280};

  {
    log:{level:"info", timestamp:true},
    dns:{servers:[{tag:"dns-remote", address:"https://1.1.1.1/dns-query", detour:"direct"}], strategy:"prefer_ipv4"},
    inbounds:[
      (inbound_vless_flow($P1)+{tag:"vless-reality"}),
      (inbound_vless($P2)+{tag:"vless-grpc-reality", transport:{type:"grpc", service_name:$GRPC}}),
      (inbound_trojan($P3)+{tag:"trojan-reality"}),
      (inbound_hy2($P4)+{tag:"hy2"}),
      (inbound_vmess_ws($P5)+{tag:"vmess-ws"}),
      (inbound_hy2_obfs($P6)+{tag:"hy2-obfs"}),
      (inbound_ss2022($P7)+{tag:"ss2022"}),
      (inbound_ss($P8)+{tag:"ss"}),
      (inbound_tuic($P9)+{tag:"tuic-v5"}),

      (inbound_vless_flow($PW1)+{tag:"vless-reality-warp"}),
      (inbound_vless($PW2)+{tag:"vless-grpc-reality-warp", transport:{type:"grpc", service_name:$GRPC}}),
      (inbound_trojan($PW3)+{tag:"trojan-reality-warp"}),
      (inbound_hy2($PW4)+{tag:"hy2-warp"}),
      (inbound_vmess_ws($PW5)+{tag:"vmess-ws-warp"}),
      (inbound_hy2_obfs($PW6)+{tag:"hy2-obfs-warp"}),
      (inbound_ss2022($PW7)+{tag:"ss2022-warp"}),
      (inbound_ss($PW8)+{tag:"ss-warp"}),
      (inbound_tuic($PW9)+{tag:"tuic-v5-warp"})
    ],
    outbounds: (
      if $ENABLE_WARP=="true" and ($WPRIV|length)>0 and ($WHOST|length)>0 then
        [{type:"direct", tag:"direct"},{type:"block", tag:"block"}, warp_outbound]
      else
        [{type:"direct", tag:"direct"},{type:"block", tag:"block"}]
      end
    ),
    route: (
      if $ENABLE_WARP=="true" and ($WPRIV|length)>0 and ($WHOST|length)>0 then
        {rules:[{inbound:["vless-reality-warp","vless-grpc-reality-warp","trojan-reality-warp","hy2-warp","vmess-ws-warp","hy2-obfs-warp","ss2022-warp","ss-warp","tuic-v5-warp"], outbound:"warp"}], final:"direct"}
      else
        {final:"direct"}
      end
    )
  }' > "${CONF_JSON}"
}

write_systemd() {
  cat >"/etc/systemd/system/${SYSTEMD_SERVICE}" <<EOF
[Unit]
Description=sing-box
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=ENABLE_DEPRECATED_WIREGUARD_OUTBOUND=true
ExecStart=${BIN_PATH} run -c ${CONF_JSON} -D ${DATA_DIR}
Restart=on-failure
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable "${SYSTEMD_SERVICE}" >/dev/null 2>&1 || true
}

open_firewall_iptables() {
  # 只在 INPUT 链加 ACCEPT，不改变默认策略，避免把 SSH 锁死
  local rules=(
    "${PORT_VLESSR}/tcp" "${PORT_VLESS_GRPCR}/tcp" "${PORT_TROJANR}/tcp" "${PORT_VMESS_WS}/tcp"
    "${PORT_HY2}/udp" "${PORT_HY2_OBFS}/udp" "${PORT_TUIC}/udp"
    "${PORT_SS2022}/tcp" "${PORT_SS2022}/udp" "${PORT_SS}/tcp" "${PORT_SS}/udp"
    "${PORT_VLESSR_W}/tcp" "${PORT_VLESS_GRPCR_W}/tcp" "${PORT_TROJANR_W}/tcp" "${PORT_VMESS_WS_W}/tcp"
    "${PORT_HY2_W}/udp" "${PORT_HY2_OBFS_W}/udp" "${PORT_TUIC_W}/udp"
    "${PORT_SS2022_W}/tcp" "${PORT_SS2022_W}/udp" "${PORT_SS_W}/tcp" "${PORT_SS_W}/udp"
  )
  local r p proto
  for r in "${rules[@]}"; do
    p="${r%/*}"; proto="${r#*/}"
    iptables -C INPUT -p "${proto}" --dport "${p}" -j ACCEPT 2>/dev/null || iptables -I INPUT -p "${proto}" --dport "${p}" -j ACCEPT
  done
}

self_check() {
  log "检查配置合法性 ..."
  ENABLE_DEPRECATED_WIREGUARD_OUTBOUND=true "${BIN_PATH}" check -c "${CONF_JSON}"

  log "重启服务 ..."
  systemctl restart "${SYSTEMD_SERVICE}"

  log "服务状态：$(systemctl is-active ${SYSTEMD_SERVICE} || true)"
}

# ===== Gist 更新（不打印订阅链接）=====
update_gist_subscription() {
  [ -n "${GIST_ID:-}" ] || return 0
  [ -n "${GH_TOKEN:-}" ] || return 0

  # 订阅内容由 run.sh 生成更合适；这里仅占位，run.sh 会再次 PATCH。
  # 保留该函数是为了“deploy 单独运行也能更新”。
  :
}

main() {
  need_root
  apt_deps
  ensure_dirs
  install_singbox
  mk_cert
  ensure_creds
  ensure_ports
  ensure_warp_profile
  write_config
  write_systemd
  open_firewall_iptables
  self_check
  update_gist_subscription
  log "deploy 完成（未打印订阅链接）"
}

main "$@"
