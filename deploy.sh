#!/usr/bin/env bash
set -Eeuo pipefail

SB_DIR="/opt/sing-box"
BIN="/usr/local/bin/sing-box"
CONF_JSON="${SB_DIR}/config.json"
DATA_DIR="${SB_DIR}/data"
CREDS_ENV="${SB_DIR}/creds.env"
SUB_LOCAL_B64="${SB_DIR}/sub.txt"
SUB_LOCAL_PLAIN="${SB_DIR}/sub_plain.txt"
SUB_ENV="${SB_DIR}/sub_urls.env"
SERVICE="sing-box.service"

SS_METHOD="aes-256-gcm"
REALITY_SNI="${REALITY_SNI:-www.microsoft.com}"

log(){ echo "[deploy] $*"; }
warn(){ echo "[deploy][WARN] $*"; }
die(){ echo "[deploy][ERROR] $*" >&2; exit 1; }
has(){ command -v "$1" >/dev/null 2>&1; }

require_root(){ [[ ${EUID:-$(id -u)} -eq 0 ]] || die "请用 root 运行（sudo -i）"; }

apt_install(){
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y --no-install-recommends "$@" >/dev/null 2>&1 || true
}

ensure_deps(){
  has apt-get || die "当前脚本按 Debian/Ubuntu 编写（需要 apt-get）"
  apt_install ca-certificates curl jq openssl tar unzip iproute2 iptables uuid-runtime netfilter-persistent
  has curl || die "curl 未安装"
  has jq   || die "jq 未安装"
  has openssl || die "openssl 未安装"
}

b64_nw(){ if base64 --help 2>/dev/null | grep -q -- "-w"; then base64 -w 0; else base64 | tr -d '\n'; fi; }

rand_port(){
  local p
  while :; do
    p=$((20000 + ( ( $(od -An -N2 -tu2 /dev/urandom | tr -d ' ') ) % 40000 )))
    ss -lntup 2>/dev/null | grep -q ":$p " || { echo "$p"; return; }
  done
}

get_ip(){
  local ip=""
  ip="$(curl -4fsS https://api.ipify.org 2>/dev/null || true)"
  [[ -z "$ip" ]] && ip="$(curl -4fsS https://ip.sb 2>/dev/null || true)"
  [[ -z "$ip" ]] && ip="$(curl -4fsS ipv4.icanhazip.com 2>/dev/null || true)"
  echo "${ip:-127.0.0.1}"
}

install_singbox(){
  if [[ -x "$BIN" ]]; then
    log "检测到 sing-box：$("$BIN" version | head -n1)"
    return 0
  fi

  log "下载 sing-box（amd64/arm64 自动识别）..."
  local arch api re url tmp pkg

  case "$(uname -m)" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) die "不支持的架构：$(uname -m)" ;;
  esac

  api="https://api.github.com/repos/SagerNet/sing-box/releases/latest"
  re="^sing-box-.*-linux-${arch}\\.(tar\\.(gz|xz)|zip)$"
  url="$(curl -fsSL "$api" | jq -r --arg re "$re" '.assets[] | select(.name|test($re)) | .browser_download_url' | head -n1)"
  [[ -n "$url" && "$url" != "null" ]] || die "获取 sing-box 下载地址失败"

  tmp="$(mktemp -d)"
  pkg="$tmp/pkg"
  curl -fL "$url" -o "$pkg" >/dev/null

  if echo "$url" | grep -qE '\.tar\.gz$|\.tgz$'; then
    tar -xzf "$pkg" -C "$tmp"
  elif echo "$url" | grep -qE '\.tar\.xz$'; then
    tar -xJf "$pkg" -C "$tmp"
  elif echo "$url" | grep -qE '\.zip$'; then
    unzip -q "$pkg" -d "$tmp"
  else
    rm -rf "$tmp"; die "未知包格式：$url"
  fi

  local sb
  sb="$(find "$tmp" -type f -name sing-box | head -n1)"
  [[ -n "$sb" ]] || { rm -rf "$tmp"; die "包内未找到 sing-box 可执行文件"; }

  install -m 0755 "$sb" "$BIN"
  rm -rf "$tmp"
  log "安装完成：$("$BIN" version | head -n1)"
}

enable_bbr(){
  mkdir -p /etc/sysctl.d
  cat >/etc/sysctl.d/99-bbr.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
  sysctl --system >/dev/null 2>&1 || true
  if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
    log "BBR 已启用"
  else
    warn "BBR 未启用（可能内核不支持）；不影响节点可用性"
  fi
}

rand_hex8(){ openssl rand -hex 8 | tr -d '\n'; }
gen_uuid(){ if command -v uuidgen >/dev/null 2>&1; then uuidgen; else cat /proc/sys/kernel/random/uuid; fi; }
gen_reality_keypair(){ "$BIN" generate reality-keypair; }

save_creds(){
  cat >"$CREDS_ENV" <<EOF
UUID=$UUID
SS1_PORT=$SS1_PORT
SS1_PASSWORD=$(printf '%q' "$SS1_PASSWORD")
SS2_PORT=$SS2_PORT
SS2_PASSWORD=$(printf '%q' "$SS2_PASSWORD")
VLESS_VISION_PORT=$VLESS_VISION_PORT
VLESS_PLAIN_PORT=$VLESS_PLAIN_PORT
TROJAN_PORT=$TROJAN_PORT
REALITY_PRIV=$(printf '%q' "$REALITY_PRIV")
REALITY_PUB=$(printf '%q' "$REALITY_PUB")
REALITY_SID=$REALITY_SID
REALITY_SNI=$REALITY_SNI
EOF
}

load_creds_if_any(){
  [[ -f "$CREDS_ENV" ]] || return 0
  # shellcheck disable=SC1090
  source "$CREDS_ENV" || true
}

write_config(){
  mkdir -p "$SB_DIR" "$DATA_DIR"
  load_creds_if_any

  : "${UUID:=$(gen_uuid)}"
  : "${SS1_PORT:=$(rand_port)}"
  : "${SS2_PORT:=$(rand_port)}"
  : "${VLESS_VISION_PORT:=$(rand_port)}"
  : "${VLESS_PLAIN_PORT:=$(rand_port)}"
  : "${TROJAN_PORT:=$(rand_port)}"

  : "${SS1_PASSWORD:=$(openssl rand -base64 24 | tr -d '\n')}"
  : "${SS2_PASSWORD:=$(openssl rand -base64 24 | tr -d '\n')}"

  if [[ -z "${REALITY_PRIV:-}" || -z "${REALITY_PUB:-}" ]]; then
    mapfile -t RKP < <(gen_reality_keypair)
    REALITY_PRIV="$(printf "%s\n" "${RKP[@]}" | awk '/PrivateKey/{print $2}')"
    REALITY_PUB="$(printf "%s\n" "${RKP[@]}" | awk '/PublicKey/{print $2}')"
  fi
  : "${REALITY_SID:=$(rand_hex8)}"

  save_creds

  jq -n \
    --arg uuid "$UUID" \
    --arg ss_method "$SS_METHOD" \
    --arg ss1_pass "$SS1_PASSWORD" \
    --arg ss2_pass "$SS2_PASSWORD" \
    --arg sni "$REALITY_SNI" \
    --arg rpriv "$REALITY_PRIV" \
    --arg sid "$REALITY_SID" \
    --argjson ss1_port "$SS1_PORT" \
    --argjson ss2_port "$SS2_PORT" \
    --argjson vless_vision_port "$VLESS_VISION_PORT" \
    --argjson vless_plain_port "$VLESS_PLAIN_PORT" \
    --argjson trojan_port "$TROJAN_PORT" \
    '{
      log:{level:"info",timestamp:true},
      inbounds:[
        {type:"shadowsocks", tag:"ss1", listen:"0.0.0.0", listen_port:$ss1_port, method:$ss_method, password:$ss1_pass},
        {type:"shadowsocks", tag:"ss2", listen:"0.0.0.0", listen_port:$ss2_port, method:$ss_method, password:$ss2_pass},

        {
          type:"vless", tag:"vless-vision", listen:"0.0.0.0", listen_port:$vless_vision_port,
          users:[{uuid:$uuid, flow:"xtls-rprx-vision"}],
          tls:{enabled:true, server_name:$sni,
            reality:{enabled:true, handshake:{server:$sni, server_port:443}, private_key:$rpriv, short_id:[$sid]}
          }
        },
        {
          type:"vless", tag:"vless", listen:"0.0.0.0", listen_port:$vless_plain_port,
          users:[{uuid:$uuid}],
          tls:{enabled:true, server_name:$sni,
            reality:{enabled:true, handshake:{server:$sni, server_port:443}, private_key:$rpriv, short_id:[$sid]}
          }
        },
        {
          type:"trojan", tag:"trojan", listen:"0.0.0.0", listen_port:$trojan_port,
          users:[{password:$uuid}],
          tls:{enabled:true, server_name:$sni,
            reality:{enabled:true, handshake:{server:$sni, server_port:443}, private_key:$rpriv, short_id:[$sid]}
          }
        }
      ],
      outbounds:[{type:"direct",tag:"direct"}],
      route:{final:"direct"}
    }' >"$CONF_JSON"

  "$BIN" check -c "$CONF_JSON" >/dev/null
  log "配置已写入：$CONF_JSON"
}

write_systemd(){
  cat >/etc/systemd/system/$SERVICE <<EOF
[Unit]
Description=sing-box
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN run -c $CONF_JSON -D $DATA_DIR
Restart=on-failure
RestartSec=2
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable "$SERVICE" >/dev/null 2>&1 || true
  systemctl restart "$SERVICE" >/dev/null 2>&1 || true
  systemctl is-active --quiet "$SERVICE" || die "服务未启动成功：systemctl status $SERVICE"
  log "服务状态：active"
}

open_firewall(){
  load_creds_if_any
  local tcp_ports=("$SS1_PORT" "$SS2_PORT" "$VLESS_VISION_PORT" "$VLESS_PLAIN_PORT" "$TROJAN_PORT")
  local udp_ports=("$SS1_PORT" "$SS2_PORT")

  for p in "${tcp_ports[@]}"; do
    iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "$p" -j ACCEPT
  done
  for p in "${udp_ports[@]}"; do
    iptables -C INPUT -p udp --dport "$p" -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport "$p" -j ACCEPT
  done

  if has netfilter-persistent; then netfilter-persistent save >/dev/null 2>&1 || true; fi

  log "已放行 TCP 端口：${tcp_ports[*]}（SS 额外放行 UDP：${udp_ports[*]}）"
  warn "如使用云厂商安全组（Vultr 面板），还需在控制台放行这些端口"
}

make_links(){
  load_creds_if_any
  local ip; ip="$(get_ip)"

  local ss1_user ss2_user
  ss1_user="$(printf "%s:%s" "$SS_METHOD" "$SS1_PASSWORD" | b64_nw)"
  ss2_user="$(printf "%s:%s" "$SS_METHOD" "$SS2_PASSWORD" | b64_nw)"

  echo "ss://${ss1_user}@${ip}:${SS1_PORT}#ss1"
  echo "ss://${ss2_user}@${ip}:${SS2_PORT}#ss2"
  echo "vless://${UUID}@${ip}:${VLESS_VISION_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#vless-reality-vision"
  echo "vless://${UUID}@${ip}:${VLESS_PLAIN_PORT}?encryption=none&security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#vless-reality"
  echo "trojan://${UUID}@${ip}:${TROJAN_PORT}?security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}&type=tcp#trojan-reality"
}

write_local_subscription_files(){
  local plain b64
  plain="$(make_links)"$'\n'
  printf "%s" "$plain" >"$SUB_LOCAL_PLAIN"
  b64="$(printf "%s" "$plain" | b64_nw)"
  printf "%s" "$b64" >"$SUB_LOCAL_B64"
  log "已生成本地订阅文件：$SUB_LOCAL_B64（base64） / $SUB_LOCAL_PLAIN（明文）"
}

self_test_ss_loopback(){
  load_creds_if_any
  local test_cfg="/tmp/sb-test.json"
  local socks_port="10808"

  cat >"$test_cfg" <<EOF
{
  "log":{"level":"error"},
  "inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":${socks_port}}],
  "outbounds":[
    {"type":"shadowsocks","tag":"ss","server":"127.0.0.1","server_port":${SS1_PORT},"method":"${SS_METHOD}","password":"${SS1_PASSWORD}"},
    {"type":"direct","tag":"direct"}
  ],
  "route":{"final":"ss"}
}
EOF

  "$BIN" check -c "$test_cfg" >/dev/null 2>&1 || { warn "自测配置检查失败"; return 0; }
  "$BIN" run -c "$test_cfg" >/tmp/sb-test.log 2>&1 &
  local pid=$!
  sleep 0.8

  if curl -fsS --socks5-hostname "127.0.0.1:${socks_port}" https://www.cloudflare.com/cdn-cgi/trace >/dev/null 2>&1; then
    log "自测通过：SS1 工作正常（本机回环 OK）"
  else
    warn "自测失败：请看 /tmp/sb-test.log 以及 systemctl status ${SERVICE}"
  fi

  kill "$pid" >/dev/null 2>&1 || true
  rm -f "$test_cfg" >/dev/null 2>&1 || true
}

update_gist_subscription_if_needed(){
  [[ -n "${GIST_ID:-}" && -n "${GH_TOKEN:-}" ]] || return 0

  write_local_subscription_files

  local sub_b64 plain payload resp code raw_b64 raw_plain
  sub_b64="$(cat "$SUB_LOCAL_B64")"
  plain="$(cat "$SUB_LOCAL_PLAIN")"

  payload="$(jq -n --arg sub_b64 "$sub_b64" --arg plain "$plain" '{
    files:{
      "sub.txt":{content:$sub_b64},
      "sub_plain.txt":{content:$plain}
    }
  }')"

  resp="$(mktemp)"
  # 关键修复：Authorization 头不要带多余引号
  code="$(curl -sS -o "$resp" -w "%{http_code}" \
    -X PATCH \
    -H "Authorization: Bearer ${GH_TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/gists/${GIST_ID}" \
    -d "$payload" || true)"

  if [[ "$code" != "200" ]]; then
    warn "Gist 更新失败（HTTP $code）。通常是 token 没有 gist 写权限 / GIST_ID 不对 / token 失效"
    rm -f "$resp"
    return 0
  fi

  raw_b64="$(jq -r '.files["sub.txt"].raw_url' <"$resp")"
  raw_plain="$(jq -r '.files["sub_plain.txt"].raw_url' <"$resp")"
  rm -f "$resp"

  cat >"$SUB_ENV" <<EOF
SUB_B64_URL=$raw_b64
SUB_PLAIN_URL=$raw_plain
EOF

  log "Gist 订阅更新成功："
  echo "  BASE64订阅：$raw_b64"
  echo "  明文订阅：  $raw_plain"
}

main(){
  require_root
  ensure_deps
  enable_bbr
  install_singbox
  write_config
  write_systemd
  open_firewall

  echo
  echo "==== 节点链接（5 个：2SS + 2VLESS + 1Trojan）===="
  make_links
  echo

  write_local_subscription_files
  self_test_ss_loopback
  update_gist_subscription_if_needed || true

  log "完成"
}

main "$@"
