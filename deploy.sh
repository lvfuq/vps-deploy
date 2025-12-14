#!/usr/bin/env bash
set -Eeuo pipefail

log(){ echo "[deploy] $*"; }
die(){ echo "[deploy][ERROR] $*" >&2; exit 1; }

require_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "请用 root 运行（或 sudo -i 后再执行）"
}

need_cmd() { command -v "$1" >/dev/null 2>&1; }

apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y >/dev/null 2>&1 || true
  apt-get install -y --no-install-recommends "$@" >/dev/null 2>&1 || true
}

ensure_base_deps() {
  if ! need_cmd apt-get; then die "当前脚本仅按 Debian/Ubuntu 的 apt-get 写（你说你是 Debian）"; fi
  apt_install ca-certificates curl wget jq openssl iproute2 coreutils python3
  need_cmd curl || die "curl 未安装"
  need_cmd jq   || die "jq 未安装"
}

enable_bbr_and_tune() {
  log "开启 BBR + 保守 TCP 优化（不换内核、不要求重启）..."
  modprobe tcp_bbr >/dev/null 2>&1 || true
  cat >/etc/sysctl.d/99-vps-tune.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr

# 保守优化（一般不会“越调越慢”）
net.core.somaxconn=8192
net.core.netdev_max_backlog=16384
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_mtu_probing=1
EOF
  sysctl --system >/dev/null 2>&1 || true

  log "当前拥塞算法：$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown)"
  log "当前队列算法：$(sysctl -n net.core.default_qdisc 2>/dev/null || echo unknown)"
}

run_singbox_plus_install() {
  local sbp_url="https://raw.githubusercontent.com/Alvin9999/Sing-Box-Plus/main/sing-box-plus.sh"
  local sbp_path="/root/sing-box-plus.sh"

  log "下载 Sing-Box-Plus ..."
  curl -fsSL "$sbp_url" -o "$sbp_path" || die "下载 Sing-Box-Plus 失败"
  chmod +x "$sbp_path"

  log "执行 Sing-Box-Plus（默认选 1：安装/部署）..."
  # 说明：这一步就是你手工运行脚本后输入 1 的等价操作
  # 在 SSH 终端里执行没问题
  printf "1\n" | bash "$sbp_path" >/tmp/sbp_install.log 2>&1 || {
    echo "---- /tmp/sbp_install.log 最后 120 行 ----" >&2
    tail -n 120 /tmp/sbp_install.log >&2 || true
    die "Sing-Box-Plus 安装/部署失败"
  }
}

collect_links_from_sbp() {
  local sbp_path="/root/sing-box-plus.sh"
  [[ -f "$sbp_path" ]] || die "未找到 $sbp_path（上一步应该已下载）"

  log "提取 18 个节点链接（默认选 2：查看分享链接）..."
  local out clean links
  out="$(printf "2\n" | bash "$sbp_path" 2>/dev/null || true)"

  # 去 ANSI 颜色码
  clean="$(printf "%s" "$out" | sed -r 's/\x1B\[[0-9;]*[A-Za-z]//g')"

  # 抽取链接行
  links="$(printf "%s\n" "$clean" | sed -nE 's/^[[:space:]]+//; /^[[:space:]]*(vless|trojan|hy2|vmess|ss|tuic):\/\//p')"

  # 基本校验
  local n
  n="$(printf "%s\n" "$links" | sed '/^$/d' | wc -l | tr -d ' ')"
  [[ "$n" -ge 9 ]] || {
    echo "---- 解析失败时的输出片段（最后 120 行） ----" >&2
    printf "%s\n" "$clean" | tail -n 120 >&2 || true
    die "未能从 Sing-Box-Plus 输出中解析到足够的节点链接（仅 $n 条）"
  }

  # 输出到文件（纯链接，每行一条）
  printf "%s\n" "$links" | sed '/^$/d' > /root/nodes.txt

  log "已写入 /root/nodes.txt（$(wc -l </root/nodes.txt | tr -d ' ') 条）"
}

update_gist_subscription() {
  # 你要的“固定订阅链接”：用同一个 GIST_ID，每次更新同一个文件内容
  : "${GIST_ID:=}"
  : "${GH_TOKEN:=}"

  [[ -n "$GIST_ID" ]] || die "缺少环境变量 GIST_ID"
  [[ -n "$GH_TOKEN" ]] || die "缺少环境变量 GH_TOKEN"

  [[ -s /root/nodes.txt ]] || die "/root/nodes.txt 不存在或为空"

  # 订阅一般用 base64（一行）
  local b64
  b64="$(base64 -w0 /root/nodes.txt)"

  log "更新 GitHub Gist：$GIST_ID ..."
  local api="https://api.github.com/gists/${GIST_ID}"
  local payload
  payload="$(jq -n --arg c "$b64" '{files: {"sub.txt": {content: $c}}}')"

  # PATCH 更新
  local http_code
  http_code="$(
    curl -sS -o /tmp/gist_update.json -w "%{http_code}" \
      -X PATCH "$api" \
      -H "Authorization: token ${GH_TOKEN}" \
      -H "Accept: application/vnd.github+json" \
      -d "$payload" || echo 000
  )"

  if [[ "$http_code" != "200" ]]; then
    echo "---- /tmp/gist_update.json ----" >&2
    cat /tmp/gist_update.json >&2 || true
    die "更新 Gist 失败（HTTP $http_code）。常见原因：Token 没有 Gist 写权限 / GIST_ID 写错 / Token 已过期"
  fi

  # 取 raw_url（稳定订阅链接）
  local raw_url
  raw_url="$(jq -r '.files["sub.txt"].raw_url // empty' /tmp/gist_update.json)"
  [[ -n "$raw_url" ]] || {
    # 兜底：再 GET 一次
    raw_url="$(
      curl -fsSL \
        -H "Authorization: token ${GH_TOKEN}" \
        -H "Accept: application/vnd.github+json" \
        "$api" | jq -r '.files["sub.txt"].raw_url // empty'
    )"
  }
  [[ -n "$raw_url" ]] || die "未能获取 Gist 的 raw_url（请打开 Gist 确认存在 sub.txt）"

  log "订阅链接（Gist Raw）：$raw_url"
  printf "%s\n" "$raw_url" > /root/subscription_url.txt
}

print_summary() {
  echo
  echo "==================== 结果 ===================="
  echo "Sing-Box 服务：$(systemctl is-active sing-box.service 2>/dev/null || echo unknown)"
  echo
  echo "==== 监听端口（sing-box）===="
  ss -lntup 2>/dev/null | grep -F 'sing-box' || true
  echo
  if [[ -s /root/subscription_url.txt ]]; then
    echo "==== 订阅链接（请自己保存，不要公开）===="
    cat /root/subscription_url.txt
    echo
  fi
  echo "==== 节点链接（每行一条）===="
  cat /root/nodes.txt
  echo "=============================================="
  echo
  echo "提示：如果你在 Vultr/云平台开启了“云防火墙/安全组”，仍需要在面板放行这些端口（系统内 iptables 放行不影响云防火墙）。"
}

main() {
  require_root
  ensure_base_deps
  enable_bbr_and_tune
  run_singbox_plus_install
  collect_links_from_sbp
  update_gist_subscription
  print_summary
}

main "$@"
