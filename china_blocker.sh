#!/bin/bash

# ==========================================================
#  China Blocker - Block traffic from China IP ranges (IPv4)
#  - ipdeny 优先；仅当 ipdeny 下载/解析失败时才使用 APNIC 备用源
#  - 兼容 Debian/Ubuntu/CentOS（mawk/gawk、iptables-legacy/nft）
#  - systemd service + systemd timer（替代 cron）
#  - 白名单始终插入 INPUT 最前；CHINA_BLOCKER 跳转尽量插第2条，失败回退第1条
#  - ipset 保存/恢复采用“原子导入 + swap”，避免清空为 0
# ==========================================================

set -u

# ================= 配置区 =================
INSTALL_DIR="/usr/local/bin"
SCRIPT_NAME="china_blocker"
TARGET_PATH="$INSTALL_DIR/$SCRIPT_NAME"

CONFIG_DIR="/etc/china_blocker"
IPSET_CONF="$CONFIG_DIR/ipset.conf"
WHITELIST_FILE="$CONFIG_DIR/whitelist.txt"
LOG_FILE="/var/log/china_blocker.log"

# 主源（优先）
IP_SOURCE="https://www.ipdeny.com/ipblocks/data/countries/cn.zone"
# 备用源（仅当主源不可用/不可解析时使用）
APNIC_URL="https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"

# 脚本自身的更新源
SCRIPT_UPDATE_URL="https://raw.githubusercontent.com/Henry00123/china_blocker/main/china_blocker.sh"

SERVICE_NAME="china_blocker"
UPDATE_SERVICE_NAME="china_blocker-update"
UPDATE_TIMER_NAME="china_blocker-update"

CHAIN_NAME="CHINA_BLOCKER"
IPSET_NAME="china_ips"
IPSET_TMP="china_ips_new"

# Timer 计划：每月 1 日 04:00（需要可改成每天："*-*-* 04:00:00"）
ON_CALENDAR="*-*-01 04:00:00"

# ================= 颜色定义 =================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ================= 基础检查 =================
if [[ ${EUID:-9999} -ne 0 ]]; then
  echo -e "${RED}错误：请使用 sudo 运行此脚本。${NC}"
  exit 1
fi

mkdir -p "$CONFIG_DIR"
if [ ! -f "$WHITELIST_FILE" ]; then
  echo "# 在此处每行添加一个要放行的IP地址" > "$WHITELIST_FILE"
fi
touch "$LOG_FILE" 2>/dev/null || true

log() {
  echo "[$(date)] $*" >> "$LOG_FILE"
}

# ================= 工具函数 =================
detect_pkg_mgr() {
  if command -v apt-get >/dev/null 2>&1; then
    echo "apt"
  elif command -v dnf >/dev/null 2>&1; then
    echo "dnf"
  elif command -v yum >/dev/null 2>&1; then
    echo "yum"
  else
    echo "none"
  fi
}

pkg_install() {
  local mgr
  mgr="$(detect_pkg_mgr)"
  case "$mgr" in
    apt)
      apt-get update -qq
      DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" >/dev/null
      ;;
    dnf)
      dnf install -y "$@" >/dev/null
      ;;
    yum)
      yum install -y "$@" >/dev/null
      ;;
    *)
      return 1
      ;;
  esac
}

check_dependencies() {
  local need=(ipset iptables curl awk sed sort uniq grep)
  for cmd in "${need[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo -e "${YELLOW}未检测到 ${cmd}，尝试自动安装...${NC}"
      case "$cmd" in
        iptables)
          pkg_install iptables || pkg_install iptables-nft || true
          ;;
        *)
          pkg_install "$cmd" || true
          ;;
      esac
    fi
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo -e "${RED}依赖缺失：$cmd（自动安装失败，请手动安装）${NC}"
      exit 1
    fi
  done

  # ca-certificates（HTTPS 更稳）
  if ! [ -f /etc/ssl/certs/ca-certificates.crt ] && ! [ -f /etc/pki/tls/certs/ca-bundle.crt ]; then
    pkg_install ca-certificates >/dev/null 2>&1 || true
    command -v update-ca-certificates >/dev/null 2>&1 && update-ca-certificates >/dev/null 2>&1 || true
  fi

  if ! command -v systemctl >/dev/null 2>&1; then
    echo -e "${YELLOW}未检测到 systemctl（系统可能非 systemd）。将无法安装为服务/定时器，但仍可手动运行。${NC}"
  fi
}

ensure_kernel_modules() {
  modprobe ip_set 2>/dev/null || true
  modprobe ip_set_hash_net 2>/dev/null || true
}

ensure_ipset() {
  ensure_kernel_modules
  ipset create "$IPSET_NAME" hash:net -exist 2>/dev/null || true
}

# INPUT 为空时插入第2条会失败 -> 先尝试 2，失败回退 1
ensure_chain() {
  iptables -N "$CHAIN_NAME" 2>/dev/null || true

  if iptables -C INPUT -j "$CHAIN_NAME" 2>/dev/null; then
    return 0
  fi

  # 优先插到第2条（第1条留给白名单），若 INPUT 为空则回退到第1条
  if ! iptables -I INPUT 2 -j "$CHAIN_NAME" 2>/dev/null; then
    iptables -I INPUT 1 -j "$CHAIN_NAME" 2>/dev/null || true
  fi
}

apply_whitelist() {
  grep -vE "^\s*#|^\s*$" "$WHITELIST_FILE" | while read -r ip; do
    [[ -z "$ip" ]] && continue
    if ! iptables -C INPUT -s "$ip" -j ACCEPT 2>/dev/null; then
      iptables -I INPUT 1 -s "$ip" -j ACCEPT
    fi
  done
}

remove_whitelist_rules() {
  [ ! -f "$WHITELIST_FILE" ] && return
  grep -vE "^\s*#|^\s*$" "$WHITELIST_FILE" | while read -r ip; do
    [[ -z "$ip" ]] && continue
    while iptables -C INPUT -s "$ip" -j ACCEPT 2>/dev/null; do
      iptables -D INPUT -s "$ip" -j ACCEPT 2>/dev/null || break
    done
  done
}

# 保存为“可执行命令列表”（不依赖 ipset restore）
save_ipset() {
  {
    echo "create $IPSET_NAME hash:net -exist"
    echo "flush $IPSET_NAME"
    ipset list "$IPSET_NAME" -o save 2>/dev/null | awk '$1=="add"{print "add '"$IPSET_NAME"' " $3 " -exist"}'
  } > "$IPSET_CONF" 2>/dev/null || true
}

# 原子 restore：解析 ipset.conf -> 导入临时 set -> swap
restore_ipset_from_conf() {
  ensure_ipset
  [ ! -f "$IPSET_CONF" ] && return 0

  local TMP_SET="${IPSET_NAME}_restore_tmp"
  ipset destroy "$TMP_SET" 2>/dev/null || true
  ipset create "$TMP_SET" hash:net hashsize 4096 maxelem 1048576 -exist 2>/dev/null || true
  ipset flush "$TMP_SET" 2>/dev/null || true

  local added=0 skipped=0 cidr
  while read -r op setname maybe_cidr _rest; do
    if [[ "$op" == "add" && "$setname" == "$IPSET_NAME" ]]; then
      cidr="$maybe_cidr"
      if ipset add "$TMP_SET" "$cidr" -exist 2>/dev/null; then
        added=$((added+1))
      else
        skipped=$((skipped+1))
      fi
    fi
  done < "$IPSET_CONF"

  if [ "$added" -gt 0 ]; then
    ipset swap "$TMP_SET" "$IPSET_NAME"
    ipset destroy "$TMP_SET" 2>/dev/null || true
    log "Restore success. Total: $(get_ipset_count)"
    return 0
  fi

  ipset destroy "$TMP_SET" 2>/dev/null || true
  log "Restore skipped: no CIDR parsed from ipset.conf (added=$added skipped=$skipped)"
  return 1
}

get_ipset_count() {
  ipset list "$IPSET_NAME" 2>/dev/null | awk -F': ' '/Number of entries/ {print $2; exit}'
}

list_blocked_ports() {
  iptables -S "$CHAIN_NAME" 2>/dev/null \
    | awk '
        /--dport/ {
            for (i=1; i<=NF; i++) if ($i=="--dport") print $(i+1)
        }' \
    | sort -n | uniq
}

pick_editor() {
  if command -v vim >/dev/null 2>&1; then
    echo "vim"
  elif command -v vi >/dev/null 2>&1; then
    echo "vi"
  else
    echo ""
  fi
}

# ================== 关键：CIDR 抽取器（更强健） ==================
# 从任意文本里提取 IPv4(/mask) token（避免 CR/BOM/杂字符导致整行匹配失败）
extract_cidr_tokens() {
  grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' \
    | grep -vE '^0\.0\.0\.0(/0)?$' \
    | sort -u
}

looks_like_html() {
  local f="$1"
  if grep -qiE '<!doctype|<html|</html>' "$f"; then
    return 0
  fi
  return 1
}

# ================= 核心功能函数 =================
restore_all() {
  restore_ipset_from_conf || true
  ensure_chain
  apply_whitelist
}

# ✅ update_ips：ipdeny 优先；只有 ipdeny 失败/解析不到 CIDR 才走 APNIC
update_ips() {
  echo -e "${CYAN}正在下载并更新 IP 库...${NC}"
  ensure_ipset
  ipset destroy "$IPSET_TMP" 2>/dev/null || true

  local TMP_FILE="" CLEAN_FILE=""
  TMP_FILE="$(mktemp)"
  CLEAN_FILE="$(mktemp)"
  trap 'rm -f "${TMP_FILE:-}" "${CLEAN_FILE:-}"' RETURN

  local CURL_OPTS=( -fsSL --connect-timeout 10 --max-time 120 --retry 3 --retry-delay 2 --retry-all-errors )

  local source_used=""
  local parsed_count=0

  # -------- 1) 主源：ipdeny（优先） --------
  if curl "${CURL_OPTS[@]}" -o "$TMP_FILE" "$IP_SOURCE"; then
    if looks_like_html "$TMP_FILE"; then
      : > "$CLEAN_FILE"
      source_used="ipdeny_html"
    else
      extract_cidr_tokens < "$TMP_FILE" > "$CLEAN_FILE"
      source_used="ipdeny"
    fi
  else
    : > "$CLEAN_FILE"
    source_used="ipdeny_download_fail"
  fi

  if [ -s "$CLEAN_FILE" ]; then
    parsed_count="$(wc -l < "$CLEAN_FILE" | awk '{print $1}')"
  fi

  # -------- 2) 备用源：APNIC（仅当 ipdeny 失败/为空） --------
  if ! [ -s "$CLEAN_FILE" ]; then
    echo -e "${YELLOW}ipdeny 下载或解析失败，切换 APNIC 备用源生成 CN IPv4 CIDR...${NC}"
    if curl "${CURL_OPTS[@]}" -o "$TMP_FILE" "$APNIC_URL"; then
      awk -F'|' '
        $2=="CN" && $3=="ipv4" {
          c = $5 + 0
          if (c < 1) next
          e = 0
          while (c % 2 == 0) { c = c / 2; e++ }
          if (c == 1) printf("%s/%d\n", $4, 32 - e)
        }
      ' "$TMP_FILE" | sort -u > "$CLEAN_FILE"
      source_used="apnic"
    else
      source_used="apnic_download_fail"
    fi
  fi

  if ! [ -s "$CLEAN_FILE" ]; then
    echo -e "${RED}更新失败：无法从 ipdeny 或 APNIC 获取有效 CIDR。${NC}"
    echo -e "${YELLOW}建议定位 ipdeny：${NC}"
    echo "  curl -v ${IP_SOURCE} -o /tmp/cn.zone 2>&1 | tail -n 30"
    echo "  head -n 5 /tmp/cn.zone"
    log "Update failed: empty cidr list (source_used=$source_used)"
    return 1
  fi

  # -------- 3) 导入到临时 set，再 swap（原子更新） --------
  ipset create "$IPSET_TMP" hash:net hashsize 4096 maxelem 1048576 -exist 2>/dev/null || true
  ipset flush "$IPSET_TMP" 2>/dev/null || true

  local added=0 skipped=0
  while IFS= read -r cidr; do
    if ipset add "$IPSET_TMP" "$cidr" -exist 2>/dev/null; then
      added=$((added+1))
    else
      skipped=$((skipped+1))
    fi
  done < "$CLEAN_FILE"

  ipset swap "$IPSET_TMP" "$IPSET_NAME"
  ipset destroy "$IPSET_TMP" 2>/dev/null || true

  save_ipset

  local COUNT
  COUNT="$(get_ipset_count)"
  COUNT="${COUNT:-unknown}"

  echo -e "${GREEN}更新成功！IP 总数：$COUNT（源：$source_used；解析：$(wc -l < "$CLEAN_FILE")；写入尝试：$added；跳过：$skipped）${NC}"
  log "Update success. Total=$COUNT source=$source_used parsed=$(wc -l < "$CLEAN_FILE") added_try=$added skipped=$skipped"
  return 0
}

# 脚本自身更新功能
update_script() {
  echo -e "${CYAN}正在检查并下载最新脚本...${NC}"
  if [[ -z "$SCRIPT_UPDATE_URL" || "$SCRIPT_UPDATE_URL" == *"your-username"* ]]; then
    echo -e "${YELLOW}尚未配置 SCRIPT_UPDATE_URL，请先在脚本顶部的配置区修改为你自己的直链。${NC}"
    return
  fi

  local TMP_SCRIPT
  TMP_SCRIPT="$(mktemp)"
  trap 'rm -f "$TMP_SCRIPT"' RETURN

  if curl -fsSL --connect-timeout 10 -o "$TMP_SCRIPT" "$SCRIPT_UPDATE_URL"; then
    # 安全验证：检查下载文件是否是一个有效的 bash 脚本
    if head -n 1 "$TMP_SCRIPT" | grep -q "#!/bin/bash"; then
      local SELF
      SELF="$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || echo "$0")"
      
      # 覆盖当前运行的脚本
      if [[ -w "$SELF" ]]; then
        cat "$TMP_SCRIPT" > "$SELF"
      fi
      
      # 如果已经安装到了 TARGET_PATH，也一并覆盖
      if [[ "$SELF" != "$TARGET_PATH" && -w "$TARGET_PATH" ]]; then
        cat "$TMP_SCRIPT" > "$TARGET_PATH"
        chmod +x "$TARGET_PATH"
      fi

      echo -e "${GREEN}脚本自更新完成！脚本将自动退出，请重新运行。${NC}"
      exit 0
    else
      echo -e "${RED}下载的文件内容无效（未检测到 #!/bin/bash）。更新失败！${NC}"
      echo -e "${YELLOW}可能是网络拦截或 URL 错误导致拉取到了 HTML 页面。${NC}"
    fi
  else
    echo -e "${RED}下载失败，请检查网络或 URL 是否正确！${NC}"
  fi
}

block_port() {
  echo -n "输入要屏蔽的端口 (如 80): "
  read -r port
  [[ -z "${port:-}" ]] && return

  if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
    echo -e "${RED}端口无效：$port${NC}"
    return
  fi

  if [[ "$port" == "22" ]]; then
    echo -e "${RED}⚠️ 警告：屏蔽 22 端口可能导致你失去连接！${NC}"
    echo -n "确认继续? (y/N): "
    read -r confirm
    [[ "${confirm:-}" != "y" ]] && return
  fi

  ensure_ipset
  ensure_chain

  local added_protos=()
  local existed_protos=()

  for proto in tcp udp; do
    if iptables -C "$CHAIN_NAME" -p "$proto" --dport "$port" -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null; then
      existed_protos+=("$proto")
    else
      iptables -A "$CHAIN_NAME" -p "$proto" --dport "$port" -m set --match-set "$IPSET_NAME" src -j DROP
      added_protos+=("$proto")
    fi
  done

  apply_whitelist

  if [ "${#added_protos[@]}" -gt 0 ]; then
    echo -e "${GREEN}已屏蔽端口 $port（仅中国 IP）: ${added_protos[*]}${NC}"
  fi
  if [ "${#added_protos[@]}" -eq 0 ] && [ "${#existed_protos[@]}" -gt 0 ]; then
    echo -e "${YELLOW}端口 $port 已经处于封禁状态（仅中国 IP）: ${existed_protos[*]}${NC}"
  fi
}

unblock_port() {
  ensure_chain

  mapfile -t ports < <(list_blocked_ports)
  if [ "${#ports[@]}" -eq 0 ]; then
    echo -e "${YELLOW}当前没有已封禁的端口。${NC}"
    return
  fi

  echo -e "${CYAN}已封禁端口列表（中国 IP 命中将 DROP）：${NC}"
  for i in "${!ports[@]}"; do
    printf "%2d) %s\n" "$((i+1))" "${ports[$i]}"
  done

  echo -n "请输入要解封的端口（可输入序号或端口号，回车取消）: "
  read -r choice
  [[ -z "${choice:-}" ]] && return

  local port=""
  if [[ "$choice" =~ ^[0-9]+$ ]]; then
    if (( choice >= 1 && choice <= ${#ports[@]} )); then
      port="${ports[$((choice-1))]}"
    else
      port="$choice"
    fi
  else
    echo -e "${RED}输入无效：$choice${NC}"
    return
  fi

  if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
    echo -e "${RED}端口无效：$port${NC}"
    return
  fi

  local removed_protos=()
  for proto in tcp udp; do
    local removed_this_proto=0
    while iptables -C "$CHAIN_NAME" -p "$proto" --dport "$port" -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null; do
      iptables -D "$CHAIN_NAME" -p "$proto" --dport "$port" -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null || break
      removed_this_proto=1
    done
    [[ $removed_this_proto -eq 1 ]] && removed_protos+=("$proto")
  done

  if [ "${#removed_protos[@]}" -gt 0 ]; then
    echo -e "${GREEN}已解封端口 $port: ${removed_protos[*]}${NC}"
  else
    echo -e "${YELLOW}端口 $port 未找到对应封禁规则（可能已被删除）。${NC}"
  fi
}

clean_all() {
  while iptables -C INPUT -j "$CHAIN_NAME" 2>/dev/null; do
    iptables -D INPUT -j "$CHAIN_NAME" 2>/dev/null || break
  done

  iptables -F "$CHAIN_NAME" 2>/dev/null || true
  iptables -X "$CHAIN_NAME" 2>/dev/null || true

  ipset destroy "$IPSET_NAME" 2>/dev/null || true
  ipset destroy "$IPSET_TMP" 2>/dev/null || true

  remove_whitelist_rules
}

install_systemd_units() {
  local SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
  local UPDATE_SERVICE_FILE="/etc/systemd/system/${UPDATE_SERVICE_NAME}.service"
  local UPDATE_TIMER_FILE="/etc/systemd/system/${UPDATE_TIMER_NAME}.timer"

  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=China IP Blocker Service
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$TARGET_PATH --restore
ExecStop=$TARGET_PATH --clean
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

  cat > "$UPDATE_SERVICE_FILE" <<EOF
[Unit]
Description=China Blocker - Update China IPSet
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$TARGET_PATH --update
StandardOutput=journal
StandardError=journal
EOF

  cat > "$UPDATE_TIMER_FILE" <<EOF
[Unit]
Description=China Blocker - Monthly Update Timer

[Timer]
OnCalendar=$ON_CALENDAR
Persistent=true
Unit=${UPDATE_SERVICE_NAME}.service

[Install]
WantedBy=timers.target
EOF
}

install_service() {
  echo -e "${CYAN}正在安装/修复服务...${NC}"

  check_dependencies

  if ! command -v systemctl >/dev/null 2>&1; then
    echo -e "${RED}未检测到 systemctl（非 systemd 系统），无法安装为服务/定时器。${NC}"
    echo -e "${YELLOW}你仍可手动运行：sudo ./$SCRIPT_NAME 或 sudo $TARGET_PATH --update${NC}"
    return
  fi

  mkdir -p "$INSTALL_DIR" 2>/dev/null || true
  mkdir -p "$CONFIG_DIR" 2>/dev/null || true
  touch "$LOG_FILE" 2>/dev/null || true

  local SELF
  SELF="$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || echo "$0")"
  if ! cp "$SELF" "$TARGET_PATH" 2>/dev/null; then
    echo -e "${RED}复制脚本失败：无法从 $SELF 复制到 $TARGET_PATH${NC}"
    echo -e "${YELLOW}如果你是用 bash <(curl ...) 方式运行，请先保存为文件再执行。${NC}"
    return
  fi
  chmod +x "$TARGET_PATH"
  echo -e "脚本已部署到: ${GREEN}$TARGET_PATH${NC}"

  echo -e "${CYAN}安装过程中自动更新一次 IP 库（ipdeny 优先）...${NC}"
  if update_ips; then
    local COUNT
    COUNT="$(get_ipset_count)"
    COUNT="${COUNT:-unknown}"
    echo -e "${GREEN}✅ 更新完成：当前中国 IP 库条目数 = $COUNT${NC}"
  else
    echo -e "${YELLOW}提示：本次自动更新失败（网络或源站问题）。安装仍继续，你可稍后手动更新。${NC}"
  fi

  install_systemd_units
  systemctl daemon-reload

  systemctl enable "$SERVICE_NAME" >/dev/null 2>&1
  systemctl restart "$SERVICE_NAME" >/dev/null 2>&1

  systemctl enable "${UPDATE_TIMER_NAME}.timer" >/dev/null 2>&1
  systemctl restart "${UPDATE_TIMER_NAME}.timer" >/dev/null 2>&1

  echo -e "${GREEN}✅ 安装完成！${NC}"
  echo -e "服务已启动并设置为开机自启。"
  echo -e "${GREEN}现在可直接开始屏蔽端口：菜单选择 3（屏蔽端口）${NC}"
  echo -e "${CYAN}已启用 systemd timer：$ON_CALENDAR 自动更新 IP 库（Persistent=true）${NC}"
}

uninstall_all() {
  echo -e "${YELLOW}正在卸载...${NC}"

  if command -v systemctl >/dev/null 2>&1; then
    systemctl stop "${UPDATE_TIMER_NAME}.timer" 2>/dev/null || true
    systemctl disable "${UPDATE_TIMER_NAME}.timer" 2>/dev/null || true
    rm -f "/etc/systemd/system/${UPDATE_TIMER_NAME}.timer" 2>/dev/null || true
    rm -f "/etc/systemd/system/${UPDATE_SERVICE_NAME}.service" 2>/dev/null || true

    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service" 2>/dev/null || true

    systemctl daemon-reload 2>/dev/null || true
  fi

  clean_all
  rm -rf "$CONFIG_DIR"
  rm -f "$TARGET_PATH"

  echo -e "${GREEN}卸载完成。${NC}"
  exit 0
}

# ================= 菜单（循环返回主菜单） =================
show_menu() {
  while true; do
    clear
    echo -e "${CYAN}==================================${NC}"
    echo -e "${CYAN}   🇨🇳 中国 IP 屏蔽助手 (一键版)   ${NC}"
    echo -e "${CYAN}==================================${NC}"
    echo -e "1. ${GREEN}安装/修复服务${NC} (推荐，只需运行一次)"
    echo -e "2. ${YELLOW}更新 IP 库${NC}"
    echo -e "3. ${RED}屏蔽端口${NC}"
    echo -e "4. ${GREEN}解封端口${NC}"
    echo -e "5. 编辑白名单（vim）"
    echo -e "6. 查看状态"
    echo -e "7. ${RED}卸载服务${NC}"
    echo -e "99. ${YELLOW}更新脚本${NC}"
    echo -e "0. 退出"
    echo -e "----------------------------------"
    echo -n "请选择: "
    read -r choice

    case "${choice:-}" in
      1) install_service ;;
      2) update_ips ;;
      3) block_port ;;
      4) unblock_port ;;
      5)
        local ed
        ed="$(pick_editor)"
        if [[ "$ed" == "vim" ]]; then
          vim "$WHITELIST_FILE"
          apply_whitelist
        elif [[ -n "$ed" ]]; then
          echo -e "${YELLOW}未安装 vim，使用 $ed 打开白名单文件。建议安装 vim：${NC}"
          echo -e "  Debian/Ubuntu: sudo apt-get install -y vim"
          echo -e "  CentOS/RHEL:   sudo yum/dnf install -y vim-enhanced"
          "$ed" "$WHITELIST_FILE"
          apply_whitelist
        else
          echo -e "${RED}未找到 vim/vi，无法编辑白名单。请先安装 vim。${NC}"
        fi
        ;;
      6)
        systemctl status "$SERVICE_NAME" --no-pager 2>/dev/null || true
        echo -e "\n${CYAN}--- timer 状态 ---${NC}"
        systemctl status "${UPDATE_TIMER_NAME}.timer" --no-pager 2>/dev/null || true
        echo -e "\n${CYAN}--- 未来计划（systemd timers）---${NC}"
        systemctl list-timers --all 2>/dev/null | grep -E "${UPDATE_TIMER_NAME}\.timer" || true

        echo -e "\n${CYAN}--- iptables（INPUT 中与本工具相关）---${NC}"
        iptables -S INPUT | grep -E "$CHAIN_NAME|ACCEPT" || true
        echo -e "\n${CYAN}--- $CHAIN_NAME 链规则 ---${NC}"
        iptables -S "$CHAIN_NAME" 2>/dev/null || true
        echo -e "\n${CYAN}--- 已封禁端口（去重）---${NC}"
        list_blocked_ports 2>/dev/null || true
        echo -e "\n${CYAN}--- ipset $IPSET_NAME 条目数 ---${NC}"
        get_ipset_count 2>/dev/null || true
        ;;
      7) uninstall_all ;;
      99) update_script ;;
      0) exit 0 ;;
      *) echo "无效选择" ;;
    esac

    echo ""
    read -p "按回车返回主菜单..." _
  done
}

# ================= 入口 =================
check_dependencies

# systemd 调用（在目标路径且有参数）不显示菜单
if [[ "$0" == "$TARGET_PATH" && -n "${1:-}" ]]; then
  case "$1" in
    --restore) restore_all ;;
    --clean)   clean_all ;;
    --update)  update_ips ;;
  esac
  exit 0
fi

case "${1:-}" in
  --install) install_service ;;
  --update)  update_ips ;;
  --block)   block_port ;;
  --restore) restore_all ;;
  --clean)   clean_all ;;
  *)         show_menu ;;
esac
