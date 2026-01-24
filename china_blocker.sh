#!/bin/bash

# ================= 配置区 =================
INSTALL_DIR="/usr/local/bin"
SCRIPT_NAME="china_blocker"
TARGET_PATH="$INSTALL_DIR/$SCRIPT_NAME"

CONFIG_DIR="/etc/china_blocker"
IPSET_CONF="$CONFIG_DIR/ipset.conf"
WHITELIST_FILE="$CONFIG_DIR/whitelist.txt"
LOG_FILE="/var/log/china_blocker.log"

# 主源（可能被拦截/返回 HTML，但 HTTP 200）
IP_SOURCE="https://www.ipdeny.com/ipblocks/data/countries/cn.zone"
# 备用源：APNIC delegated（生成 CN IPv4 CIDR）
APNIC_URL="https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"

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
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}错误：请使用 sudo 运行此脚本。${NC}"
    exit 1
fi

mkdir -p "$CONFIG_DIR"
if [ ! -f "$WHITELIST_FILE" ]; then
    mkdir -p "$(dirname "$WHITELIST_FILE")" 2>/dev/null || true
    echo "# 在此处每行添加一个要放行的IP地址" > "$WHITELIST_FILE"
fi
touch "$LOG_FILE" 2>/dev/null || true

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
    # 必需命令
    local need=(ipset iptables curl awk sed sort uniq)
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

    # 强烈建议：ca-certificates（Debian/Ubuntu minimal 常缺，导致 HTTPS 异常/被替换页）
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

ensure_chain() {
    iptables -N "$CHAIN_NAME" 2>/dev/null || true
    # INPUT: 1 白名单 2 jump 到 CHINA_BLOCKER
    if ! iptables -C INPUT -j "$CHAIN_NAME" 2>/dev/null; then
        iptables -I INPUT 2 -j "$CHAIN_NAME"
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

save_ipset() {
    # 保存为“可执行命令列表”（不依赖 ipset restore）
    {
        echo "create $IPSET_NAME hash:net -exist"
        echo "flush $IPSET_NAME"
        ipset list "$IPSET_NAME" 2>/dev/null | awk '/^([0-9]{1,3}\.){3}[0-9]{1,3}\// {print "add '"$IPSET_NAME"' " $1 " -exist"}'
    } > "$IPSET_CONF" 2>/dev/null || true
}

restore_ipset_from_conf() {
    if [ -f "$IPSET_CONF" ]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            ipset $line 2>/dev/null || true
        done < "$IPSET_CONF"
    else
        ensure_ipset
    fi
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

# ================= 核心功能函数 =================

restore_all() {
    restore_ipset_from_conf
    ensure_chain
    apply_whitelist
}

# ✅ 更新 IP：主源 ipdeny + 备用源 APNIC（整数算法，兼容 mawk）；curl 增加重试/超时；trap 用 RETURN
update_ips() {
    echo -e "${CYAN}正在下载并更新 IP 库...${NC}"
    ensure_ipset

    ipset destroy "$IPSET_TMP" 2>/dev/null || true

    local TMP_FILE CLEAN_FILE
    TMP_FILE="$(mktemp)"
    CLEAN_FILE="$(mktemp)"

    trap 'rm -f "$TMP_FILE" "$CLEAN_FILE"' RETURN

    # NAT 环境更稳：超时 + 重试
    local CURL_OPTS=( -fsSL --connect-timeout 10 --max-time 120 --retry 3 --retry-delay 2 --retry-all-errors )

    # ---------- 1) 主源：ipdeny ----------
    if curl "${CURL_OPTS[@]}" -o "$TMP_FILE" "$IP_SOURCE"; then
        # 兼容：一行空格分隔 / 多行分隔
        tr -s ' \t\r\n' '\n' < "$TMP_FILE" \
        | awk '
            /^[ \t]*$/ { next }
            /^[ \t]*#/ { next }
            {
              if ($0 ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]{1,2})?$/) print $0
            }
        ' > "$CLEAN_FILE"
    fi

    # 如果主源解析不到 CIDR（可能返回 HTML/拦截页但 HTTP 200）
    if ! [ -s "$CLEAN_FILE" ]; then
        echo -e "${YELLOW}主源内容无法解析为 CIDR（可能是拦截页/HTML/非预期格式），切换 APNIC 备用源生成 CN IPv4 CIDR...${NC}"

        # ---------- 2) 备用源：APNIC delegated ----------
        if curl "${CURL_OPTS[@]}" -o "$TMP_FILE" "$APNIC_URL"; then
            # 纯整数算法判断 count 是否为 2^n（避免 mawk 浮点误差导致 n==int(n) 失败）
            awk -F'|' '
                function is_pow2_and_exp(cnt,    c,e){
                    c = cnt + 0
                    if (c < 1) return -1
                    e = 0
                    while (c % 2 == 0) { c = c / 2; e++ }
                    if (c == 1) return e
                    return -1
                }
                $2=="CN" && $3=="ipv4" {
                    exp = is_pow2_and_exp($5)
                    if (exp >= 0) {
                        printf("%s/%d\n", $4, 32-exp)
                    }
                }
            ' "$TMP_FILE" > "$CLEAN_FILE"
        fi
    fi

    if ! [ -s "$CLEAN_FILE" ]; then
        echo -e "${RED}更新失败：仍然没有获得可用的 CIDR 列表。${NC}"
        echo -e "${YELLOW}建议执行并粘贴输出以定位（是否被拦截/证书/DNS/代理）：${NC}"
        echo "  curl -v ${IP_SOURCE} -o /tmp/cn.zone 2>&1 | tail -n 30"
        echo "  head -n 5 /tmp/cn.zone"
        echo "[$(date)] Update failed: empty cidr list after primary+fallback" >> "$LOG_FILE"
        return 1
    fi

    # ---------- 3) 逐条导入临时集合，再 swap ----------
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

    echo -e "${GREEN}更新成功！IP 总数：$COUNT（本次新增尝试：$added，跳过：$skipped）${NC}"
    echo "[$(date)] Update success. Total: $COUNT, added_try=$added, skipped=$skipped" >> "$LOG_FILE"
    return 0
}

block_port() {
    echo -n "输入要屏蔽的端口 (如 80): "
    read -r port
    [[ -z "$port" ]] && return

    if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
        echo -e "${RED}端口无效：$port${NC}"
        return
    fi

    if [[ "$port" == "22" ]]; then
        echo -e "${RED}⚠️ 警告：屏蔽 22 端口可能导致你失去连接！${NC}"
        echo -n "确认继续? (y/N): "
        read -r confirm
        [[ "$confirm" != "y" ]] && return
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
    [[ -z "$choice" ]] && return

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

    echo -e "${CYAN}安装过程中自动更新一次 IP 库...${NC}"
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
        systemctl stop "${UPDATE_TIMER_NAME}.timer" 2>/dev/null
        systemctl disable "${UPDATE_TIMER_NAME}.timer" 2>/dev/null
        rm -f "/etc/systemd/system/${UPDATE_TIMER_NAME}.timer" 2>/dev/null
        rm -f "/etc/systemd/system/${UPDATE_SERVICE_NAME}.service" 2>/dev/null

        systemctl stop "$SERVICE_NAME" 2>/dev/null
        systemctl disable "$SERVICE_NAME" 2>/dev/null
        rm -f "/etc/systemd/system/${SERVICE_NAME}.service" 2>/dev/null

        systemctl daemon-reload 2>/dev/null
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
        echo -e "0. 退出"
        echo -e "----------------------------------"
        echo -n "请选择: "
        read -r choice

        case $choice in
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
if [[ "$0" == "$TARGET_PATH" && -n "$1" ]]; then
    case "$1" in
        --restore) restore_all ;;
        --clean)   clean_all ;;
        --update)  update_ips ;;
    esac
    exit 0
fi

case "$1" in
    --install) install_service ;;
    --update)  update_ips ;;
    --block)   block_port ;;
    --restore) restore_all ;;
    --clean)   clean_all ;;
    *)         show_menu ;;
esac
