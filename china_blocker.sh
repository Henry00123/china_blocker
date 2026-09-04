#!/bin/bash
# ==========================================================
#  China Blocker (nftables 版) - 屏蔽来自中国的 IPv4 / IPv6 流量
#  CB_FLAVOR=nftables
#  CB_VERSION=2.0.0
#
#  与 iptables + ipset 版本的主要差异：
#   - 独立的 `table inet china_blocker`，不再往 INPUT 里抢位置插规则
#   - nftables 命名 set 替代 ipset，interval + auto-merge 自动合并相邻网段
#   - 白名单 / 端口都是 set 元素，增删即改集合，不再解析防火墙输出反推状态
#   - IP 库更新采用「双槽位 set + 分块载入 + 原子切换规则引用」：
#     绕开 nft 单事务约 64KB 的 netlink 报文上限，同时保持对外原子可见
#   - 支持 IPv6（ipdeny v6 优先，APNIC 备用）
#   - 同时挂 input 与 forward hook，覆盖 Docker 发布端口（可关闭）
#   - 配置文件即唯一真相来源，重启恢复 = 重新载入几个文本文件
#   - 安装后提供 `cb` 快捷命令，直接调出菜单
# ==========================================================

set -u

# nft 通常在 /usr/sbin，非登录 root shell 里可能不在 PATH
PATH="/usr/sbin:/sbin:/usr/local/sbin:$PATH"
export PATH

CB_VERSION="2.0.0"

# ================= 配置区 =================
INSTALL_DIR="/usr/local/bin"
SCRIPT_NAME="china_blocker"
TARGET_PATH="$INSTALL_DIR/$SCRIPT_NAME"

# 快捷命令：安装后可直接输入 `cb` 调出菜单
ALIAS_NAME="cb"
ALIAS_PATH="$INSTALL_DIR/$ALIAS_NAME"

CONFIG_DIR="/etc/china_blocker"
WHITELIST_FILE="$CONFIG_DIR/whitelist.txt"
BLOCKED_PORTS_FILE="$CONFIG_DIR/blocked_ports.txt"
DATA_V4="$CONFIG_DIR/china_ipv4.txt"    # 纯文本 CIDR 列表，便于人工查看
DATA_V6="$CONFIG_DIR/china_ipv6.txt"
LOCK_FILE="$CONFIG_DIR/.lock"
STAMP_FILE="$CONFIG_DIR/.datastamp"      # 已载入内核的数据指纹，见 data_stamp_fresh
LOG_FILE="/var/log/china_blocker.log"

# nftables.service 的 drop-in，防止 `flush ruleset` 清掉本表
NFT_DROPIN_DIR="/etc/systemd/system/nftables.service.d"
NFT_DROPIN_FILE="$NFT_DROPIN_DIR/china_blocker.conf"

# IPv4 数据源
IP_SOURCE="https://www.ipdeny.com/ipblocks/data/countries/cn.zone"
# IPv6 数据源
IP6_SOURCE="https://www.ipdeny.com/ipv6/ipaddresses/blocks/cn.zone"
# 备用源（IPv4 / IPv6 共用，仅当主源失败时使用）
APNIC_URL="https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"

# 脚本自身的更新源。下载后会校验 CB_FLAVOR=nftables，防止误装回 iptables 版。
SCRIPT_UPDATE_URL="https://raw.githubusercontent.com/Henry00123/china_blocker/main/china_blocker.sh"

SERVICE_NAME="china_blocker"
UPDATE_SERVICE_NAME="china_blocker-update"
UPDATE_TIMER_NAME="china_blocker-update"
HEALTH_SERVICE_NAME="china_blocker-health"
HEALTH_TIMER_NAME="china_blocker-health"

# ================= nftables 对象命名 =================
TABLE="china_blocker"
CHAIN_IN="input"
CHAIN_FWD="forward"
S4PRE="china4_"       # 双槽位：china4_a / china4_b
S6PRE="china6_"       # 双槽位：china6_a / china6_b
WL4="whitelist4"
WL6="whitelist6"
PORTSET="blocked_ports"

# hook 优先级：-10 在常规 filter(0) 之前执行，
# 等价于原脚本"把跳转插到 INPUT 最前面"的效果。
HOOK_PRIORITY="-10"

# 是否同时挂 forward hook。Docker 发布端口(-p)的流量走 forward 而非 input，
# 只挂 input 会漏掉容器端口。置 0 可关闭（例如本机作为路由器需要转发中国流量）。
BLOCK_FORWARD="1"

# 单个 nft 事务的行数上限。nft 会把整个 -f 文件作为一个 netlink 批次发送，
# 超过约 64KB 就会 "Message too long"，所以必须分块。调大会触发该错误。
CHUNK_LINES=1500
# 单条 add element 语句里的元素个数（纯粹为了可读性和排错方便）
ELEMS_PER_STMT=300

# 数据健全性下限：解析结果少于该行数视为数据源异常，拒绝替换现有集合。
# 中国 IPv4 实际约 1.1 万条 CIDR，IPv6 约 3 千条，阈值取得很宽松。
MIN_V4_LINES=2000
MIN_V6_LINES=200

# 单条记录允许的最小前缀长度。用于挡住 `1.0.0.0/0`、`2001:db8::/0` 这类
# 「一条记录覆盖全网」的条目——源站返回残缺内容或被投毒时，一条就足以
# 把封禁集合扩成全网。只过滤 `0.0.0.0/0` 字面量是挡不住变体的。
# 中国实际分配的最大块远小于这两个阈值，正常数据不会被误杀。
MIN_V4_PREFIX=8
MIN_V6_PREFIX=16

# 等待并发锁的秒数
LOCK_WAIT=180

# Timer 计划：每月 1 日 04:00（改成每天："*-*-* 04:00:00"）
ON_CALENDAR="*-*-01 04:00:00"
# 健康检查间隔：定期确认表还在（防止被其他工具的 flush ruleset 清掉）
HEALTH_INTERVAL="15min"

# ================= 颜色定义 =================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ================= 帮助（无需 root，也无副作用） =================
show_help() {
  cat <<EOF
China Blocker (nftables 版) v$CB_VERSION

用法: $ALIAS_NAME [选项]        (等价于 $TARGET_PATH)

  不带参数        进入交互菜单
  --install       安装/修复服务
  --update        更新中国 IP 库 (IPv4 + IPv6)
  --block         交互式屏蔽端口
  --restore       从配置恢复规则（systemd 开机调用）
  --health        健康检查：表不在则自动恢复（systemd timer 调用）
  --clean         移除 nftables 表与全部规则（不影响配置与开机自启）
  --disable       停用并禁用 systemd 单元 + 清理规则（持久停用，保留配置）
  --status        打印状态报告
  --version       打印版本号
  -h, --help      显示本帮助

说明：--clean 只清当前规则，开机时服务会重新恢复；
      要持久停用请用 --disable，要彻底删除请用菜单 7（卸载）。
EOF
}

case "${1:-}" in
  -h|--help)  show_help; exit 0 ;;
  --version)  echo "china_blocker (nftables) v$CB_VERSION"; exit 0 ;;
esac

# ================= 基础检查 =================
if [[ ${EUID:-9999} -ne 0 ]]; then
  echo -e "${RED}错误：请使用 sudo 运行此脚本。${NC}"
  exit 1
fi

mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR" 2>/dev/null || true
if [ ! -f "$WHITELIST_FILE" ]; then
  cat > "$WHITELIST_FILE" <<'EOF'
# 每行一个要放行的 IP 或网段，支持 IPv4 与 IPv6
# 支持行尾注释，例：
#   203.0.113.9         # 办公室出口
#   198.51.100.0/24
#   2001:db8::1
#   2001:db8:1::/48
EOF
fi
[ -f "$BLOCKED_PORTS_FILE" ] || : > "$BLOCKED_PORTS_FILE"
touch "$LOG_FILE" 2>/dev/null || true
chmod 600 "$LOG_FILE" 2>/dev/null || true

log() { echo "[$(date '+%F %T')] $*" >> "$LOG_FILE" 2>/dev/null || true; }

# ================= 临时文件统一管理 =================
# 所有临时文件都放在本次运行独占的目录下，由唯一的 EXIT trap 兜底清理。
# 不使用 `trap ... RETURN`：bash 每个函数只有一个 RETURN trap 槽位，
# 嵌套调用（apply_whitelist 在 update_ips 内部被调用）会互相覆盖，导致文件泄漏。
TMPROOT="$(mktemp -d 2>/dev/null || echo "")"
if [ -z "$TMPROOT" ]; then
  echo -e "${RED}无法创建临时目录（/tmp 是否只读或已满？）。${NC}"
  exit 1
fi
_cleanup() {
  local rc=$?
  [ -n "${TMPROOT:-}" ] && [ -d "$TMPROOT" ] && rm -rf "$TMPROOT"
  return $rc
}
trap _cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mktmp()    { mktemp "$TMPROOT/f.XXXXXX"; }
mktmpdir() { mktemp -d "$TMPROOT/d.XXXXXX"; }

# ================= 并发互斥 =================
# 定时更新与开机 --restore 若同时跑，会各自往不同槽位写数据、抢着切换规则引用，
# 可能留下只装了一半的集合。用 flock 串行化所有会改内核状态的操作。
_LOCK_HELD=0
acquire_lock() {
  [ "$_LOCK_HELD" -eq 1 ] && return 0
  if ! command -v flock >/dev/null 2>&1; then
    _LOCK_HELD=1   # 没有 flock 就不强求，退化为无锁
    return 0
  fi
  : > "$LOCK_FILE" 2>/dev/null || true
  if ! exec 9>>"$LOCK_FILE" 2>/dev/null; then
    _LOCK_HELD=1
    return 0
  fi
  if ! flock -w "$LOCK_WAIT" 9; then
    echo -e "${RED}另一个 china_blocker 实例正在运行（等待 ${LOCK_WAIT}s 超时）。${NC}"
    log "acquire_lock timeout"
    return 1
  fi
  _LOCK_HELD=1
  return 0
}

# 主动释放锁。必须在调用 `systemctl start/restart china_blocker` 之前调用：
# 该单元是 Type=oneshot，systemctl 会一直等到 ExecStart（也就是 `--restore`）跑完，
# 而 `--restore` 自己也要抢同一把锁 —— 父进程握着锁等子进程，子进程等锁，
# 直接死锁到 flock 超时（LOCK_WAIT 秒），且 oneshot 默认不设启动超时不会被 systemd 打断。
release_lock() {
  [ "$_LOCK_HELD" -eq 1 ] || return 0
  exec 9>&- 2>/dev/null || true
  _LOCK_HELD=0
  return 0
}

# ================= 依赖 =================
detect_pkg_mgr() {
  if   command -v apt-get >/dev/null 2>&1; then echo "apt"
  elif command -v dnf     >/dev/null 2>&1; then echo "dnf"
  elif command -v yum     >/dev/null 2>&1; then echo "yum"
  else echo "none"; fi
}

pkg_install() {
  case "$(detect_pkg_mgr)" in
    apt) apt-get update -qq
         DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" >/dev/null ;;
    dnf) dnf install -y "$@" >/dev/null ;;
    yum) yum install -y "$@" >/dev/null ;;
    *)   return 1 ;;
  esac
}

# 内核可达性检查：所有动作都需要，且不会动包管理器。
check_kernel_nft() {
  if ! command -v nft >/dev/null 2>&1; then
    echo -e "${RED}未找到 nft 命令。请先安装 nftables：${NC}"
    echo -e "${YELLOW}  Debian/Ubuntu: apt-get install -y nftables${NC}"
    echo -e "${YELLOW}  CentOS/RHEL:   dnf install -y nftables${NC}"
    exit 1
  fi
  modprobe nf_tables 2>/dev/null || true
  if ! nft list ruleset >/dev/null 2>&1; then
    echo -e "${RED}nft 无法访问内核 nf_tables 子系统（内核过旧，或容器缺少 NET_ADMIN 权限）。${NC}"
    exit 1
  fi
}

# 完整依赖检查（可能触发包安装）。只在 --install / --update 这类真正联网的路径调用，
# 避免 --clean / --restore / --status 在开机早期或离线环境卡在 apt-get 上。
check_dependencies() {
  local cmd pkg
  for cmd in nft curl awk sed sort grep; do
    command -v "$cmd" >/dev/null 2>&1 && continue
    # 命令名 ≠ 包名：apt-get install sort / grep 是装不上的（分属 coreutils、grep），
    # awk 由 gawk 或 mawk 提供。映射错了只会白跑一次 apt-get update。
    case "$cmd" in
      nft)   pkg="nftables"  ;;
      awk)   pkg="gawk"      ;;
      sort)  pkg="coreutils" ;;
      *)     pkg="$cmd"      ;;   # curl / sed / grep 与包名同名
    esac
    echo -e "${YELLOW}未检测到 ${cmd}，尝试安装 ${pkg}...${NC}"
    pkg_install "$pkg" || true
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo -e "${RED}依赖缺失：$cmd（自动安装 $pkg 失败，请手动安装）${NC}"
      exit 1
    fi
  done

  # ca-certificates（HTTPS 更稳）
  if ! [ -f /etc/ssl/certs/ca-certificates.crt ] && ! [ -f /etc/pki/tls/certs/ca-bundle.crt ]; then
    pkg_install ca-certificates >/dev/null 2>&1 || true
    command -v update-ca-certificates >/dev/null 2>&1 && update-ca-certificates >/dev/null 2>&1 || true
  fi

  check_kernel_nft

  command -v systemctl >/dev/null 2>&1 || \
    echo -e "${YELLOW}未检测到 systemctl（系统可能非 systemd）。无法安装服务/定时器，但仍可手动运行。${NC}"
}

nft_version() { nft --version 2>/dev/null | awk '{print $2}'; }

# ================= 表 / 链 骨架 =================
# nft 的 `add` 对 table/set/chain 是幂等的（已存在即视为成功），
# 因此骨架可以反复写入，不会破坏已有 set 内容。
_write_skeleton() {
  local am="$1" errf="$2"   # $1 = "auto-merge;" 或空；$2 = 收集 nft 报错的文件
  local fwd=""
  [ "$BLOCK_FORWARD" = "1" ] && \
    fwd="chain $CHAIN_FWD { type filter hook forward priority $HOOK_PRIORITY; policy accept; }"
  nft -f - 2>"$errf" <<EOF
table inet $TABLE {
    set ${S4PRE}a  { type ipv4_addr;    flags interval; $am }
    set ${S4PRE}b  { type ipv4_addr;    flags interval; $am }
    set ${S6PRE}a  { type ipv6_addr;    flags interval; $am }
    set ${S6PRE}b  { type ipv6_addr;    flags interval; $am }
    set $WL4       { type ipv4_addr;    flags interval; }
    set $WL6       { type ipv6_addr;    flags interval; }
    set $PORTSET   { type inet_service; }
    chain $CHAIN_IN { type filter hook input priority $HOOK_PRIORITY; policy accept; }
    $fwd
}
EOF
}

active_chains() {
  echo "$CHAIN_IN"
  [ "$BLOCK_FORWARD" = "1" ] && echo "$CHAIN_FWD"
}

# 当前生效的槽位（从链里的 set 引用反推）。$1 = 4 或 6
current_slot() {
  local pre out
  if [ "$1" = "4" ]; then pre="$S4PRE"; else pre="$S6PRE"; fi
  out="$(nft list chain inet "$TABLE" "$CHAIN_IN" 2>/dev/null)" || { echo ""; return 0; }
  if   [[ "$out" == *"@${pre}a"* ]]; then echo "a"
  elif [[ "$out" == *"@${pre}b"* ]]; then echo "b"
  else echo ""; fi
}

slot_or_default() { local s; s="$(current_slot "$1")"; echo "${s:-a}"; }
other_slot()      { [ "$1" = "a" ] && echo "b" || echo "a"; }

# 期望的规则序列（顺序敏感：白名单的 return 必须排在 drop 之前）
_expected_rules() {
  local s4="$1" s6="$2"
  cat <<EOF
ip saddr @$WL4 return
ip6 saddr @$WL6 return
tcp dport @$PORTSET ip saddr @${S4PRE}${s4} counter drop
udp dport @$PORTSET ip saddr @${S4PRE}${s4} counter drop
tcp dport @$PORTSET ip6 saddr @${S6PRE}${s6} counter drop
udp dport @$PORTSET ip6 saddr @${S6PRE}${s6} counter drop
EOF
}

# 内核里实际的规则序列，归一化掉 counter 的计数值以便逐字比对
_actual_rules() {
  nft list chain inet "$TABLE" "$1" 2>/dev/null \
    | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' \
    | sed -nE '/^(ip|ip6|tcp|udp) /p' \
    | sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter/'
}

# 规则是否已经是期望形态（含顺序）。用于避免无谓重建，从而保住 counter 计数。
_rules_ok() {
  local s4="${1:-$(slot_or_default 4)}" s6="${2:-$(slot_or_default 6)}" want ch
  want="$(_expected_rules "$s4" "$s6")"
  while read -r ch; do
    [ -z "$ch" ] && continue
    [ "$(_actual_rules "$ch")" = "$want" ] || return 1
  done < <(active_chains)
  return 0
}

# 重建链规则：flush + 重写在同一个事务里，对外原子
_install_rules() {
  local s4="$1" s6="$2" ch body flushes=""
  _rules_ok "$s4" "$s6" && return 0

  body=""
  while read -r ch; do
    [ -z "$ch" ] && continue
    flushes="${flushes}flush chain inet $TABLE $ch"$'\n'
    body="${body}    chain $ch {
        ip  saddr @$WL4 return
        ip6 saddr @$WL6 return
        tcp dport @$PORTSET ip  saddr @${S4PRE}${s4} counter drop
        udp dport @$PORTSET ip  saddr @${S4PRE}${s4} counter drop
        tcp dport @$PORTSET ip6 saddr @${S6PRE}${s6} counter drop
        udp dport @$PORTSET ip6 saddr @${S6PRE}${s6} counter drop
    }
"
  done < <(active_chains)

  nft -f - <<EOF
${flushes}table inet $TABLE {
$body}
EOF
}

ensure_table() {
  local errf
  errf="$(mktmp)"
  if ! _write_skeleton "auto-merge;" "$errf"; then
    # 老版本 nft(<0.9) 不支持 auto-merge，退化为普通 interval set
    if ! _write_skeleton "" "$errf"; then
      echo -e "${RED}创建 nftables 表失败，nft 版本：$(nft_version)${NC}"
      echo -e "${YELLOW}nft 报错：${NC}"
      sed 's/^/  /' "$errf" >&2
      log "ensure_table failed (nft $(nft_version)): $(tr '\n' ' ' < "$errf")"
      rm -f "$errf"
      return 1
    fi
    echo -e "${YELLOW}当前 nft 不支持 auto-merge，已退化为普通 interval set（功能不受影响）。${NC}"
  fi
  rm -f "$errf"

  # 用户把 BLOCK_FORWARD 从 1 改回 0 时，之前建的 forward 链不会自动消失，
  # 这里主动删掉，否则它会带着旧规则继续拦转发流量。
  if [ "$BLOCK_FORWARD" != "1" ]; then
    nft delete chain inet "$TABLE" "$CHAIN_FWD" 2>/dev/null || true
  fi

  _install_rules "$(slot_or_default 4)" "$(slot_or_default 6)" \
    || { echo -e "${RED}安装 nftables 规则失败。${NC}"; return 1; }
  return 0
}

table_loaded() { nft list chain inet "$TABLE" "$CHAIN_IN" >/dev/null 2>&1; }

# ================= set 载入 =================
# 把 stdin 的元素拼成 add element 语句
emit_add_elements() {
  awk -v t="$TABLE" -v s="$1" -v CH="$ELEMS_PER_STMT" '
    NF > 0 {
      buf = buf (c++ ? ", " : "") $1
      if (c >= CH) { printf("add element inet %s %s { %s }\n", t, s, buf); buf=""; c=0 }
    }
    END { if (c > 0) printf("add element inet %s %s { %s }\n", t, s, buf) }
  '
}

# 分块把文件载入指定 set。该 set 此刻不被任何规则引用，
# 所以中间状态对流量不可见，最终由 _install_rules 一次性切换引用。
# 单块失败时逐行重载该块，跳过非法行。返回跳过的行数（通过 _SKIPPED_LINES）。
_load_chunk_linewise() {
  local setname="$1" file="$2" off="$3" end="$4" line bad=0
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    if ! printf 'add element inet %s %s { %s }\n' "$TABLE" "$setname" "$line" \
         | nft -f - 2>/dev/null; then
      bad=$(( bad + 1 ))
      log "skip invalid element: $setname <$line>"
    fi
  done < <(sed -n "${off},${end}p" "$file")
  _SKIPPED_LINES=$(( _SKIPPED_LINES + bad ))
  return 0
}

load_set_chunked() {
  local setname="$1" file="$2" compact total off end
  nft flush set inet "$TABLE" "$setname" 2>/dev/null || return 1

  # 必须先压掉空行/注释再分块：总量用非空行数、取块用 sed 物理行号，
  # 两者在含空行的文件上不相等，循环会提前结束并静默丢掉尾部数据。
  # 正常路径下 extract_v4/v6 的输出没有空行，但数据文件是明文、允许用户
  # 手工增删（README 有说明），手编时加一个空行就会踩中。
  compact="$(mktmp)" || return 1
  sed -E 's/#.*$//' "$file" 2>/dev/null | tr -d ' \t\r' | grep -v '^$' > "$compact"
  total="$(grep -c . "$compact" 2>/dev/null)"; total="${total:-0}"
  if [ "$total" -eq 0 ]; then rm -f "$compact"; return 1; fi

  _SKIPPED_LINES=0
  off=1
  while [ "$off" -le "$total" ]; do
    end=$(( off + CHUNK_LINES - 1 ))
    if ! sed -n "${off},${end}p" "$compact" | emit_add_elements "$setname" | nft -f - 2>/dev/null; then
      # 整块提交失败通常只是其中一两行非法（例如手工编辑过数据文件）。
      # 退化为逐行载入，跳过坏行而不是丢掉整块 1500 条。
      log "load_set_chunked: chunk ${off}-${end} failed, retrying line by line"
      _load_chunk_linewise "$setname" "$compact" "$off" "$end"
    fi
    off=$(( end + 1 ))
  done
  rm -f "$compact"

  # 全部行都非法说明数据文件根本不可用，视为失败以保留原有集合
  if [ "$_SKIPPED_LINES" -ge "$total" ]; then
    log "load_set_chunked failed: $setname all $total lines invalid"
    return 1
  fi
  [ "$_SKIPPED_LINES" -gt 0 ] && \
    echo -e "${YELLOW}已跳过 $_SKIPPED_LINES 条非法记录（详见日志）。${NC}"
  return 0
}

# 载入 IPv4/IPv6 数据并原子切换。参数为数据文件路径，留空表示不动该协议族。
# 返回值：0 = 规则已切到期望状态；1 = 切换失败
load_and_swap() {
  local f4="${1:-}" f6="${2:-}"
  local s4 s6 n4 n6 t failed=0
  s4="$(slot_or_default 4)"; s6="$(slot_or_default 6)"
  n4="$s4"; n6="$s6"

  if [ -n "$f4" ] && [ -s "$f4" ]; then
    t="$(other_slot "$s4")"
    if load_set_chunked "${S4PRE}${t}" "$f4"; then
      n4="$t"
    else
      failed=1
      echo -e "${RED}IPv4 集合载入失败，已保留原有数据。${NC}"
    fi
  fi

  if [ -n "$f6" ] && [ -s "$f6" ]; then
    t="$(other_slot "$s6")"
    if load_set_chunked "${S6PRE}${t}" "$f6"; then
      n6="$t"
    else
      failed=1
      echo -e "${RED}IPv6 集合载入失败，已保留原有数据。${NC}"
    fi
  fi

  # 一次事务同时切换 v4/v6 的引用（所有链一起切）
  _install_rules "$n4" "$n6" || return 1

  # 回收已经不被引用的旧集合，释放内存
  [ "$n4" != "$s4" ] && { nft flush set inet "$TABLE" "${S4PRE}${s4}" 2>/dev/null || true; }
  [ "$n6" != "$s6" ] && { nft flush set inet "$TABLE" "${S6PRE}${s6}" 2>/dev/null || true; }

  # 有任何一族没载入成功就不能写指纹：否则下次 restore 会误判"内核里已经是这份
  # 数据"而跳过重载，让一份没真正生效的数据被永久当成已生效。
  if [ "$failed" -eq 1 ]; then
    rm -f "$STAMP_FILE" 2>/dev/null || true
    return 1
  fi
  return 0
}

# ---- 数据指纹 ----
# 目的：让重复执行 --restore 不必反复切槽位重建规则（那会清零 counter）。
# 指纹 = 两个数据文件的内容摘要 + 当前生效槽位。
_hash_cmd() {
  if   command -v sha256sum >/dev/null 2>&1; then echo "sha256sum"
  elif command -v md5sum    >/dev/null 2>&1; then echo "md5sum"
  elif command -v cksum     >/dev/null 2>&1; then echo "cksum"
  else echo ""; fi
}

data_fingerprint() {
  local h; h="$(_hash_cmd)"
  [ -z "$h" ] && { echo ""; return 0; }
  printf '%s|%s|%s\n' \
    "$( ( cat "$DATA_V4" "$DATA_V6" 2>/dev/null || true ) | $h | awk '{print $1}')" \
    "$(slot_or_default 4)" "$(slot_or_default 6)"
}

write_data_stamp() {
  local fp; fp="$(data_fingerprint)"
  [ -z "$fp" ] && return 0
  printf '%s\n' "$fp" > "$STAMP_FILE" 2>/dev/null || true
  chmod 600 "$STAMP_FILE" 2>/dev/null || true
}

# 内核里的数据是否就是当前文件这一份
data_stamp_fresh() {
  local fp cur
  fp="$(data_fingerprint)"
  [ -z "$fp" ] && return 1                       # 没有可用的摘要工具就别偷懒
  [ -r "$STAMP_FILE" ] || return 1
  cur="$(cat "$STAMP_FILE" 2>/dev/null)"
  [ "$fp" = "$cur" ]
}

# 统计内核里某个 set 的元素数（不依赖 jq）
nft_set_count() {
  nft list set inet "$TABLE" "$1" 2>/dev/null \
    | tr '\n' ' ' \
    | sed -n 's/.*elements = {\([^}]*\)}.*/\1/p' \
    | tr ',' '\n' \
    | grep -c '[0-9a-fA-F]'
}

# 列出内核里某个 set 的元素
nft_set_elements() {
  nft list set inet "$TABLE" "$1" 2>/dev/null \
    | tr '\n' ' ' \
    | sed -n 's/.*elements = {\([^}]*\)}.*/\1/p' \
    | tr ',' '\n' \
    | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' \
    | grep -v '^$'
}

active_count4() { nft_set_count "${S4PRE}$(slot_or_default 4)"; }
active_count6() { nft_set_count "${S6PRE}$(slot_or_default 6)"; }

nft_drop_counter() {
  local ch total=0 n
  while read -r ch; do
    [ -z "$ch" ] && continue
    n="$(nft list chain inet "$TABLE" "$ch" 2>/dev/null \
         | grep -oE 'packets [0-9]+' | awk '{s+=$2} END {print s+0}')"
    total=$(( total + ${n:-0} ))
  done < <(active_chains)
  echo "$total"
}

# 某个 IP 是否落在中国集合 / 白名单里（用于防锁死自检）
ip_in_set() {
  local ip="$1" setname="$2"
  nft get element inet "$TABLE" "$setname" "{ $ip }" >/dev/null 2>&1
}
ip_in_china() {
  local ip="$1"
  if [[ "$ip" == *:* ]]; then ip_in_set "$ip" "${S6PRE}$(slot_or_default 6)"
  else                        ip_in_set "$ip" "${S4PRE}$(slot_or_default 4)"; fi
}
ip_in_whitelist() {
  local ip="$1"
  if [[ "$ip" == *:* ]]; then ip_in_set "$ip" "$WL6"
  else                        ip_in_set "$ip" "$WL4"; fi
}

# ================= 白名单 / 端口（配置文件为唯一真相） =================
# 返回 0 = 全部条目已写入内核；1 = 出现失败（调用方应视为未完全生效）
apply_whitelist() {
  ensure_table || return 1

  local d ALL W4 W6 total good rc=0
  d="$(mktmpdir)" || { echo -e "${RED}创建临时目录失败，已放弃修改白名单（原有白名单保持不变）。${NC}"; return 1; }
  ALL="$d/all"; W4="$d/v4"; W6="$d/v6"

  # 去掉整行注释与行尾注释，再去空白与 CR
  if ! sed -E 's/#.*$//' "$WHITELIST_FILE" 2>/dev/null \
        | tr -d ' \t\r' | grep -v '^$' > "$ALL"; then
    : > "$ALL"
  fi

  # 白名单的正则比 IP 库宽松（允许裸 IPv6、由内核消化写法差异），
  # 但 /0 必须挡掉：白名单命中即 return，一条 0.0.0.0/0 会让整表形同虚设，
  # 而状态报告只会显示「已生效」，用户根本看不出防护已经废了。
  grep    ':' "$ALL" 2>/dev/null | grep -E '^[0-9A-Fa-f:]+(/[0-9]{1,3})?$'              | grep -v '/0$' | sort -u > "$W6"
  grep -v ':' "$ALL" 2>/dev/null | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$' | grep -v '/0$' | sort -u > "$W4"

  # 注意：grep -c 无匹配时会输出 "0" 并以 1 退出，所以不能写 `|| echo 0`
  # ——那样会得到两行 "0\n0"，后面的算术运算就崩了。
  local g4 g6
  total="$(grep -c . "$ALL" 2>/dev/null)"; total="${total:-0}"
  g4="$(grep -c . "$W4" 2>/dev/null)"; g4="${g4:-0}"
  g6="$(grep -c . "$W6" 2>/dev/null)"; g6="${g6:-0}"
  good=$(( g4 + g6 ))
  if [ "$total" -ne "$good" ]; then
    echo -e "${YELLOW}白名单中有 $((total - good)) 行格式无法识别，已跳过。${NC}"
    rc=1
  fi

  if ! {
    echo "flush set inet $TABLE $WL4"
    emit_add_elements "$WL4" < "$W4"
    echo "flush set inet $TABLE $WL6"
    emit_add_elements "$WL6" < "$W6"
  } | nft -f - 2>/dev/null; then
    # 白名单直接关系到"会不会把自己锁在外面"，所以批量失败时退化为逐条应用，
    # 只丢掉真正非法的那一条，其余照常生效。
    echo -e "${YELLOW}白名单批量应用失败，改为逐条应用...${NC}"
    nft flush set inet "$TABLE" "$WL4" 2>/dev/null || true
    nft flush set inet "$TABLE" "$WL6" 2>/dev/null || true
    local ip bad=0
    while read -r ip; do
      [ -z "$ip" ] && continue
      nft add element inet "$TABLE" "$WL4" "{ $ip }" 2>/dev/null || \
        { echo -e "${RED}  跳过非法白名单条目：$ip${NC}"; bad=$((bad+1)); }
    done < "$W4"
    while read -r ip; do
      [ -z "$ip" ] && continue
      nft add element inet "$TABLE" "$WL6" "{ $ip }" 2>/dev/null || \
        { echo -e "${RED}  跳过非法白名单条目：$ip${NC}"; bad=$((bad+1)); }
    done < "$W6"
    log "apply_whitelist fell back to per-element mode, bad=$bad"
    [ "$bad" -gt 0 ] && rc=1
  fi

  rm -rf "$d"
  return $rc
}

# 规范化端口文件：容忍 CRLF、行尾注释、空白与乱序，非法内容明确报告
normalize_ports_file() {
  local d T BAD n
  d="$(mktmpdir)" || return 1
  T="$d/ports"; BAD="$d/bad"

  sed -E 's/#.*$//' "$BLOCKED_PORTS_FILE" 2>/dev/null \
    | tr -d ' \t\r' | grep -v '^$' > "$d/raw"

  awk '$0 ~ /^[0-9]+$/ && $1+0 >= 1 && $1+0 <= 65535 { print $1 > OUT; next } { print $0 > BADF }' \
    OUT="$T" BADF="$BAD" "$d/raw" 2>/dev/null || true
  [ -f "$T" ]   || : > "$T"
  [ -f "$BAD" ] || : > "$BAD"

  n="$(grep -c . "$BAD" 2>/dev/null)"; n="${n:-0}"
  if [ "$n" -gt 0 ]; then
    echo -e "${YELLOW}端口列表中有 $n 行不是合法端口，已忽略：${NC}" >&2
    sed 's/^/  /' "$BAD" >&2
    log "normalize_ports_file dropped $n invalid line(s)"
  fi

  sort -n -u "$T" > "$d/sorted"
  cat "$d/sorted" > "$BLOCKED_PORTS_FILE"
  rm -rf "$d"
  return 0
}

apply_ports() {
  ensure_table || return 1
  normalize_ports_file
  {
    echo "flush set inet $TABLE $PORTSET"
    emit_add_elements "$PORTSET" < "$BLOCKED_PORTS_FILE"
  } | nft -f - || { echo -e "${RED}端口集合应用失败。${NC}"; return 1; }
  return 0
}

list_blocked_ports() { normalize_ports_file 2>/dev/null; cat "$BLOCKED_PORTS_FILE"; }

# ================= SSH 自锁检测 =================
# 收集所有"看起来是 SSH"的端口：当前会话的服务端口、sshd 实际监听端口、配置文件里的 Port
ssh_ports() {
  {
    if [ -n "${SSH_CONNECTION:-}" ]; then awk '{print $4}' <<< "$SSH_CONNECTION"; fi
    # 只取对外监听（*、0.0.0.0、[::]、具体外网地址），跳过 loopback：
    # sshd 的 X11/端口转发会在 127.0.0.1 上开临时监听（如 127.0.0.1:6010），
    # 那些不是 SSH 服务端口，收进来会让封无关端口时弹出假的自锁警告。
    _sshd_listen_ports() {
      awk '
        /sshd/ {
          addr = $4
          n = split(addr, a, ":"); port = a[n]
          if (port !~ /^[0-9]+$/) { next }
          host = substr(addr, 1, length(addr) - length(port) - 1)
          if (host ~ /^(127\.|\[::1\]|::1)/) { next }
          print port
        }'
    }
    if command -v ss >/dev/null 2>&1; then
      ss -H -lntp 2>/dev/null | _sshd_listen_ports
    elif command -v netstat >/dev/null 2>&1; then
      netstat -lntp 2>/dev/null | _sshd_listen_ports
    fi
    awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/ { print $2 }' /etc/ssh/sshd_config 2>/dev/null
    for f in /etc/ssh/sshd_config.d/*.conf; do
      [ -f "$f" ] || continue
      awk '/^[[:space:]]*Port[[:space:]]+[0-9]+/ { print $2 }' "$f" 2>/dev/null
    done
  } 2>/dev/null | grep -E '^[0-9]+$' | sort -n -u
}

ssh_client_ip() {
  [ -n "${SSH_CONNECTION:-}" ] && awk '{print $1}' <<< "$SSH_CONNECTION"
}

# 封禁 $1 端口前的自锁风险评估。返回 0 = 可以继续；1 = 用户取消
lockout_check() {
  local port="$1" sports cip risky=0
  sports="$(ssh_ports)"

  if grep -qx "$port" <<< "$sports"; then
    risky=1
    echo -e "${RED}⚠️  端口 $port 看起来正是本机的 SSH 端口！${NC}"
    echo -e "${YELLOW}   检测到的 SSH 端口：$(tr '\n' ' ' <<< "$sports")${NC}"
  elif [ "$port" = "22" ]; then
    risky=1
    echo -e "${RED}⚠️  警告：22 是 SSH 默认端口，屏蔽后可能失去连接。${NC}"
  fi

  # 只有在封 SSH 端口时才需要评估来源 IP：封别的端口即使命中中国库，
  # 也只是失去该端口的访问，不会把管理通道掐断，没必要打断用户。
  [ "$risky" -eq 0 ] && return 0

  cip="$(ssh_client_ip)"
  if [ -n "$cip" ]; then
    echo -e "   你当前的来源 IP：${CYAN}${cip}${NC}"
    if ip_in_whitelist "$cip"; then
      echo -e "   ${GREEN}✓ 该 IP 已在白名单中，本次封禁不会影响你。${NC}"
      risky=0
    elif ip_in_china "$cip"; then
      echo -e "   ${RED}✗ 该 IP 属于中国 IP 库且不在白名单中——封禁后你会立刻掉线！${NC}"
      echo -e "   ${YELLOW}建议先执行菜单 5，把 ${cip} 加入白名单。${NC}"
      risky=1
    else
      # 只有在中国库确实有数据时，"不在库中"才是可信的结论；
      # 库为空时任何 IP 都"不在库中"，那是假的安全感。
      local have4 have6
      have4="$(active_count4)"; have6="$(active_count6)"
      if { [[ "$cip" == *:* ]] && [ "${have6:-0}" -gt 0 ]; } \
      || { [[ "$cip" != *:* ]] && [ "${have4:-0}" -gt 0 ]; }; then
        echo -e "   ${GREEN}✓ 该 IP 不在中国 IP 库中，本次封禁不会影响你。${NC}"
        risky=0
      else
        echo -e "   ${YELLOW}⚠ 中国 IP 库当前为空，无法判断该 IP 是否会被拦截。${NC}"
        echo -e "   ${YELLOW}  建议先执行菜单 2 更新 IP 库。${NC}"
        risky=1
      fi
    fi
  else
    if [ "$risky" -eq 1 ]; then
      echo -e "   ${YELLOW}无法识别你的来源 IP（非 SSH 会话？），请自行确认。${NC}"
    fi
  fi

  [ "$risky" -eq 0 ] && return 0

  echo -e "${YELLOW}如确认继续，请完整输入该端口号（输入其他内容则取消）：${NC}"
  echo -n "> "
  local answer
  read -r answer || return 1
  if [ "${answer:-}" != "$port" ]; then
    echo -e "${GREEN}已取消。${NC}"
    return 1
  fi
  return 0
}

# ================= 数据源解析 =================
looks_like_html() { grep -qiE '<!doctype|<html|</html>' "$1"; }

# 严格校验：每段 0-255，前缀 MIN_V4_PREFIX-32。
# 不带前缀的裸地址视为 /32 放行；前缀短于阈值的整条丢弃（见 MIN_V4_PREFIX 注释）。
extract_v4() {
  grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' \
  | awk -F'[./]' -v minp="$MIN_V4_PREFIX" '
      {
        if (NF != 4 && NF != 5) { next }
        for (i = 1; i <= 4; i++) { if ($i + 0 > 255) { next } }
        p = (NF == 5 ? $5 + 0 : 32)
        if (p > 32 || p < minp) { next }
        print $0
      }' \
  | sort -u
}

# IPv6 必须写成 地址/前缀，裸地址丢弃；前缀须在 MIN_V6_PREFIX-128 之间。
extract_v6() {
  tr -d ' \t\r' \
  | grep -E '^[0-9A-Fa-f:]+/[0-9]{1,3}$' \
  | awk -F'/' -v minp="$MIN_V6_PREFIX" '$2 + 0 <= 128 && $2 + 0 >= minp { print $0 }' \
  | sort -u
}

# APNIC IPv4：把 (起始地址, 地址数量) 分解为 CIDR。
# 原脚本只处理 2 的幂次，非幂次条目会被整条丢弃；这里做完整分解。
apnic_v4() {
  awk -F'|' '
    function ip2int(ip, a) { split(ip, a, "."); return ((a[1]*256 + a[2])*256 + a[3])*256 + a[4] }
    function int2ip(x) {
      return sprintf("%d.%d.%d.%d", int(x/16777216)%256, int(x/65536)%256, int(x/256)%256, x%256)
    }
    $2 == "CN" && $3 == "ipv4" && $4 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {
      start = ip2int($4); n = $5 + 0
      if (n < 1) next
      while (n > 0) {
        # start 的最低置位比特决定最大可用的对齐块
        if (start == 0) { align = 2147483648 }
        else { align = 1; s = start; while (s % 2 == 0) { align *= 2; s = int(s/2) } }
        blk = align
        while (blk > n) blk = blk / 2
        p = 32; b = blk; while (b > 1) { b = b / 2; p-- }
        printf("%s/%d\n", int2ip(start), p)
        start += blk; n -= blk
      }
    }
  ' "$1" | sort -u
}

apnic_v6() {
  awk -F'|' '$2 == "CN" && $3 == "ipv6" && $4 ~ /:/ && $5 ~ /^[0-9]+$/ && $5 + 0 <= 128 \
             { printf("%s/%s\n", $4, $5) }' "$1" | sort -u
}

# 两个文件内容是否完全一致。cmp 属 diffutils，精简系统可能没有，
# 所以退化到已有的摘要工具；两者都没有时返回 1（当作不同，宁可多重载一次）。
files_identical() {
  local a="$1" b="$2" h
  [ -f "$a" ] && [ -f "$b" ] || return 1
  if command -v cmp >/dev/null 2>&1; then
    cmp -s "$a" "$b"
    return $?
  fi
  h="$(_hash_cmd)"
  [ -z "$h" ] && return 1
  [ "$($h < "$a" | awk '{print $1}')" = "$($h < "$b" | awk '{print $1}')" ]
}

# 原子落盘：先写同目录临时文件再 mv，避免更新中途断电留下半个文件
save_data_file() {
  local src="$1" dst="$2" tmp="${2}.new.$$"
  cp -f "$src" "$tmp" || return 1
  chmod 600 "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$dst" || { rm -f "$tmp"; return 1; }
  return 0
}

# ================= 核心：更新 IP 库 =================
update_ips() {
  local d rc=0
  acquire_lock || return 1
  d="$(mktmpdir)" || { echo -e "${RED}创建临时目录失败。${NC}"; return 1; }
  _update_ips_impl "$d" || rc=$?
  rm -rf "$d"
  return $rc
}

_update_ips_impl() {
  local d="$1"
  echo -e "${CYAN}正在下载并更新 IP 库（IPv4 + IPv6）...${NC}"
  check_dependencies
  ensure_table || return 1

  local TMP="$d/dl" C4="$d/v4" C6="$d/v6" APNIC_CACHE="$d/apnic"
  : > "$C4"; : > "$C6"

  local CURL_OPTS=( -fsSL --connect-timeout 10 --max-time 180 --retry 3 --retry-delay 2 )
  # --retry-all-errors 是 curl 7.71+ 才有的，老版本会直接报错退出
  if curl --help all 2>/dev/null | grep -q 'retry-all-errors'; then
    CURL_OPTS+=( --retry-all-errors )
  fi
  local src4="" src6=""

  # ---- 主源：ipdeny ----
  if curl "${CURL_OPTS[@]}" -o "$TMP" "$IP_SOURCE" && ! looks_like_html "$TMP"; then
    extract_v4 < "$TMP" > "$C4"; src4="ipdeny"
  fi
  if curl "${CURL_OPTS[@]}" -o "$TMP" "$IP6_SOURCE" && ! looks_like_html "$TMP"; then
    extract_v6 < "$TMP" > "$C6"; src6="ipdeny"
  fi

  # ---- 备用源：APNIC（只在需要时下载一次） ----
  if ! [ -s "$C4" ] || ! [ -s "$C6" ]; then
    echo -e "${YELLOW}ipdeny 部分或全部不可用，尝试 APNIC 备用源...${NC}"
    if curl "${CURL_OPTS[@]}" -o "$APNIC_CACHE" "$APNIC_URL"; then
      if ! [ -s "$C4" ]; then apnic_v4 "$APNIC_CACHE" > "$C4"; src4="apnic"; fi
      if ! [ -s "$C6" ]; then apnic_v6 "$APNIC_CACHE" > "$C6"; src6="apnic"; fi
    else
      echo -e "${YELLOW}APNIC 下载失败。${NC}"
    fi
  fi

  local n4 n6
  n4="$(grep -c . "$C4" 2>/dev/null)"; n4="${n4:-0}"
  n6="$(grep -c . "$C6" 2>/dev/null)"; n6="${n6:-0}"

  # ---- 健全性阈值：数据明显偏少说明源站返回了残缺内容，拒绝替换 ----
  if [ "$n4" -gt 0 ] && [ "$n4" -lt "$MIN_V4_LINES" ]; then
    echo -e "${RED}IPv4 只解析出 $n4 条（低于下限 $MIN_V4_LINES），判定为数据源异常，放弃替换。${NC}"
    log "update: v4 sanity check failed ($n4 < $MIN_V4_LINES, src=$src4)"
    : > "$C4"; n4=0; src4="${src4}(rejected)"
  fi
  if [ "$n6" -gt 0 ] && [ "$n6" -lt "$MIN_V6_LINES" ]; then
    echo -e "${RED}IPv6 只解析出 $n6 条（低于下限 $MIN_V6_LINES），判定为数据源异常，放弃替换。${NC}"
    log "update: v6 sanity check failed ($n6 < $MIN_V6_LINES, src=$src6)"
    : > "$C6"; n6=0; src6="${src6}(rejected)"
  fi

  if [ "$n4" -eq 0 ] && [ "$n6" -eq 0 ]; then
    echo -e "${RED}更新失败：没能拿到通过校验的数据，已保留原有 IP 库。${NC}"
    echo -e "${YELLOW}排查建议：${NC}"
    echo "  curl -v $IP_SOURCE -o /tmp/cn.zone 2>&1 | tail -n 30"
    echo "  head -n 5 /tmp/cn.zone"
    log "Update failed: no usable data (src4=$src4 src6=$src6)"
    return 1
  fi

  [ "$n4" -eq 0 ] && echo -e "${YELLOW}本次未更新 IPv4，保留原有 IPv4 集合。${NC}"
  [ "$n6" -eq 0 ] && echo -e "${YELLOW}本次未更新 IPv6，保留原有 IPv6 集合。${NC}"

  # ---- 数据没变就别切槽位 ----
  # 切槽位会重建链，counter 随之清零。IP 库每月更新一次、上游常常没有任何变化，
  # 没必要为一份完全相同的数据丢掉一个月的命中统计。
  # 判定条件必须同时满足：新数据与盘上文件逐字节一致（未下载的协议族视为一致）、
  # 指纹与内核吻合、规则形态正确、集合非空——否则仍需老老实实重载。
  local same4=1 same6=1
  [ "$n4" -gt 0 ] && { files_identical "$C4" "$DATA_V4" || same4=0; }
  [ "$n6" -gt 0 ] && { files_identical "$C6" "$DATA_V6" || same6=0; }
  if [ "$same4" -eq 1 ] && [ "$same6" -eq 1 ] \
     && data_stamp_fresh \
     && _rules_ok "$(slot_or_default 4)" "$(slot_or_default 6)" \
     && { [ "$(active_count4)" -gt 0 ] || [ "$(active_count6)" -gt 0 ]; }; then
    apply_whitelist >/dev/null 2>&1 || log "update: apply_whitelist reported failure"
    apply_ports     >/dev/null 2>&1 || log "update: apply_ports reported failure"
    echo -e "${GREEN}IP 库已是最新（内容无变化），未重建规则，命中计数保留。${NC}"
    echo -e "  IPv4：源=${src4:-none} 解析=${n4} 内核条目=$(active_count4)"
    echo -e "  IPv6：源=${src6:-none} 解析=${n6} 内核条目=$(active_count6)"
    log "Update: data identical to on-disk copy, skipped reload (src4=$src4 src6=$src6)"
    return 0
  fi

  local before4 before6
  before4="$(slot_or_default 4)"; before6="$(slot_or_default 6)"

  load_and_swap "$C4" "$C6" || { echo -e "${RED}切换规则引用失败。${NC}"; return 1; }

  # 只有真正切换成功的协议族才更新持久化文件
  local saved=1
  [ "$(slot_or_default 4)" != "$before4" ] && \
    { save_data_file "$C4" "$DATA_V4" || { saved=0; log "save DATA_V4 failed"; }; }
  [ "$(slot_or_default 6)" != "$before6" ] && \
    { save_data_file "$C6" "$DATA_V6" || { saved=0; log "save DATA_V6 failed"; }; }

  # 指纹必须在数据文件落盘之后再写：data_fingerprint 摘要的是 DATA_V4/DATA_V6，
  # 提前写会把"旧文件的摘要"当成"内核里这份新数据"记下来。落盘失败时删除指纹，
  # 宁可下次 restore 多重载一次，也不能让文件与内核悄悄错开。
  if [ "$saved" -eq 1 ]; then
    write_data_stamp
  else
    rm -f "$STAMP_FILE" 2>/dev/null || true
  fi

  apply_whitelist >/dev/null 2>&1 || log "update: apply_whitelist reported failure"
  apply_ports     >/dev/null 2>&1 || log "update: apply_ports reported failure"

  local k4 k6
  k4="$(active_count4)"; k6="$(active_count6)"
  echo -e "${GREEN}更新完成。${NC}"
  echo -e "  IPv4：源=${src4:-none} 解析=${n4} 内核条目=${k4}"
  echo -e "  IPv6：源=${src6:-none} 解析=${n6} 内核条目=${k6}"
  echo -e "  ${CYAN}内核条目数是 auto-merge 合并后的结果，通常小于解析行数，属正常现象。${NC}"
  log "Update done. v4(src=$src4 parsed=$n4 kernel=$k4) v6(src=$src6 parsed=$n6 kernel=$k6)"
  return 0
}

# ================= 恢复 / 清理 =================
# 返回 0 = 规则已按配置完整装好；非 0 = 有环节失败（systemd 会因此把服务标记为 failed）
restore_all() {
  acquire_lock || return 1
  ensure_table || return 1

  local rc=0 have=0
  [ -s "$DATA_V4" ] && have=1
  [ -s "$DATA_V6" ] && have=1

  if [ "$have" -eq 1 ]; then
    # 内核里已经是这份数据、且规则形态正确时不必重新载入。
    # 重新载入会切换槽位并重建链，从而清零 counter。
    if data_stamp_fresh \
       && _rules_ok "$(slot_or_default 4)" "$(slot_or_default 6)" \
       && [ "$(active_count4)" -gt 0 -o "$(active_count6)" -gt 0 ]; then
      log "restore: data unchanged and rules intact, skip reload"
    elif load_and_swap "$DATA_V4" "$DATA_V6"; then
      # 这里的数据文件本来就在盘上、内容没动过，载入成功即可记录指纹
      write_data_stamp
    else
      log "restore: load_and_swap failed"
      rc=1
    fi
  fi

  apply_whitelist >/dev/null || { log "restore: apply_whitelist failed"; rc=1; }
  apply_ports              || { log "restore: apply_ports failed";     rc=1; }

  if [ "$have" -eq 0 ]; then
    # 锁已在函数开头拿到，acquire_lock 会因 _LOCK_HELD=1 直接返回，不会重复等待
    log "restore: no data files, triggering update"
    update_ips || rc=1
  fi

  log "Restore done (rc=$rc). v4=$(active_count4) v6=$(active_count6) ports=[$(list_blocked_ports 2>/dev/null | tr '\n' ' ')]"
  return $rc
}

# 健康检查：表被别的工具 flush 掉了就自动装回来
health_check() {
  if table_loaded && _rules_ok "$(slot_or_default 4)" "$(slot_or_default 6)"; then
    return 0
  fi
  echo -e "${YELLOW}检测到规则缺失或形态不符，正在自动恢复...${NC}"
  log "health: rules missing or mismatched, restoring"
  restore_all
}

clean_all() {
  # 一条命令带走整张表：链、规则、所有 set
  nft delete table inet "$TABLE" 2>/dev/null || true
  # 内核已经没有数据了，指纹必须失效，否则下次 restore 会误判"无需重载"
  rm -f "$STAMP_FILE" 2>/dev/null || true
  log "Cleaned: table inet $TABLE removed"
  echo -e "${GREEN}已移除 nftables 表 inet $TABLE。${NC}"
  if command -v systemctl >/dev/null 2>&1 \
     && systemctl is-enabled "$SERVICE_NAME" >/dev/null 2>&1; then
    echo -e "${YELLOW}注意：$SERVICE_NAME 仍处于开机自启状态，重启后规则会自动恢复。${NC}"
    echo -e "${YELLOW}      要持久停用请执行：$ALIAS_NAME --disable${NC}"
  fi
  return 0
}

# 持久停用：停掉并禁用所有单元，再清规则。配置文件保留，方便以后 --install 复原。
disable_all() {
  echo -e "${YELLOW}正在持久停用 China Blocker...${NC}"
  if command -v systemctl >/dev/null 2>&1; then
    local u
    for u in "${HEALTH_TIMER_NAME}.timer" "${UPDATE_TIMER_NAME}.timer" "$SERVICE_NAME"; do
      systemctl disable --now "$u" >/dev/null 2>&1 || true
    done
    systemctl reset-failed "$SERVICE_NAME" >/dev/null 2>&1 || true
  fi

  # nftables.service 的 drop-in 也必须一起摘掉，否则 systemctl restart nftables
  # 会通过 ExecStartPost 把整张表重新装回来，"持久停用"就名不副实了。
  if [ -f "$NFT_DROPIN_FILE" ]; then
    rm -f "$NFT_DROPIN_FILE" 2>/dev/null || true
    rmdir "$NFT_DROPIN_DIR" 2>/dev/null || true
    command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload >/dev/null 2>&1 || true
    echo -e "  - 已移除 nftables.service 的 drop-in"
  fi

  nft delete table inet "$TABLE" 2>/dev/null || true
  rm -f "$STAMP_FILE" 2>/dev/null || true
  log "Disabled: units stopped/disabled, drop-in removed, table removed"
  echo -e "${GREEN}已停用并禁用开机自启，规则已清除。配置文件保留在 $CONFIG_DIR。${NC}"
  echo -e "${CYAN}要重新启用：$ALIAS_NAME --install${NC}"
  return 0
}

# ================= 端口封禁 / 解封 =================
block_port() {
  acquire_lock || return 1
  ensure_table || return 1

  local port confirm cur
  # 先把当前状态摊开：不然用户看不见已经封了什么，容易重复输入同一个端口，
  # 或者想不起上次封的是 8080 还是 8081。
  mapfile -t cur < <(list_blocked_ports)
  if [ "${#cur[@]}" -gt 0 ]; then
    echo -e "${CYAN}当前已屏蔽端口（共 ${#cur[@]} 个，tcp + udp，IPv4 + IPv6）：${NC}"
    echo -e "  ${YELLOW}${cur[*]}${NC}"
  else
    echo -e "${CYAN}当前没有已屏蔽的端口。${NC}"
  fi

  echo -n "输入要屏蔽的端口 (如 80，回车取消): "
  read -r port || return 1
  [[ -z "${port:-}" ]] && return 0

  if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
    echo -e "${RED}端口无效：$port${NC}"; return 1
  fi

  # 先把白名单同步进内核，再做自锁评估和封禁。
  # 否则刚写进 whitelist.txt 还没生效的条目会被误判为"未放行"，
  # 更糟的是封禁生效时白名单还是空的，等于没有后路。
  apply_whitelist >/dev/null || echo -e "${YELLOW}白名单未能完整应用，请留意上面的提示。${NC}"

  lockout_check "$port" || return 0

  if grep -qx "$port" "$BLOCKED_PORTS_FILE" 2>/dev/null; then
    echo -e "${YELLOW}端口 $port 已处于封禁状态（仅中国 IP）。${NC}"
    apply_ports >/dev/null || true
    return 0
  fi

  echo "$port" >> "$BLOCKED_PORTS_FILE"
  if apply_ports; then
    echo -e "${GREEN}已屏蔽端口 $port（仅中国 IP，tcp + udp，IPv4 + IPv6）${NC}"
    log "block port $port"
  else
    grep -vx "$port" "$BLOCKED_PORTS_FILE" > "${BLOCKED_PORTS_FILE}.tmp" 2>/dev/null || : > "${BLOCKED_PORTS_FILE}.tmp"
    mv -f "${BLOCKED_PORTS_FILE}.tmp" "$BLOCKED_PORTS_FILE"
    echo -e "${RED}封禁失败，已回滚。${NC}"
    return 1
  fi
  return 0
}

unblock_port() {
  acquire_lock || return 1
  ensure_table || return 1

  local ports choice port i
  mapfile -t ports < <(list_blocked_ports)
  if [ "${#ports[@]}" -eq 0 ]; then
    echo -e "${YELLOW}当前没有已封禁的端口。${NC}"; return 0
  fi

  echo -e "${CYAN}已封禁端口列表（中国 IP 命中将 DROP）：${NC}"
  for i in "${!ports[@]}"; do printf "%2d) %s\n" "$((i+1))" "${ports[$i]}"; done

  echo -n "请输入要解封的端口（可输入序号或端口号，回车取消）: "
  read -r choice || return 1
  [[ -z "${choice:-}" ]] && return 0

  if [[ ! "$choice" =~ ^[0-9]+$ ]]; then
    echo -e "${RED}输入无效：$choice${NC}"; return 1
  fi

  if (( choice >= 1 && choice <= ${#ports[@]} )); then
    port="${ports[$((choice-1))]}"
  else
    port="$choice"
  fi

  if ! grep -qx "$port" "$BLOCKED_PORTS_FILE" 2>/dev/null; then
    echo -e "${YELLOW}端口 $port 未在封禁列表中。${NC}"; return 0
  fi

  grep -vx "$port" "$BLOCKED_PORTS_FILE" > "${BLOCKED_PORTS_FILE}.tmp" 2>/dev/null || : > "${BLOCKED_PORTS_FILE}.tmp"
  mv -f "${BLOCKED_PORTS_FILE}.tmp" "$BLOCKED_PORTS_FILE"

  if apply_ports; then
    echo -e "${GREEN}已解封端口 $port${NC}"
    log "unblock port $port"
  else
    echo -e "${RED}解封应用失败，请检查 nft 状态。${NC}"
    return 1
  fi
  return 0
}

# ================= 白名单编辑 =================
pick_editor() {
  if   command -v vim  >/dev/null 2>&1; then echo "vim"
  elif command -v vi   >/dev/null 2>&1; then echo "vi"
  elif command -v nano >/dev/null 2>&1; then echo "nano"
  else echo ""; fi
}

manage_whitelist() {
  acquire_lock || return 1
  local ed
  ed="$(pick_editor)"
  if [[ -z "$ed" ]]; then
    echo -e "${RED}未找到 vim/vi/nano，无法编辑白名单。${NC}"
    echo -e "${YELLOW}可直接编辑文件：$WHITELIST_FILE${NC}"
    return 1
  fi
  [[ "$ed" != "vim" ]] && echo -e "${YELLOW}未安装 vim，使用 $ed 打开白名单文件。${NC}"
  "$ed" "$WHITELIST_FILE"
  if apply_whitelist; then
    echo -e "${GREEN}白名单已应用：IPv4 $(nft_set_count "$WL4") 条，IPv6 $(nft_set_count "$WL6") 条${NC}"
  else
    echo -e "${YELLOW}白名单已部分应用，内核当前：IPv4 $(nft_set_count "$WL4") 条，IPv6 $(nft_set_count "$WL6") 条${NC}"
  fi
  return 0
}

# ================= 状态报告 =================
show_status_report() {
  clear 2>/dev/null || true
  echo -e "${CYAN}==================================================${NC}"
  echo -e "${CYAN}   China Blocker (nftables) v$CB_VERSION 状态报告   ${NC}"
  echo -e "${CYAN}==================================================${NC}"

  echo -e "${GREEN}[1] 核心服务状态 (systemd)${NC}"
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active "$SERVICE_NAME" >/dev/null 2>&1; then
    echo -e "  - 防护服务状态 : ${GREEN}● 正在运行 (Active)${NC}"
  else
    echo -e "  - 防护服务状态 : ${RED}○ 已停止 (Inactive)${NC}"
  fi

  if command -v systemctl >/dev/null 2>&1 && systemctl is-active "${UPDATE_TIMER_NAME}.timer" >/dev/null 2>&1; then
    echo -e "  - 定时更新状态 : ${GREEN}● 已启用 (Active)${NC}"
    local info next
    info="$(systemctl list-timers --all 2>/dev/null | grep "${UPDATE_TIMER_NAME}\.timer")"
    if [ -n "$info" ]; then
      next="$(echo "$info" | sed 's/^[ \t]*//;s/[ \t][ \t]*/ /g' | cut -d' ' -f1-3)"
      echo -e "  - 下次更新时间 : ${YELLOW}${next}${NC}"
    fi
  else
    echo -e "  - 定时更新状态 : ${RED}○ 已禁用 (Inactive)${NC}"
  fi

  if command -v systemctl >/dev/null 2>&1 && systemctl is-active "${HEALTH_TIMER_NAME}.timer" >/dev/null 2>&1; then
    echo -e "  - 健康检查     : ${GREEN}● 每 $HEALTH_INTERVAL 检查一次${NC}"
  else
    echo -e "  - 健康检查     : ${YELLOW}○ 未启用${NC}"
  fi
  echo -e "--------------------------------------------------"

  echo -e "${GREEN}[2] nftables 状态${NC}"
  echo -e "  - nft 版本         : ${CYAN}$(nft_version)${NC}"
  if table_loaded; then
    echo -e "  - 规则表 inet $TABLE : ${GREEN}● 已加载${NC}"
    local ch
    while read -r ch; do
      [ -z "$ch" ] && continue
      if [ "$(_actual_rules "$ch")" = "$(_expected_rules "$(slot_or_default 4)" "$(slot_or_default 6)")" ]; then
        echo -e "    · chain $ch : ${GREEN}规则完整${NC} (priority $HOOK_PRIORITY, policy accept)"
      else
        echo -e "    · chain $ch : ${RED}规则不符预期${NC}（可执行 $ALIAS_NAME --restore 修复）"
      fi
    done < <(active_chains)
    [ "$BLOCK_FORWARD" = "1" ] || \
      echo -e "    ${YELLOW}· forward hook 未启用：Docker 发布端口不会被拦截${NC}"
    echo -e "  - 生效槽位         : IPv4=${CYAN}${S4PRE}$(slot_or_default 4)${NC}  IPv6=${CYAN}${S6PRE}$(slot_or_default 6)${NC}"
  else
    echo -e "  - 规则表 inet $TABLE : ${RED}○ 未加载（防护未生效！）${NC}"
  fi
  echo -e "  - 累计丢弃报文     : ${YELLOW}$(nft_drop_counter)${NC} (自上次规则重建起)"
  echo -e "--------------------------------------------------"

  echo -e "${GREEN}[3] IP 集合状态（读自内核）${NC}"
  local c4 c6
  c4="$(active_count4)"; c6="$(active_count6)"
  if [ "${c4:-0}" -gt 0 ]; then
    echo -e "  - 中国 IPv4 条目 : ${GREEN}${c4}${NC}"
  else
    echo -e "  - 中国 IPv4 条目 : ${RED}0${NC} (警告: 库为空，防护可能未生效！)"
  fi
  if [ "${c6:-0}" -gt 0 ]; then
    echo -e "  - 中国 IPv6 条目 : ${GREEN}${c6}${NC}"
  else
    echo -e "  - 中国 IPv6 条目 : ${YELLOW}0${NC} (未获取到 IPv6 数据)"
  fi
  echo -e "  ${CYAN}注：条目数为 auto-merge 合并后的结果，小于源文件行数属正常现象。${NC}"
  echo -e "--------------------------------------------------"

  echo -e "${GREEN}[4] 白名单（读自内核，即真正生效的条目）${NC}"
  local kwl fwl e
  kwl="$(mktmp)"; fwl="$(mktmp)"
  { nft_set_elements "$WL4"; nft_set_elements "$WL6"; } | sort -u > "$kwl"
  if [ -s "$kwl" ]; then
    while read -r e; do
      [ -z "$e" ] && continue
      echo -e "  - ${CYAN}${e}${NC}"
    done < "$kwl"
  else
    echo -e "  - ${YELLOW}[当前无生效的白名单 IP]${NC}"
  fi

  # 找出"配置文件里写了但实际没生效"的条目。
  # 不能拿文件文本直接和 nft 的输出比字符串：nft 会把 1.2.3.4/32 打印成 1.2.3.4、
  # 把 IPv6 压缩成最简写法，纯文本比对会产生大量误报。
  # 这里改用 `nft get element` 让内核自己判断该条目在不在集合里，写法差异由内核消化。
  local miss=0
  : > "$fwl"
  while read -r e; do
    [ -z "$e" ] && continue
    local st q
    if [[ "$e" == *:* ]]; then st="$WL6"; else st="$WL4"; fi
    # 单主机前缀要去掉才查得到：interval set 里 1.2.3.4/32 与 1.2.3.4 不是同一个写法。
    # IPv6 的大小写与 0 压缩差异由内核自己消化，不必在这里处理。
    q="${e%/32}"; q="${q%/128}"
    if ! nft get element inet "$TABLE" "$st" "{ $q }" >/dev/null 2>&1; then
      echo "$e" >> "$fwl"
      miss=$(( miss + 1 ))
    fi
  done < <(sed -E 's/#.*$//' "$WHITELIST_FILE" 2>/dev/null | tr -d ' \t\r' | grep -v '^$' | sort -u)

  if [ "$miss" -gt 0 ]; then
    echo -e "  ${RED}以下 $miss 条写在 $WHITELIST_FILE 里但未生效：${NC}"
    sed 's/^/    ! /' "$fwl"
    echo -e "  ${YELLOW}原因通常是格式非法，或与另一条白名单重叠被跳过。${NC}"
  fi
  rm -f "$kwl" "$fwl"
  echo -e "--------------------------------------------------"

  echo -e "${GREEN}[5] 已封禁的端口 (中国 IP 命中将 DROP)${NC}"
  local bp p
  mapfile -t bp < <(nft_set_elements "$PORTSET" | sort -n)
  if [ "${#bp[@]}" -gt 0 ]; then
    echo -ne "  - 内核生效端口 : "
    for p in "${bp[@]}"; do echo -ne "${RED}[${p}]${NC} "; done
    echo ""
  else
    echo -e "  - 内核生效端口 : ${YELLOW}[当前未封禁任何端口]${NC}"
  fi
  echo -e "${CYAN}==================================================${NC}"
  echo -e "查看完整规则： ${CYAN}nft list table inet $TABLE${NC}"
}

# ================= 快捷命令 cb =================
# 建立 /usr/local/bin/cb -> china_blocker 软链接，安装后直接输入 cb 即可调出菜单。
install_alias() {
  if [ -e "$ALIAS_PATH" ] || [ -L "$ALIAS_PATH" ]; then
    local cur
    cur="$(readlink -f "$ALIAS_PATH" 2>/dev/null || echo "")"
    if [ "$cur" != "$TARGET_PATH" ]; then
      echo -e "${YELLOW}$ALIAS_PATH 已被其他程序占用，跳过创建 ${ALIAS_NAME} 快捷命令。${NC}"
      echo -e "${YELLOW}你仍可使用完整命令：$TARGET_PATH${NC}"
      return 1
    fi
  fi

  if ! ln -sfn "$TARGET_PATH" "$ALIAS_PATH" 2>/dev/null; then
    echo -e "${YELLOW}创建 ${ALIAS_NAME} 快捷命令失败，可手动执行：ln -sfn $TARGET_PATH $ALIAS_PATH${NC}"
    return 1
  fi

  # PATH 里是否有同名命令抢在前面
  local resolved
  resolved="$(command -v "$ALIAS_NAME" 2>/dev/null || echo "")"
  if [ -n "$resolved" ] && [ "$(readlink -f "$resolved" 2>/dev/null)" != "$TARGET_PATH" ]; then
    echo -e "${YELLOW}注意：PATH 中已存在优先级更高的 ${ALIAS_NAME}（$resolved），请改用 $ALIAS_PATH${NC}"
  fi
  return 0
}

remove_alias() {
  if [ -L "$ALIAS_PATH" ]; then
    local cur
    cur="$(readlink -f "$ALIAS_PATH" 2>/dev/null || echo "")"
    [ "$cur" = "$TARGET_PATH" ] && rm -f "$ALIAS_PATH"
  fi
}

# ================= systemd =================
install_systemd_units() {
  local SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
  local UPDATE_SERVICE_FILE="/etc/systemd/system/${UPDATE_SERVICE_NAME}.service"
  local UPDATE_TIMER_FILE="/etc/systemd/system/${UPDATE_TIMER_NAME}.timer"
  local HEALTH_SERVICE_FILE="/etc/systemd/system/${HEALTH_SERVICE_NAME}.service"
  local HEALTH_TIMER_FILE="/etc/systemd/system/${HEALTH_TIMER_NAME}.timer"

  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=China IP Blocker (nftables)
After=network.target network-online.target nftables.service firewalld.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$TARGET_PATH --restore
ExecReload=$TARGET_PATH --restore
ExecStop=$TARGET_PATH --clean
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

  cat > "$UPDATE_SERVICE_FILE" <<EOF
[Unit]
Description=China Blocker - Update China IP sets
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

  # 健康检查：别的工具执行 flush ruleset 后能自动把表装回来
  cat > "$HEALTH_SERVICE_FILE" <<EOF
[Unit]
Description=China Blocker - Health check / self-heal
After=network.target

[Service]
Type=oneshot
ExecStart=$TARGET_PATH --health
StandardOutput=journal
StandardError=journal
EOF

  cat > "$HEALTH_TIMER_FILE" <<EOF
[Unit]
Description=China Blocker - Health check timer

[Timer]
OnBootSec=2min
OnUnitActiveSec=$HEALTH_INTERVAL
Unit=${HEALTH_SERVICE_NAME}.service

[Install]
WantedBy=timers.target
EOF

  # 多数发行版的 /etc/nftables.conf 第一行就是 `flush ruleset`，
  # nftables.service 一旦重启就会把我们的表一起清掉。
  # 挂一个 drop-in，让它启动后自动把本表装回去。
  if systemctl list-unit-files 2>/dev/null | grep -q '^nftables\.service'; then
    mkdir -p "$NFT_DROPIN_DIR"
    cat > "$NFT_DROPIN_FILE" <<EOF
[Service]
ExecStartPost=-$TARGET_PATH --restore
EOF
    echo -e "${CYAN}已为 nftables.service 添加 drop-in，避免 'flush ruleset' 清掉本表。${NC}"
  fi
}

install_service() {
  echo -e "${CYAN}正在安装/修复服务...${NC}"
  acquire_lock || return 1
  check_dependencies

  if ! command -v systemctl >/dev/null 2>&1; then
    echo -e "${RED}未检测到 systemctl（非 systemd 系统），无法安装为服务/定时器。${NC}"
    echo -e "${YELLOW}你仍可手动运行：sudo $TARGET_PATH --update / --restore${NC}"
    return 1
  fi

  mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" 2>/dev/null || true
  touch "$LOG_FILE" 2>/dev/null || true

  local SELF
  SELF="$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || echo "$0")"
  if [[ "$SELF" != "$TARGET_PATH" ]]; then
    if ! cp "$SELF" "$TARGET_PATH" 2>/dev/null; then
      echo -e "${RED}复制脚本失败：无法从 $SELF 复制到 $TARGET_PATH${NC}"
      echo -e "${YELLOW}如果你是用 bash <(curl ...) 方式运行，请先保存为文件再执行。${NC}"
      return 1
    fi
  fi
  chmod +x "$TARGET_PATH"
  echo -e "脚本已部署到: ${GREEN}$TARGET_PATH${NC}"
  install_alias && echo -e "快捷命令已就绪: 以后直接输入 ${GREEN}sudo ${ALIAS_NAME}${NC} 即可调出菜单"

  ensure_table || return 1

  echo -e "${CYAN}安装过程中自动更新一次 IP 库（ipdeny 优先）...${NC}"
  if update_ips; then
    echo -e "${GREEN}✅ IP 库就绪${NC}"
  else
    echo -e "${YELLOW}提示：本次自动更新失败（网络或源站问题）。安装继续，可稍后手动更新。${NC}"
  fi

  # 顺序很重要：先放行白名单，再启用封禁
  apply_whitelist >/dev/null || echo -e "${YELLOW}白名单未能完整应用，请执行菜单 6 查看详情。${NC}"
  apply_ports              || echo -e "${YELLOW}端口集合应用失败。${NC}"

  install_systemd_units

  # 规则此刻已经装好了，下面只动 systemd。必须先放锁：
  # china_blocker.service 是 Type=oneshot，`systemctl restart` 会等 `--restore` 执行完毕，
  # 而 `--restore` 要抢同一把锁，握着锁去 restart 就是等自己，只能耗到 flock 超时。
  release_lock

  systemctl daemon-reload
  systemctl enable  "$SERVICE_NAME" >/dev/null 2>&1
  systemctl restart "$SERVICE_NAME" >/dev/null 2>&1
  systemctl enable  "${UPDATE_TIMER_NAME}.timer" >/dev/null 2>&1
  systemctl restart "${UPDATE_TIMER_NAME}.timer" >/dev/null 2>&1
  systemctl enable  "${HEALTH_TIMER_NAME}.timer" >/dev/null 2>&1
  systemctl restart "${HEALTH_TIMER_NAME}.timer" >/dev/null 2>&1

  echo -e "${GREEN}✅ 安装完成！${NC}"
  echo -e "服务已启动并设置为开机自启。"
  echo -e "${GREEN}以后随时输入 ${ALIAS_NAME} 即可调出本菜单（如：sudo ${ALIAS_NAME}）${NC}"
  echo -e "${GREEN}现在可直接开始屏蔽端口：菜单选择 3（屏蔽端口）${NC}"
  echo -e "${CYAN}已启用 systemd timer：$ON_CALENDAR 自动更新 IP 库（Persistent=true）${NC}"
  echo -e "${CYAN}已启用健康检查：每 $HEALTH_INTERVAL 确认规则仍在${NC}"
  [ "$BLOCK_FORWARD" = "1" ] && \
    echo -e "${CYAN}已同时挂 input 与 forward hook（覆盖 Docker 发布端口）${NC}"
  return 0
}

uninstall_all() {
  echo -e "${YELLOW}正在卸载...${NC}"
  if command -v systemctl >/dev/null 2>&1; then
    local u
    for u in "${HEALTH_TIMER_NAME}.timer" "${UPDATE_TIMER_NAME}.timer" "$SERVICE_NAME"; do
      systemctl stop    "$u" 2>/dev/null || true
      systemctl disable "$u" 2>/dev/null || true
    done
    rm -f "/etc/systemd/system/${HEALTH_TIMER_NAME}.timer" \
          "/etc/systemd/system/${HEALTH_SERVICE_NAME}.service" \
          "/etc/systemd/system/${UPDATE_TIMER_NAME}.timer" \
          "/etc/systemd/system/${UPDATE_SERVICE_NAME}.service" \
          "/etc/systemd/system/${SERVICE_NAME}.service" 2>/dev/null || true
    rm -f "$NFT_DROPIN_FILE" 2>/dev/null || true
    rmdir "$NFT_DROPIN_DIR" 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
    # 清掉可能残留的 failed 状态，避免 systemctl --failed 里留一条幽灵记录
    for u in "$SERVICE_NAME" "${UPDATE_SERVICE_NAME}.service" "${HEALTH_SERVICE_NAME}.service"; do
      systemctl reset-failed "$u" >/dev/null 2>&1 || true
    done
  fi

  nft delete table inet "$TABLE" 2>/dev/null || true
  remove_alias
  rm -rf "$CONFIG_DIR"
  rm -f "$TARGET_PATH"
  echo -e "${GREEN}卸载完成。${NC}"
  echo -e "${CYAN}日志已保留在 $LOG_FILE（如需删除：rm -f $LOG_FILE）${NC}"
  exit 0
}

# ================= 脚本自更新 =================
update_script() {
  echo -e "${CYAN}正在检查并下载最新脚本...${NC}"
  if [[ -z "$SCRIPT_UPDATE_URL" || "$SCRIPT_UPDATE_URL" == *"your-username"* ]]; then
    echo -e "${YELLOW}尚未配置 SCRIPT_UPDATE_URL，请先在脚本顶部的配置区改为你自己的直链。${NC}"
    return 1
  fi

  local d TMP_SCRIPT
  d="$(mktmpdir)" || return 1
  TMP_SCRIPT="$d/new.sh"

  if ! curl -fsSL --connect-timeout 10 -o "$TMP_SCRIPT" "$SCRIPT_UPDATE_URL"; then
    echo -e "${RED}下载失败，请检查网络或 URL 是否正确！${NC}"; rm -rf "$d"; return 1
  fi
  if ! head -n 1 "$TMP_SCRIPT" | grep -q '^#!/bin/bash'; then
    echo -e "${RED}下载的文件内容无效（未检测到 #!/bin/bash）。更新失败！${NC}"
    echo -e "${YELLOW}可能是网络拦截或 URL 错误导致拉取到了 HTML 页面。${NC}"; rm -rf "$d"; return 1
  fi
  # 防止把 nftables 版覆盖成 iptables 版（同一个仓库文件名可能没变）
  if ! grep -q 'CB_FLAVOR=nftables' "$TMP_SCRIPT"; then
    echo -e "${RED}下载到的脚本不是 nftables 版（缺少 CB_FLAVOR=nftables 标记），已放弃更新。${NC}"
    echo -e "${YELLOW}请确认 SCRIPT_UPDATE_URL 指向的是 nftables 版脚本。${NC}"
    rm -rf "$d"; return 1
  fi
  if ! bash -n "$TMP_SCRIPT" 2>/dev/null; then
    echo -e "${RED}下载的脚本语法检查未通过，已放弃更新。${NC}"; rm -rf "$d"; return 1
  fi

  local newver
  newver="$(grep -m1 '^CB_VERSION=' "$TMP_SCRIPT" | cut -d'"' -f2)"
  echo -e "${CYAN}当前版本 $CB_VERSION → 下载版本 ${newver:-未知}${NC}"

  # 原子替换：写同目录临时文件后 mv，避免中途失败留下截断的脚本
  local SELF t
  SELF="$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || echo "$0")"
  local ok=0
  for t in "$SELF" "$TARGET_PATH"; do
    [ -z "$t" ] && continue
    [ -f "$t" ] || continue
    [ -w "$(dirname "$t")" ] || continue
    if cp -f "$TMP_SCRIPT" "${t}.new.$$" && chmod +x "${t}.new.$$" && mv -f "${t}.new.$$" "$t"; then
      ok=1
    else
      rm -f "${t}.new.$$" 2>/dev/null || true
      echo -e "${YELLOW}更新 $t 失败。${NC}"
    fi
    [ "$SELF" = "$TARGET_PATH" ] && break
  done
  rm -rf "$d"

  if [ "$ok" -eq 0 ]; then
    echo -e "${RED}没有任何文件被更新。${NC}"; return 1
  fi
  echo -e "${GREEN}脚本自更新完成！脚本将自动退出，请重新运行。${NC}"
  exit 0
}

# ================= 菜单 =================
show_menu() {
  local choice back
  while true; do
    clear 2>/dev/null || true
    echo -e "${CYAN}====================================${NC}"
    echo -e "${CYAN} 🇨🇳 中国 IP 屏蔽助手 (nftables 版) ${NC}"
    echo -e "${CYAN}          v$CB_VERSION${NC}"
    echo -e "${CYAN}====================================${NC}"
    echo -e "1. ${GREEN}安装/修复服务${NC} (推荐，只需运行一次)"
    echo -e "2. ${YELLOW}更新 IP 库${NC} (IPv4 + IPv6)"
    echo -e "3. ${RED}屏蔽端口${NC}"
    echo -e "4. ${GREEN}解封端口${NC}"
    echo -e "5. 编辑白名单"
    echo -e "6. 查看状态"
    echo -e "7. ${RED}卸载服务${NC}"
    echo -e "8. ${YELLOW}持久停用${NC} (停服务但保留配置)"
    echo -e "99. ${YELLOW}更新脚本${NC}"
    echo -e "0. 退出"
    echo -e "------------------------------------"
    echo -e "${CYAN}提示：安装后随时输入 ${ALIAS_NAME} 即可调出本菜单${NC}"
    echo -n "请选择: "
    # 读到 EOF（例如被管道调用）时直接退出，避免空转成死循环
    if ! read -r choice; then
      echo ""
      exit 0
    fi

    case "${choice:-}" in
      1)  install_service ;;
      2)  update_ips ;;
      3)  block_port ;;
      4)  unblock_port ;;
      5)  manage_whitelist ;;
      6)  show_status_report ;;
      7)  uninstall_all ;;
      8)  disable_all ;;
      99) update_script ;;
      0)  exit 0 ;;
      *)  echo "无效选择" ;;
    esac

    # 下一轮循环会 clear 屏幕，所以这里必须停下来让用户看完刚才的输出。
    # 同时给出退出路径：安装/更新这类一次性动作做完后，多数人是想直接走的。
    echo ""
    echo -e "${CYAN}------------------------------------${NC}"
    echo -n "回车返回主菜单，输入 q 退出: "
    if ! read -r back; then
      echo ""
      exit 0
    fi
    case "${back:-}" in
      q|Q|0|exit|quit) echo -e "${GREEN}已退出。${NC}"; exit 0 ;;
    esac
  done
}

# ================= 入口 =================
# 依赖检查分两档：只有真正联网的动作才允许触发包安装，
# 其余动作（开机恢复、清理、看状态）只做内核可达性检查，避免在
# 开机早期或离线环境里卡在 apt-get 上。
case "${1:-}" in
  --install|--update) : ;;    # 由各自函数内部调用 check_dependencies
  *)                  check_kernel_nft ;;
esac

case "${1:-}" in
  --install)  install_service ;;
  --update)   update_ips ;;
  --block)    block_port ;;
  --restore)  restore_all ;;
  --health)   health_check ;;
  --clean)    clean_all ;;
  --disable)  disable_all ;;
  --status)   show_status_report ;;
  "")         show_menu ;;
  *)          echo -e "${RED}未知参数：$1${NC}"; show_help; exit 1 ;;
esac
exit $?
