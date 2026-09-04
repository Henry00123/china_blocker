# China Blocker（中国 IP 屏蔽助手 · nftables 版）

一个用于 Linux 服务器的“一键版”脚本：基于 **纯 nftables**（不再依赖 iptables / ipset），按端口屏蔽来自 **中国 IPv4 与 IPv6** 的访问，并提供 **白名单放行**、**systemd 开机自启**、**systemd timer 定时更新 IP 库**、**`cb` 快捷命令** 等功能。

> 适合：海外服务器、需要按端口限制中国访问的场景
> 支持：Debian / Ubuntu / CentOS / RHEL / Rocky / AlmaLinux 等主流发行版（systemd + nftables 环境）
> 要求：内核支持 nf_tables（脚本启动时以 `nft list ruleset` 能否执行为准），容器环境需具备 `NET_ADMIN` 能力
> 建议：`nft` ≥ 0.9 以启用 `auto-merge`；低于该版本脚本会自动退化为普通 interval set 并给出提示，功能不受影响。脚本本身不做内核 / nft 版本比较

------

## 功能特性

- **按端口屏蔽**中国 IP，TCP/UDP、IPv4/IPv6 同时生效（单张 `table inet` 双栈）
- **白名单放行**，规则永远排在封禁规则之前
- **自动更新 IP 库**：ipdeny `cn.zone` 优先，主源失败时回落 APNIC delegated（v4/v6 共用）
- **更新期间防护不中断**：双槽位 set + 分块载入 + 一次事务切换引用
- **覆盖 Docker 发布端口**：同时挂 `input` 与 `forward` hook，可关
- **SSH 自锁检查**：探测真实 SSH 端口，并判断你当前的 IP 会不会被拦
- **健康检查自愈**：规则被别的工具清掉后 15 分钟内自动恢复
- **数据健全性校验**：逐条格式校验 + 前缀下限（挡住 `/0` 全网条目）+ 总量下限，异常数据源不会削弱现有防护
- **并发安全**：`flock` 文件锁，定时任务与手动操作不会互相踩
- **`cb` 快捷命令**：安装后直接 `sudo cb` 调出菜单
- 一键安装 / 修复，systemd 开机自启 + timer 定时更新；兼容 gawk / mawk / busybox awk

------

## 工作原理（简述）

脚本创建一张**独立的** nftables 表，不再往 `INPUT` 里抢插规则位置：

```
table inet china_blocker {
    set china4_a       { type ipv4_addr;    flags interval; auto-merge; }
    set china4_b       { type ipv4_addr;    flags interval; auto-merge; }
    set china6_a       { type ipv6_addr;    flags interval; auto-merge; }
    set china6_b       { type ipv6_addr;    flags interval; auto-merge; }
    set whitelist4     { type ipv4_addr;    flags interval; }
    set whitelist6     { type ipv6_addr;    flags interval; }
    set blocked_ports  { type inet_service; }

    chain input {
        type filter hook input priority -10; policy accept;

        ip  saddr @whitelist4 return
        ip6 saddr @whitelist6 return
        tcp dport @blocked_ports ip  saddr @china4_a counter drop
        udp dport @blocked_ports ip  saddr @china4_a counter drop
        tcp dport @blocked_ports ip6 saddr @china6_a counter drop
        udp dport @blocked_ports ip6 saddr @china6_a counter drop
    }

    chain forward {           # 与 input 完全相同的规则序列
        type filter hook forward priority -10; policy accept;
        ...                   # 覆盖 Docker 发布端口，可用 BLOCK_FORWARD=0 关闭
    }
}
```

几个关键设计：

**`table inet` 双栈。** IPv4 与 IPv6 共用一张表，每个 hook 一条链，同一条链里用 `ip saddr` / `ip6 saddr` 分别匹配，不需要为两个协议族维护两套规则。

**`priority -10` 取代“插到 INPUT 第 1 条”。** 原版靠 `iptables -I INPUT 1/2` 争抢位置，容易被 ufw、firewalld、Docker 重新插入的规则挤到后面。nftables 里各表按 hook 优先级排序，`-10` 早于常规 filter（`0`），效果稳定且与其他防火墙互不干扰。

**白名单用 `return` 而非 `accept`。** `return` 只结束本表的求值，后续同/低优先级的表（ufw、firewalld）照常评估，所以白名单不会意外把服务器整个放行。

**`policy accept` = 默认放行。** 即使 set 为空、数据没下载成功，或规则只装了一半，结果都是“不拦”，不会把自己锁在门外。

**双槽位 set + 原子切换。** `nft -f` 把整个文件作为一个 netlink 批次提交，超过约 64 KB 就会报 `Message too long`；而中国 IPv4 库有一万多条 CIDR，远超这个上限。脚本因此为每个协议族准备两个槽位（`china4_a` / `china4_b`）：先把新数据**分块**写进当前**未被引用**的那个槽位（分块非原子，但对外不可见），全部写完后再用一次很小的事务把链里的 set 引用整体切过去，最后清空旧槽位释放内存。对外表现为瞬间生效，且更新失败时旧数据继续生效。

**配置文件是唯一真相来源。** 白名单、封禁端口、IP 库都以纯文本落盘，重启恢复就是重新读几个文件 → 写入 set，不再需要 `ipset save/restore`，也不用解析防火墙输出反推状态。

**规则先比对再重建。** 脚本会把内核里的实际规则序列（归一化掉 counter 数值后）与期望序列逐字比对，一致就跳过重建。同时 `--restore` 会用数据文件的摘要 + 当前槽位算一个指纹存在 `.datastamp`，指纹没变且规则完好时连 IP 库都不重新载入。

`--update` 也有同样的保护：新下载的数据与盘上文件逐字节一致时（IP 库每月更新一次，上游常常没有任何变化）跳过切槽位，只重新应用白名单与端口。因此**重复执行 `--restore` 或 `--update` 都不会清零 counter**；只有数据确实变了、或表被删 / 规则被破坏时才会真正重建。

**坏行不影响整批。** 单个 nft 事务里只要有一条记录不被接受，整批就会被拒绝。载入 IP 库时若某块提交失败，脚本会自动把该块降级为**逐行载入**，跳过坏行并写入日志，而不是丢掉整块 1500 条；只有当一个文件的所有行都不可用时才判定失败，此时**保留原有集合**（因为写的是未被引用的槽位，旧数据始终完好）。载入前还会先剥掉空行与注释，所以手工编辑数据文件不会因为一个空行导致后半截被丢掉。

白名单也有逐行降级，但语义不同：它会先清空 `whitelist4`/`whitelist6` 再逐条写回，所以**整份白名单都不可用时内核白名单会变成空**，不像 IP 库那样有旧数据兜底。另外白名单集合没有启用 `auto-merge`，两条互相重叠的条目（例如同时写 `10.0.0.1` 和 `10.0.0.0/24`）会被内核拒绝并触发降级，后写的那条会被跳过。

------

## 安装 & 使用

```bash
curl -fsSL https://raw.githubusercontent.com/Henry00123/china_blocker/main/china_blocker.sh -o china_blocker.sh && chmod +x china_blocker.sh && sudo ./china_blocker.sh
```

执行后在菜单中选择：

- `1` 安装/修复服务（推荐首次运行，会自动更新一次 IP 库）
- `3` 屏蔽端口
- `4` 解封端口

安装完成后直接 `sudo cb` 就能调出菜单。`cb` 是 `/usr/local/bin/cb → /usr/local/bin/china_blocker` 的软链接；若该路径已被其他程序占用，脚本会跳过创建并提示你使用完整命令，不会覆盖别人的文件。

### 命令行参数

两个命令等价（`cb` 就是 `china_blocker`）：

| 参数           | 作用                                                |
| -------------- | --------------------------------------------------- |
| *（不带参数）*   | 进入交互菜单                                        |
| `--install`    | 安装/修复服务                                       |
| `--update`     | 更新中国 IP 库（IPv4 + IPv6）                       |
| `--block`      | 交互式屏蔽端口                                      |
| `--restore`    | 从配置恢复规则（systemd 开机时调用）                |
| `--health`     | 健康检查：规则缺失或被覆盖时自动恢复（timer 调用）  |
| `--clean`      | 移除 nftables 表与全部规则（**不动** systemd 单元） |
| `--disable`    | 持久停用：停掉并 disable 全部单元，再移除规则       |
| `--status`     | 打印状态报告                                        |
| `--version`    | 打印版本号                                          |
| `-h`,`--help`  | 显示帮助                                            |

`--help` / `--version` **不需要 root**，也不会创建任何文件；其余参数都需要 root。

菜单项 `1`~`8` 依次为：安装/修复服务、更新 IP 库、屏蔽端口、解封端口、编辑白名单、查看状态、卸载服务、持久停用；`99` 更新脚本，`0` 退出。

### 并发保护

`--install` / `--update` / `--restore` / `--block`、解封端口、编辑白名单都会先用 `flock` 抢一把文件锁（`/etc/china_blocker/.lock`，最长等待 180 秒）。这样定时更新 timer 与你手动敲的命令、开机 restore 撞在一起时会排队执行，不会互相踩掉对方写了一半的集合。

`--health` 先做无锁的只读比对，只有判定需要恢复时才通过 `--restore` 拿锁。`--clean` / `--disable` 不加锁：它们移除规则靠单条 `nft delete table`（本身原子），且这两个动作的语义就是「无条件停掉」，没有与并发写者协商的必要。系统上没有 `flock` 命令时脚本不会因此中止，只是退化为无锁运行。

`--install` 会在规则装好、开始动 systemd 之前**主动放锁**。`china_blocker.service` 是 `Type=oneshot`，`systemctl restart` 会一直等到 `ExecStart`（即 `--restore`）跑完；握着锁去 restart 就是父进程等子进程、子进程等锁，只能耗到 180 秒超时才继续。放锁之后的操作只碰 systemd 单元文件，不写内核集合，不需要互斥。

------

## 配置文件与路径

| 作用                             | 路径                                                    |
| -------------------------------- | ------------------------------------------------------- |
| 安装后的脚本路径（systemd 调用） | `/usr/local/bin/china_blocker`                          |
| 快捷命令（软链接）               | `/usr/local/bin/cb`                                     |
| 配置目录                         | `/etc/china_blocker/`                                   |
| 白名单文件                       | `/etc/china_blocker/whitelist.txt`                      |
| 已封禁端口列表                   | `/etc/china_blocker/blocked_ports.txt`                  |
| 中国 IPv4 库（纯文本 CIDR）      | `/etc/china_blocker/china_ipv4.txt`                     |
| 中国 IPv6 库（纯文本 CIDR）      | `/etc/china_blocker/china_ipv6.txt`                     |
| 并发锁文件                       | `/etc/china_blocker/.lock`                              |
| 数据指纹（避免无谓重建规则）     | `/etc/china_blocker/.datastamp`                         |
| 日志文件                         | `/var/log/china_blocker.log`                            |
| systemd service                  | `/etc/systemd/system/china_blocker.service`             |
| systemd update service           | `/etc/systemd/system/china_blocker-update.service`      |
| systemd update timer             | `/etc/systemd/system/china_blocker-update.timer`        |
| systemd health service           | `/etc/systemd/system/china_blocker-health.service`      |
| systemd health timer             | `/etc/systemd/system/china_blocker-health.timer`        |
| nftables.service drop-in         | `/etc/systemd/system/nftables.service.d/china_blocker.conf`（仅在系统存在 `nftables.service` 时创建） |

> 注意：不再有 `ipset.conf`。IP 库直接以可读的 CIDR 文本保存，可以随时 `wc -l` / `grep` 查看，也可以手工增删后执行 `sudo cb --restore` 生效。载入前脚本会先剥掉空行与注释再分块，所以手工编辑时留空行、加注释都不会导致数据丢失。

------

## 白名单（Whitelist）

用菜单 `5` 编辑（优先 `vim`，回退 `vi` / `nano`），保存退出即自动生效；也可以直接改文件再执行 `sudo cb --restore`。

每行一个 IP 或 CIDR，IPv4 与 IPv6 可以混写，支持整行注释、行尾注释与空行：

```
# 放行办公室出口 IP
1.2.3.4

# 放行整个网段
203.0.113.0/24    # 行尾注释也会被正确剥离

# 放行 IPv6
2001:db8::1
2001:db8:1234::/48
```

白名单会写入 `whitelist4` / `whitelist6` 集合，对应的 `return` 规则始终排在封禁规则之前。任何 `/0` 结尾的条目会被拒绝——那等于把整表变成空操作。

批量写入若因某一行不被接受而失败（例如 `1.2.3.4/33`，或与另一条重叠），脚本会降级为**逐条写入**，只跳过那一行。被跳过的行只在**当次执行的终端输出**里逐条列出（日志只记一个 `apply_whitelist fell back to per-element mode, bad=N` 的计数），所以改完白名单请留意屏幕上的红色提示。

------

## 查看状态

菜单选择 `6`（或 `sudo cb --status`）会显示：

- **核心服务状态**：`china_blocker.service` 的运行状态、`china_blocker-update.timer` 的状态与下一次触发时间，以及健康检查 timer 是否启用。
- **nftables 状态**：`nft` 版本、`table inet china_blocker` 是否已加载、**每条链（`input` / `forward`）的规则是否符合预期**、当前生效的槽位（`china4_a`/`china4_b`）、以及**累计丢弃报文数**（`counter`，自上次规则重建起计）。某条链显示「规则不符预期」时执行 `sudo cb --restore` 即可修复。
- **IP 集合状态**：内核中实际生效的中国 IPv4 / IPv6 条目数。
- **白名单放行 IP**：列出**内核集合 `whitelist4`/`whitelist6` 里实际生效**的条目，并把 `whitelist.txt` 里写了却没生效的行标成 `!`。这里是逐条用 `nft get element` 去问内核「这个条目在不在集合里」，而不是拿文本比字符串，所以 `1.2.3.4/32` 与 `1.2.3.4`、`2001:0db8:00aa::1` 与 `2001:db8:aa::1` 这类写法差异不会造成误报——被 `!` 标出的就是真的没生效，原因通常是格式非法，或与另一条白名单重叠而被跳过。
- **已封禁端口**：同样读内核集合 `blocked_ports`，即当前真正在拦的端口（TCP/UDP）。

也可以手动查看：

```bash
systemctl status china_blocker --no-pager
systemctl list-timers --all | grep china_blocker
nft list table inet china_blocker            # 完整规则，含 counter 命中数
nft list chain inet china_blocker input      # 只看链和计数器
nft list set inet china_blocker blocked_ports
```

中国 IP 库的条目数请以 `sudo cb --status` 的 `[3]` 区块为准，别自己去数：nft 会把大量元素挤在同一行输出，`grep -c` 之类的行计数并不等于元素数；而且当前生效的槽位可能是 `china4_b`，此时 `china4_a` 已被清空，直接去查 `china4_a` 会误判为「库为空」（`[2]` 区块会打印当前生效槽位）。

条目数**小于**源文件行数是正常的：`auto-merge` 会把相邻或重叠的 CIDR 合并成区间（例如 `1.0.1.0/24` 与 `1.0.2.0/23` 相邻会并成一条），匹配范围没有任何损失。

------

## 定时更新（systemd timer）

脚本会装两个 timer。

**IP 库更新**（默认每月 1 号 04:00）：

- timer：`china_blocker-update.timer`（`Persistent=true`，关机期间漏掉的计划会在开机后补跑）
- service：`china_blocker-update.service`（执行 `china_blocker --update`）

**健康检查**（开机 2 分钟后首次，之后每 15 分钟）：

- timer：`china_blocker-health.timer`
- service：`china_blocker-health.service`（执行 `china_blocker --health`）

健康检查解决的是「规则被别人清掉了」这类问题：某些防火墙工具、`nft flush ruleset`、或手工误操作都可能让本表消失或规则残缺。`--health` 会比对内核里的实际规则序列，一致就什么都不做（因此**不会**清零 counter），不一致才触发一次 `--restore`。

两个间隔都在脚本配置区：更新时间改 `ON_CALENDAR`（例如每天凌晨 4 点写 `"*-*-* 04:00:00"`），健康检查改 `HEALTH_INTERVAL`。改完重新执行菜单 `1` 生效。

### 服务单元的行为

`china_blocker.service` 是 `Type=oneshot` + `RemainAfterExit=yes`：

```
ExecStart  = /usr/local/bin/china_blocker --restore
ExecReload = /usr/local/bin/china_blocker --restore
ExecStop   = /usr/local/bin/china_blocker --clean
```

所以：`systemctl reload china_blocker` 等价于「重新从配置文件恢复规则」，改完白名单或端口文件后用它最省事；而 `systemctl stop china_blocker` 会**移除整张表**，`systemctl restart` 期间存在一个极短的无防护窗口。

------

## 停用与卸载：三个层次

三个命令的区别只在于「动多少东西」，选错了会出现「清完又自己回来了」的困惑：

| 操作 | 动内核规则 | 动 systemd 单元 | 动配置与脚本 | 之后会自动恢复吗 |
| --- | --- | --- | --- | --- |
| `--clean` | 删表 | 不动（仍 enabled） | 保留 | **会**。开机时 `china_blocker.service` 会 `--restore`，健康检查更快，15 分钟内就装回去 |
| `--disable`（菜单 `8`） | 删表 | disable 三个单元、移除 nftables drop-in | 保留 | 不会 |
| 卸载（菜单 `7`） | 删表 | 删除五个单元文件 + drop-in + `reset-failed` | 删除 `/etc/china_blocker/`、脚本、`cb` 软链接（**保留日志**） | 不会 |

所以：

- 临时排查用 `--clean`，它故意只收窄到「清当前规则」。执行时脚本会检测到单元仍 enabled 并提示你这一点。
- 要**持久**停用（例如被自己封在门外、需要从容改配置）用 `sudo cb --disable`。它相当于
  `sudo systemctl disable --now china_blocker china_blocker-update.timer china_blocker-health.timer`，
  外加移除 nftables.service 的 drop-in——否则 `systemctl restart nftables` 会通过 `ExecStartPost` 把表装回来。`--now` 已经触发了 `ExecStop`（即 `--clean`），不必再单独执行一次。改好之后 `sudo cb --install` 原样恢复。
- `systemctl stop china_blocker` 不算停用：健康检查 timer 会把规则装回去。

若想完全手工卸载（下面的花括号展开需要 bash / zsh，`sh` 下请逐条写全）：

```bash
sudo systemctl disable --now china_blocker china_blocker-update.timer china_blocker-health.timer 2>/dev/null
sudo rm -f /etc/systemd/system/china_blocker{,-update,-health}.service \
           /etc/systemd/system/china_blocker-{update,health}.timer \
           /etc/systemd/system/nftables.service.d/china_blocker.conf
sudo rmdir /etc/systemd/system/nftables.service.d 2>/dev/null   # 目录非空会自动跳过
sudo systemctl daemon-reload
sudo systemctl reset-failed china_blocker china_blocker-update china_blocker-health 2>/dev/null
sudo nft delete table inet china_blocker 2>/dev/null
sudo rm -rf /etc/china_blocker

# cb 只在确实指向本脚本时才删，避免误删同名命令
[ "$(readlink -f /usr/local/bin/cb 2>/dev/null)" = /usr/local/bin/china_blocker ] \
  && sudo rm -f /usr/local/bin/cb
sudo rm -f /usr/local/bin/china_blocker
sudo rm -f /var/log/china_blocker.log   # 日志，可选
```

------

## 数据源说明（为什么可能条目数不同）

脚本更新 IP 库时：

- IPv4 **优先使用 ipdeny** 的 `cn.zone`；IPv6 优先使用 ipdeny 的 IPv6 `cn.zone`
- 若主源下载失败、解析失败或返回 HTML（可能被拦截/跳转），才启用 **APNIC** delegated 备用源生成 CIDR

APNIC 的 delegated 文件给出的是「起始地址 + 地址数量」，而数量**不一定是 2 的整数次幂**（例如 `43.224.0.0|1536`）。脚本会把每条记录按对齐边界贪心拆解为多个合法 CIDR，完整覆盖声明范围且不越界。

解析结果会先过三道校验再落盘：

**逐条格式校验。** IPv4 检查四段都 ≤ 255；IPv6 **必须写成 `地址/前缀`**，裸地址当作非法行丢弃（手工编辑 `china_ipv6.txt` 时注意这点）。

**前缀下限。** IPv4 前缀须在 `MIN_V4_PREFIX`（默认 8）到 32 之间，不带前缀视为 `/32`；IPv6 须在 `MIN_V6_PREFIX`（默认 16）到 128 之间。这道校验挡的是 `1.0.0.0/0`、`2001:db8::/0` 这类「一条记录覆盖全网」的条目——只黑名单 `0.0.0.0/0` 字面量挡不住变体，而源站返回残缺内容或被投毒时，一条 `/0` 就足以把封禁集合扩成全网。中国实际分配的最大块远小于这两个阈值，正常数据不会被误杀。

白名单用的是另一套更宽松的正则（裸 IPv6 允许，写法差异交给内核消化），但同样拒绝任何 `/0` 结尾的条目——白名单命中即 `return`，一条 `0.0.0.0/0` 会让整表形同虚设，而状态报告只会显示「已生效」，用户根本看不出防护已经废了。

**总量下限。** 中国 IPv4 实际约 1.1 万条 CIDR、IPv6 约 3 千条，脚本要求解析结果至少有 `MIN_V4_LINES`（默认 2000）/ `MIN_V6_LINES`（默认 200）行，否则判定为数据源异常（返回了错误页、被投毒、只下载了一半），**拒绝替换现有集合**并在日志里记录。这样即使上游某天返回一个只有几行的文件，也不会把你的防护悄悄削成筛子。

由于不同数据源国家归类口径不同，IP 条目数存在差异是正常的。脚本日志（`/var/log/china_blocker.log`）会记录本次使用了哪个源、是否触发了降级或拒绝。

------

## 与其他防火墙共存

**ufw / firewalld。** 各自是独立的表，按 hook 优先级依次求值。本表在 `-10`，先跑；白名单命中时 `return` 只退出本表，ufw/firewalld 的规则照常生效。两者可以同时使用。

**nftables.service。** 多数发行版的 `/etc/nftables.conf` 第一行就是 `flush ruleset`，一旦 `systemctl restart nftables` 就会连带清掉本表。**若系统上存在 `nftables.service` 单元**，安装时脚本会自动添加 drop-in（并在终端提示）；不存在这个单元时（例如只装了 nft 工具、或由 firewalld 统一管理）会跳过：

```
# /etc/systemd/system/nftables.service.d/china_blocker.conf
[Service]
ExecStartPost=-/usr/local/bin/china_blocker --restore
```

让 `nftables.service` 启动后自动把本表装回去。`--disable` 与卸载都会移除这个 drop-in，`--clean` 不动它。

**Docker。** Docker 发布端口（`-p`）的流量走的是 `forward` hook 而不是 `input`，只挂 `input` 会漏掉容器端口。因此脚本默认**同时挂 `input` 与 `forward` 两条链**（配置项 `BLOCK_FORWARD="1"`），容器发布端口一样会被拦截。

如果本机同时充当路由器、需要正常转发中国流量，把配置区改成 `BLOCK_FORWARD="0"` 再执行菜单 `1`（或 `--install`）即可；脚本会自动删掉已存在的 `forward` 链，不会留下残留规则。

------

## 常见问题（FAQ）

### 1）安装后 IP 条目数为 0？

先执行 `sudo cb --update && sudo cb --status`。如果更新成功仍为 0，通常是两种情况：网络无法访问 ipdeny 与 APNIC（脚本日志会写明），或系统 / 容器（LXC、OpenVZ）未开放 netfilter 能力，需要宿主授予 `NET_ADMIN`。

### 2）更新时报 `Message too long`？

这是 nft 单事务约 64 KB 的 netlink 上限。当前版本已通过**分块载入 + 原子切换**规避；如果你仍看到该错误，说明脚本配置区的 `CHUNK_LINES` 被改得过大，或数据文件异常。把 `CHUNK_LINES` 调小（默认 `1500`）后重试即可。

### 3）迁移自 iptables + ipset 版本，旧规则怎么办？

nftables 版完全不碰 `iptables` / `ipset`，两者可以并存但没有必要。建议先用**旧版脚本**执行 `--clean` 卸载干净再安装本版本。若旧版脚本已删除，可手动清理：

```bash
sudo iptables -D INPUT -j CHINA_BLOCKER 2>/dev/null
sudo iptables -F CHINA_BLOCKER 2>/dev/null
sudo iptables -X CHINA_BLOCKER 2>/dev/null
sudo ipset destroy china_ips 2>/dev/null
```

### 4）我会不会把自己 SSH 踢下线？

脚本会主动做一次**自锁检查**，不是只对 `22` 硬编码提示。屏蔽端口前它会：

1. **探测你实际的 SSH 端口** —— 依次看 `$SSH_CONNECTION`（当前这条连接的目标端口）、`ss` / `netstat` 里 sshd 的**对外**监听端口、以及 `sshd_config` 与 `sshd_config.d/*.conf` 里的 `Port` 行。所以把 SSH 改成 2222 也能被认出来。绑在 loopback 上的监听会跳过——sshd 的 X11 / 端口转发会在 `127.0.0.1` 开临时监听（如 `127.0.0.1:6010`），那些不是 SSH 服务端口。
2. **判断你自己会不会被拦** —— 取 `$SSH_CONNECTION` 里的客户端 IP：命中白名单直接放行不再追问；不在中国 IP 库里也不追问；确实落在中国 IP 库里才会红字警告「封禁后你会立刻掉线」。
3. **要求复述端口号确认** —— 判定有风险时必须重新输入一遍该端口号才会继续，回车或输错都取消。

一个例外：中国 IP 库为空（没更新成功）时脚本无法判断你的 IP 会不会被拦，此时提示「无法判断」并**仍然要求确认**，而不是假装安全。

依然建议先把管理 IP 加入白名单（菜单 `5`）再屏蔽端口，并保留一个已连接的 SSH 会话作为后路，或确认服务商提供 VNC / 串口控制台。

万一被锁在外面，通过控制台执行 `nft delete table inet china_blocker` 可立刻解除全部封禁，但这只是临时的（健康检查 timer 15 分钟内就会装回来）。想争取到足够时间从容修配置，用 `sudo cb --disable`，改好白名单后再 `sudo cb --install` 恢复。

### 5）`--clean` 之后为什么开机又恢复了？

这是设计如此，`--clean` 只清当前规则。见上文「[停用与卸载：三个层次](#停用与卸载三个层次)」——要持久停用请用 `sudo cb --disable`，要彻底删除用菜单 `7`。

------

## 安全提示

- 本工具会修改防火墙规则，请确保你了解自己在做什么
- 不建议在远程 SSH 时贸然封禁 SSH 端口
- 建议先把你的管理 IP 加入白名单，再开始封禁端口
- 默认策略是 `policy accept`（默认放行），任何数据缺失或规则残缺都只会导致“不拦”，不会导致“全拦”
