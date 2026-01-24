# China Blocker（中国 IP 屏蔽助手）

一个用于 Linux 服务器的“一键版”脚本：基于 **ipset + iptables**，按端口屏蔽来自 **中国 IPv4** 的访问，并提供 **白名单放行**、**systemd 开机自启**、**systemd timer 定时更新 IP 库** 等功能。

> 适合：海外服务器、需要按端口限制中国访问的场景
>  支持：Debian / Ubuntu / CentOS / RHEL / Rocky / AlmaLinux 等主流发行版（systemd 环境）

------

## 功能特性

- ✅ **一键安装/修复服务**（systemd）
- ✅ **按端口屏蔽**中国 IP（TCP/UDP）
- ✅ **解封端口时列出已封禁端口**供选择
- ✅ **白名单**（放行指定 IP，规则永远在 INPUT 最前）
- ✅ **自动更新中国 IP 库**
  - 主源：**ipdeny（优先）**
  - 备用：**APNIC delegated**（仅在 ipdeny 下载/解析失败时启用）
- ✅ **systemd timer 定时更新**（默认每月 1 日 04:00）
- ✅ 兼容 mawk / gawk，兼容 iptables legacy / nft（根据系统环境）

------

## 工作原理（简述）

- 使用 **ipset** 保存中国 IPv4 CIDR 集合（集合名默认：`china_ips`）
- 使用 **iptables** 创建自定义链 `CHINA_BLOCKER`
- 对用户指定端口添加规则：

```
-A CHINA_BLOCKER -p tcp --dport <PORT> -m set --match-set china_ips src -j DROP
-A CHINA_BLOCKER -p udp --dport <PORT> -m set --match-set china_ips src -j DROP
```

- 在 INPUT 链插入跳转到 `CHINA_BLOCKER`（尽量插到第 2 条，失败则回退到第 1 条）
- 白名单 IP 使用 `ACCEPT` 规则插入 INPUT 第 1 条，确保始终优先放行

------

## 安装 & 使用

```
curl -fsSL https://raw.githubusercontent.com/Henry00123/china_blocker/main/china_blocker.sh -o china_blocker.sh && chmod +x china_blocker.sh && sudo ./china_blocker.sh
```

执行后在菜单中选择：

- `1` 安装/修复服务（推荐首次运行）
- `3` 屏蔽端口
- `4` 解封端口

------

## 配置文件与路径

| 作用                             | 路径                                               |
| -------------------------------- | -------------------------------------------------- |
| 安装后的脚本路径（systemd 调用） | `/usr/local/bin/china_blocker`                     |
| 配置目录                         | `/etc/china_blocker/`                              |
| ipset 保存文件（用于开机恢复）   | `/etc/china_blocker/ipset.conf`                    |
| 白名单文件                       | `/etc/china_blocker/whitelist.txt`                 |
| 日志文件                         | `/var/log/china_blocker.log`                       |
| systemd service                  | `/etc/systemd/system/china_blocker.service`        |
| systemd update service           | `/etc/systemd/system/china_blocker-update.service` |
| systemd timer                    | `/etc/systemd/system/china_blocker-update.timer`   |

------

## 白名单（Whitelist）

编辑白名单：

- 菜单选择 `5`（默认使用 `vim`）
- 或手动编辑：

```
sudo vim /etc/china_blocker/whitelist.txt
```

格式：每行一个 IP（支持注释与空行）

```
# 放行办公室出口 IP
1.2.3.4

# 放行家里宽带
5.6.7.8
```

修改后脚本会自动把白名单规则插入 INPUT 最前（优先放行）。

------

## 查看状态

菜单选择 `6` 会显示：

- `china_blocker.service` 状态
- `china_blocker-update.timer` 状态与下次触发时间
- INPUT 链是否已跳转到 `CHINA_BLOCKER`
- `CHINA_BLOCKER` 链规则
- 已封禁端口列表
- `ipset china_ips` 条目数

你也可以手动查看：

```
systemctl status china_blocker --no-pager
systemctl status china_blocker-update.timer --no-pager
systemctl list-timers --all | grep china_blocker
ipset list china_ips | grep "Number of entries"
iptables -S INPUT | grep CHINA_BLOCKER
iptables -S CHINA_BLOCKER
```

------

## 定时更新（systemd timer）

默认每月 1 号 04:00 更新一次 IP 库：

- timer：`china_blocker-update.timer`
- service：`china_blocker-update.service`（执行 `china_blocker --update`）

查看下一次更新计划：

```
systemctl list-timers --all | grep china_blocker
```

如果你想改为每天凌晨 4 点更新：

1. 编辑脚本中 `ON_CALENDAR`：

   ```
   ON_CALENDAR="*-*-* 04:00:00"
   ```

2. 重新安装/修复服务（菜单 1 或 `--install`）

------

## 数据源说明（为什么可能条目数不同）

脚本更新 IP 库时：

- **优先使用 ipdeny** 的 `cn.zone`
- 若 ipdeny 下载失败、解析失败或返回 HTML（可能被拦截/跳转），才启用 **APNIC** delegated 备用源生成 CIDR

由于不同数据源国家归类口径可能不同，IP 条目数存在差异是正常的。脚本日志会记录使用了哪个源。

------

## 常见问题（FAQ）

### 1）安装后 ipset 条目数为 0？

请先执行：

```
sudo /usr/local/bin/china_blocker --update
ipset list china_ips | grep "Number of entries"
```

如果更新成功仍为 0，多半是系统/容器（LXC/OpenVZ）未开放 netfilter/ipset 能力，需要宿主开放相关 capability。

------

### 2）启动 service 时出现 `iptables: Index of insertion too big.`

脚本已处理该情况：会自动回退插入规则到 INPUT 第 1 条；该报错一般发生在 INPUT 链为空时。

如果你仍看到该报错但规则未生效，请手动确认 INPUT 链：

```
iptables -S INPUT | grep CHINA_BLOCKER
```

------

### 3）我会不会把自己 SSH 踢下线？

脚本在屏蔽端口时会对 `22` 端口做强提示，需要确认才会继续。

强烈建议：

- 把自己的管理 IP 加入白名单
- 或不要屏蔽 `22`

------

### 4）如何卸载？

菜单选择 `7`（卸载服务）

或手动：

```
sudo /usr/local/bin/china_blocker --clean
sudo systemctl disable --now china_blocker 2>/dev/null
sudo systemctl disable --now china_blocker-update.timer 2>/dev/null
sudo rm -f /etc/systemd/system/china_blocker.service
sudo rm -f /etc/systemd/system/china_blocker-update.service
sudo rm -f /etc/systemd/system/china_blocker-update.timer
sudo systemctl daemon-reload
sudo rm -rf /etc/china_blocker
sudo rm -f /usr/local/bin/china_blocker
```

------

## 安全提示

- 本工具会修改防火墙规则，请确保你了解自己在做什么
- 不建议在远程 SSH 时贸然封禁 `22` 端口
- 建议先把你的管理 IP 加入白名单
