# China Blocker（中国 IP 屏蔽助手）

一个基于 **ipset + iptables** 的一键脚本：下载中国大陆 IP 段（cn.zone），将其写入 ipset 集合，并按需对指定端口（TCP/UDP）对中国来源 IP 进行 DROP。支持 **systemd 开机恢复**、**定时更新**、**白名单放行**、**交互式菜单**。

> ✅ 本脚本只管理自己的 iptables 专用链 `CHINA_BLOCKER`，不会覆盖整机防火墙规则。
> ✅ 安装/修复服务时会自动更新一次 IP 库，装完即可直接屏蔽端口。

------

## 功能特性

- **更新中国 IP 库**：从 ipdeny 下载 `cn.zone` 并写入 ipset（兼容模式逐条导入）
- **按端口屏蔽（TCP/UDP）**：仅对命中中国 IP 段的来源进行 DROP
- **解封端口**：会列出已封禁端口供选择（可输入序号或端口号）
- **白名单**：白名单 IP 在 INPUT 链第 1 条直接 ACCEPT（优先级最高）
- **systemd 服务**：
  - 开机自动恢复（恢复 ipset + CHINA_BLOCKER 跳转 + 白名单）
  - 停止服务自动清理（移除 CHINA_BLOCKER、删除 ipset、删除白名单规则）
- **定时任务（cron）**：默认每月 1 日 04:00 自动更新一次 IP 库
- **日志**：写入 `/var/log/china_blocker.log`

------

## 工作原理

1. 下载中国 IP 段列表（来源：ipdeny `cn.zone`）
2. 写入 ipset 集合：`china_ips`
3. 创建 iptables 专用链：`CHINA_BLOCKER`
4. 在 `INPUT` 链第 2 条插入跳转：`-j CHINA_BLOCKER`
5. 在 `CHINA_BLOCKER` 链中按端口添加规则：
   - `-p tcp/udp --dport <PORT> -m set --match-set china_ips src -j DROP`
6. 白名单写入 `INPUT` 链第 1 条：
   - `-I INPUT 1 -s <IP> -j ACCEPT`

------

## 环境要求

- Linux（使用 iptables）
- 必需命令：
  - `ipset`
  - `iptables`
  - `curl`
- 必须以 root 执行（建议 `sudo`）

> 注：某些系统使用 nftables 兼容层（iptables-nft），一般可用，但如果你的机器上同时运行 firewalld/ufw/docker/k8s 等，会有规则管理上的交互影响，需要自行评估。

------

## 安装与使用

### 1) 下载并运行

```
curl -fsSL https://raw.githubusercontent.com/Henry00123/china_blocker/main/china_blocker.sh -o china_blocker.sh && chmod +x china_blocker.sh && sudo ./china_blocker.sh
```

进入交互式菜单后：

- `1` 安装/修复服务（推荐第一次就选这个）
- `2` 更新 IP 库
- `3` 屏蔽端口
- `4` 解封端口
- `5` 编辑白名单（vim）
- `6` 查看状态
- `7` 卸载服务

### 2) 一键安装（推荐）

菜单选择 `1` 会执行：

- 将脚本复制到：`/usr/local/bin/china_blocker`
- 自动更新一次 IP 库（成功会提示当前条目数）
- 写入 systemd：`/etc/systemd/system/china_blocker.service`
- 启动并设置开机自启
- 写入 cron：每月 1 日 04:00 更新

安装完成后会提示：

> “现在可直接开始屏蔽端口：菜单选择 3（屏蔽端口）”

------

## 命令行模式

脚本支持以下参数（无需进入菜单）：

```
sudo /usr/local/bin/china_blocker --update   # 更新 IP 库
sudo /usr/local/bin/china_blocker --restore  # 恢复（systemd ExecStart 调用）
sudo /usr/local/bin/china_blocker --clean    # 清理（systemd ExecStop 调用）
sudo /usr/local/bin/china_blocker --install  # 安装/修复服务
```

------

## 配置与文件路径

- 脚本安装路径：`/usr/local/bin/china_blocker`
- 配置目录：`/etc/china_blocker/`
  - ipset 保存文件（命令列表形式）：`/etc/china_blocker/ipset.conf`
  - 白名单：`/etc/china_blocker/whitelist.txt`
- 日志：`/var/log/china_blocker.log`
- systemd：
  - `/etc/systemd/system/china_blocker.service`

------

## 白名单说明

白名单文件：`/etc/china_blocker/whitelist.txt`

- 每行一个 IP（支持注释 `#`）
- 白名单规则会插入到 `INPUT` 链第 1 条，优先级最高
- 菜单 `5` 使用 `vim` 编辑后会自动重新应用白名单

示例：

```
# 在此处每行添加一个要放行的IP地址
203.0.113.10
198.51.100.8
```

------

## 查看与验证

### 查看 ipset 条目数

```
sudo ipset list china_ips | grep -E "Number of entries"
```

### 查看 iptables 规则

```
sudo iptables -S INPUT | grep CHINA_BLOCKER
sudo iptables -S CHINA_BLOCKER
```

### systemd 状态

```
sudo systemctl status china_blocker --no-pager
sudo journalctl -u china_blocker -n 200 --no-pager
```

------

## 卸载

菜单选择 `7` 或执行：

```
sudo /usr/local/bin/china_blocker --clean
sudo systemctl stop china_blocker
sudo systemctl disable china_blocker
sudo rm -f /etc/systemd/system/china_blocker.service
sudo systemctl daemon-reload
sudo rm -rf /etc/china_blocker
sudo rm -f /usr/local/bin/china_blocker
```

> 卸载会清理：`CHINA_BLOCKER` 链、ipset 集合、白名单 ACCEPT 规则、cron 项、配置目录。

------

## 注意事项（重要）

1. **不要轻易屏蔽 22 端口**
    脚本对 22 有确认提示，但如果你从中国 IP 登录 SSH，屏蔽后可能会断连。
2. **与其它防火墙管理工具共存**
    如果你启用了 ufw/firewalld/docker/k8s 等，建议先确认它们是否会重写 INPUT 规则顺序。脚本只插入一条 jump，但规则顺序仍会影响最终行为。
3. **IP 数据源依赖外网**
    更新依赖 ipdeny 的 cn.zone，如果源站不可用，更新会失败，但不影响已存在规则继续工作。
