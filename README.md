# 3x-pilang

一个运行在 3x-ui 面板服务器上的批量节点工具。把一批 SOCKS5 节点粘进去，它会自动写入本机 3x-ui 的 SQLite 数据库（或通过面板 API），为每个节点创建 VLESS + Reality 入站，并追加对应的 SOCKS 出站和路由规则。

## 功能

- 支持直接读写 `/etc/x-ui/x-ui.db`，速度快，无需逐个通过面板操作。
- 支持通过 3x-ui 面板 API 创建入站。
- 同时创建本地 Web UI 和命令行两种使用方式。
- 写入前自动备份数据库到 `/root/xui-batch-backups`。
- 自动生成 UUID、客户端、Reality 配置，并为每个节点设置独立端口和备注名。
- 重复执行时会跳过已存在的端口/标签，幂等写入。

## 一键安装

在已安装 3x-ui 的服务器上以 root 执行：

```bash
curl -fsSL https://raw.githubusercontent.com/rainbowgag/3x-pilang/master/install.sh | bash
```

安装脚本会克隆仓库到 `/root/3x-pilang`，检查 `git`、`python3`、`systemctl`，然后创建并启动 `3x-pilang-web` 服务。

默认绑定 `0.0.0.0:8765`。安装完成后打开：

```text
http://服务器IP:8765
```

如果只想本机访问，可以改成：

```bash
curl -fsSL https://raw.githubusercontent.com/rainbowgag/3x-pilang/master/install.sh | WEB_HOST=127.0.0.1 WEB_PORT=8765 bash
```

如果不想使用 `curl | bash`，也可以手动安装：

```bash
git clone https://github.com/rainbowgag/3x-pilang.git /root/3x-pilang
bash /root/3x-pilang/install_service.sh
```

> 安全提醒：Web UI 没有登录鉴权，请用防火墙限制 8765 端口，或绑定 `127.0.0.1` 后通过 SSH 隧道访问，不要把管理端口直接暴露到公网。

## 节点输入格式

每行一个 SOCKS5 节点，支持以下两种写法：

```text
82.198.243.27:443:user:pass
user:pass@82.198.243.27:443
```

行尾带 `{宏}` 之类的标记会自动忽略，例如：

```text
82.198.243.27:443:user:pass{宏}
```

## Web UI 使用

1. 打开 `http://服务器IP:8765`。
2. 粘贴节点列表。
3. 填写“节点名前缀”和“入站起始端口”。
4. 可选填写面板地址、账号、密码，并勾选“使用面板 API 创建入站”；不勾选则直接写数据库。
5. 点击“开始创建”。

默认参数：

- 节点名前缀：`德国z`
- 名称起始编号：`1`
- 入站起始端口：`11112`
- 数据库路径：`/etc/x-ui/x-ui.db`
- Reality 目标：`www.sony.com:443`
- Reality SNI：`www.sony.com`

## 命令行使用

直接写数据库：

```bash
python3 /root/3x-pilang/3xui_batch_nodes.py \
  --name-prefix 德国z \
  --inbound-start-port 11112 \
  --input-file /root/nodes.txt \
  --restart-xui
```

从标准输入读取：

```bash
python3 /root/3x-pilang/3xui_batch_nodes.py \
  --name-prefix 德国z \
  --inbound-start-port 11112 \
  --restart-xui <<'EOF'
82.198.243.27:443:user:pass
user:pass@82.198.243.27:443
EOF
```

通过面板 API 创建入站：

```bash
python3 /root/3x-pilang/3xui_batch_nodes.py \
  --panel-url https://你的服务器:8443/面板路径 \
  --username admin \
  --password '你的密码' \
  --name-prefix 德国z \
  --inbound-start-port 11112 \
  --input-file /root/nodes.txt \
  --use-api \
  --insecure \
  --restart-xui
```

先演练不写入：

```bash
python3 /root/3x-pilang/3xui_batch_nodes.py \
  --name-prefix 德国z \
  --inbound-start-port 11112 \
  --input-file /root/nodes.txt \
  --dry-run
```

### 命令行参数

| 参数 | 说明 |
| --- | --- |
| `--panel-url` | 3x-ui 面板基础地址，需包含面板路径，如 `https://host:8443/basepath`。API 模式必填 |
| `--username` | 面板用户名。API 模式必填 |
| `--password` | 面板密码。API 模式必填 |
| `--db` | SQLite 数据库路径，默认 `/etc/x-ui/x-ui.db` |
| `--name-prefix` | 出站和入站备注前缀，如 `德国z`。必填 |
| `--name-start` | 名称起始编号，默认 `1` |
| `--inbound-start-port` | 入站起始端口，如 `11112`。必填 |
| `--input-file` | 节点列表文件。省略则从标准输入读取 |
| `--use-api` | 通过面板 API 创建入站，否则直接写数据库 |
| `--insecure` | 跳过 HTTPS 证书校验 |
| `--restart-xui` | 完成后重启 `x-ui` 服务 |
| `--dry-run` | 只打印计划，不写入 |
| `--web` | 启动本地 Web UI |
| `--web-host` | Web UI 监听地址，默认 `127.0.0.1` |
| `--web-port` | Web UI 端口，默认 `8765` |
| `--reality-private-key` | Reality 私钥 |
| `--reality-public-key` | Reality 公钥 |
| `--reality-target` | Reality 目标，默认 `www.sony.com:443` |
| `--reality-sni` | Reality SNI，默认 `www.sony.com` |
| `--reality-short-ids` | 逗号分隔的 shortIds |
| `--fingerprint` | 浏览器指纹，默认 `chrome` |
| `--spider-x` | Reality spiderX，默认 `/` |

## Reality 密钥

脚本内置了默认公钥/私钥，仅用于示例。正式使用前请生成自己的密钥对并替换：

```bash
x-ui x25519
```

生成的 `Private key` 和 `Public key` 可以在 Web UI 中填写，或通过 `--reality-private-key`、`--reality-public-key` 传入。

## 备份与恢复

每次写入前会自动把数据库备份到：

```text
/root/xui-batch-backups/x-ui.db.时间戳.bak
```

如果出现问题，停掉 `x-ui` 后恢复备份即可。

## 服务管理

查看状态：

```bash
systemctl status 3x-pilang-web
```

查看日志：

```bash
journalctl -u 3x-pilang-web -f
```

重启服务：

```bash
systemctl restart 3x-pilang-web
```

卸载服务：

```bash
bash /root/3x-pilang/uninstall_service.sh
```

卸载脚本只移除 systemd 服务，不会删除 `/root/3x-pilang` 目录。
