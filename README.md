# AeroBox

面向 **Linux / Wayland** 的代理客户端，使用 Rust、GTK4、libadwaita 和 GtkSourceView 5。所有连接、分流、DNS 和虚拟网卡功能直接集成在 AeroBox 中，统一构建和发布。

## 安装

从 [Releases](https://github.com/imengying/AeroBoxForLinux/releases) 下载 `AeroBoxForLinux-linux-amd64.tar.gz`，适用于 Intel / AMD 的 x86_64 电脑。目前仅构建和发布此架构的安装包。

Arch Linux：

```sh
sudo pacman -S --needed gtk4 libadwaita gtksourceview5 librsvg
tar -xzf AeroBoxForLinux-linux-amd64.tar.gz
cd AeroBoxForLinux-linux-amd64
./install.sh
```

安装器默认将程序放入 `~/.local/bin/AeroBox`，随后可从应用菜单启动。也可直接运行解压目录中的 `./AeroBox`。成品不需要 Rust 工具链。

程序仅支持 Wayland；Sway / Hyprland 请配置对应的 xdg-desktop-portal 后端。更新时重新运行安装器，完全退出旧进程后再启动。`./uninstall.sh` 卸载程序并保留用户数据。自定义位置使用 `PREFIX=/目标目录 ./install.sh`，卸载时使用相同的 `PREFIX`；系统级安装使用 `sudo env PREFIX=/usr/local ./install.sh`。图形界面以普通用户运行。

## 使用

1. 导入订阅链接、文件或节点内容。支持常见 Clash YAML、sing-box JSON、Base64 和节点分享链接，导入成功后自动选用该订阅。
2. 点击订阅卡片切换订阅，点击节点卡片选择节点。每个订阅分别记住所选节点；运行中切换失败会恢复原连接。
3. 在首页选择「规则」或「全局」，点击右下角「启动」。全局使用所选节点；规则按启用的规则分流，未匹配的连接使用所选节点。模式切换会断开旧连接。
4. 节点卡片下方可单独测速，右下角悬浮按钮测试当前订阅。连接页可查看和断开连接，设置页提供日志级别与连接诊断。

首页显示出口 IP、上传下载、连接数、运行时间及 AeroBox 整体内存。IPv4 在上方，启用 IPv6 后同时检测并显示 IPv6；两个地址分别更新，点击 IP 卡片重新检测。IPv6 开关位于设置中；字体大小支持 9–18 pt，布局随字体和 Wayland 缩放调整。日志级别默认 `error`。

支持 Shadowsocks、VMess、VLESS、Trojan、AnyTLS、Hysteria2、TUIC、Naive、SOCKS 和 HTTP。具体传输和字段见[协议与订阅](docs/protocols.md)。

### 系统代理与虚拟网卡

系统代理支持 GNOME 和 KDE Plasma；停止时恢复本次修改前的桌面设置。Brave / Chromium 可使用桌面代理，浏览器扩展或启动参数指定的代理可能覆盖它。HTTP / SOCKS 入口固定为本机 `127.0.0.1:2080`，不提供局域网共享和端口设置。

TUN 使用固定的内部 Rust 网络栈，需要 `/dev/net/tun`、`nftables` 命令及网络管理权限。Arch Linux 可安装 `nftables libcap polkit`。从首页启用虚拟网卡时，如缺少权限会弹出桌面授权框；授权后 AeroBox 自动重启以获得 `CAP_NET_ADMIN` / `CAP_NET_RAW`，并恢复之前的连接状态。取消授权会保留原有状态。界面仍以当前用户身份运行；更新替换程序后，再次启用时会按需授权。

TUN 的路由与防回环由引擎统一管理，停止时清理。默认网络断开时保留接管并暂停转发，恢复联网后自动重建连接；异常退出留下的网络状态在下次启动 TUN 时清理。关闭主窗口会停止网络运行并恢复桌面代理。

### DNS 与规则

直连 DNS 和远程 DNS 支持 `udp://`、`tcp://`、`tls://`、`https://` 和 `quic://`。例如 `udp://223.5.5.5`、`tls://dns.alidns.com`、`https://cloudflare-dns.com/dns-query`。HTTPS DNS 地址不能包含账号、查询参数或片段。

节点域名使用直连 DNS 解析；远程 DNS 经所选节点查询，命中直连域名规则时使用直连 DNS。直连 DNS 自身使用域名时通过系统解析器引导。IPv6、DNS 缓存、嗅探和私网绕行可在设置中调整。

自定义域名规则同时控制 DNS 分流和拦截，并优先于内置的大陆分流规则；拦截规则仍优先。带 IP、端口等条件的规则仅在域名本身足以确定匹配时影响 DNS，其余条件在连接时判断。关闭 IPv6 后，接管的 AAAA 查询返回空结果，不查询上游。

内置与 AeroBoxForAndroid 同来源的中国大陆 IP、中国大陆域名、广告拦截规则，安装包附带初始 SRS 数据，运行时在线更新并缓存，默认每 1440 分钟更新。中国大陆规则默认直连，广告拦截默认关闭。规则支持直连、代理和拦截，以及域名、域名后缀、域名关键字、IP 网段和端口条件；全局模式忽略普通分流和广告规则，IPv6 等网络限制仍生效。

可添加在线 JSON / SRS 规则或编辑本地规则。更换已有规则的来源或格式时先读取并校验新数据，失败保留原规则。格式有效的空规则集合表示清空匹配项；空响应或损坏数据不会替换已缓存的规则。SRS 由 Rust 直接读取，编辑后保存为 JSON，无需外部编译器。规则来源及许可见 [resources/rules/README.md](resources/rules/README.md)。

订阅、规则下载和出口 IP 检测使用当前运行的代理；停止后直连。代理失败时不会为下载自动改走直连。

## 数据与备份

数据位于 `$XDG_CONFIG_HOME/AeroBoxForLinux/`，未设置时使用 `~/.config/AeroBoxForLinux/`。`state.json` 保存设置、订阅和规则信息，规则缓存也位于此目录。订阅及备份包含连接凭据，请妥善保管。

配置与备份直接保存设置、订阅和规则；读取时校验字段、节点选择及规则内容。无效数据会报错并保留原文件。

设置中的备份功能导出订阅、凭据、规则及设置；恢复时合并资源，重名资源生成副本，不覆盖现有资源。窗口尺寸和登录启动保留本机值。缺少规则数据或校验失败时不写入半份状态。恢复默认设置保留订阅、节点、规则、当前选择及窗口尺寸。

## 开发

使用 Rust 1.100、GTK ≥ 4.10、libadwaita ≥ 1.5 和 GtkSourceView ≥ 5.6。执行 `make test` 检查代码，`make package` 生成安装包。依赖安装、文件布局和验证方式见[开发说明](https://github.com/imengying/AeroBoxForLinux/blob/main/docs/development.md)。

## 来源与许可

项目源于 GUI-for-Cores / GUI.for.SingBox，遵循 [GPL-3.0](LICENSE)。界面参考 [Material 3](https://m3.material.io) 和 [FlClash](https://github.com/chen08209/FlClash)，订阅流程参考 [Hiddify](https://github.com/hiddify/hiddify-app)。第三方代码来源见 [THIRD_PARTY.md](THIRD_PARTY.md) 与 `licenses/`；相关许可随安装包分发。
