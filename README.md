# AeroBox

面向 **Linux / Wayland** 的代理客户端，使用 Rust、GTK4、libadwaita 和 GtkSourceView 5。网络引擎在应用进程内运行，随 AeroBox 静态编译，无需安装、下载或指定外部内核。协议实现基于仓库内的第三方 [shoes](vendor/shoes) 代码，最终只生成一个 `AeroBox` 应用。

## 安装

从 [Releases](https://github.com/imengying/AeroBoxForLinux/releases) 下载：Intel / AMD 电脑选择 `AeroBoxForLinux-linux-amd64.tar.gz`，ARM64 设备选择 `AeroBoxForLinux-linux-arm64.tar.gz`。

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
3. 在首页选择「规则」「全局」或「直连」，点击右下角「启动」。全局使用所选节点；规则按启用的规则分流，未匹配的连接使用所选节点；直连绕过节点。模式切换会断开旧连接。
4. 节点卡片下方可单独测速，右下角悬浮按钮测试当前订阅。连接页可查看和断开连接，设置中的内核页可检查配置、重启和诊断连接。

首页显示单个出口 IP、上传下载、连接数、运行时间及 AeroBox 整体内存。优先显示 IPv4，点击 IP 卡片重新检测。IPv6 开关位于设置中；字体大小支持 9–18 pt，布局随字体和 Wayland 缩放调整。日志级别默认 `error`。

### 协议与限制

支持 Shadowsocks（含 SS2022）、VMess、VLESS、Trojan、AnyTLS、Hysteria2、TUIC、Naive、SOCKS 和 HTTP。受支持的传输和安全参数按实际实现转换；未知字段、浏览器 TLS 指纹模拟、Shadowsocks 插件及其他未实现参数会明确拒绝并报告位置，避免导入后静默丢失设置。不提供 ShadowTLS、Snell 或旧版内核参数兼容。

协议名称相同不代表所有参数组合都已完成互通验证。节点导入、运行配置校验和本地协议测试覆盖各自的边界；具体服务端仍须用实际连接验证。

### 系统代理与虚拟网卡

系统代理支持 GNOME 和 KDE Plasma；停止时恢复本次修改前的桌面设置。Brave / Chromium 可使用桌面代理，浏览器扩展或启动参数指定的代理可能覆盖它。其他应用可填写本地 HTTP / SOCKS 入口，默认 `127.0.0.1:2080`。

TUN 使用固定的内部 Rust 网络栈，需要 `/dev/net/tun`、`nftables` 命令及网络管理权限。Arch Linux 可安装 `nftables libcap polkit`。在设置中授权后，**完全退出并重新启动 AeroBox** 才会获得当前进程需要的 `CAP_NET_ADMIN` / `CAP_NET_RAW`；授权作用于应用可执行文件，界面仍以当前用户身份运行。更新替换程序后需重新授权。

TUN 的路由与防回环由引擎统一管理，停止时恢复；没有额外的协议栈或严格路由选择项。关闭主窗口会停止网络运行并恢复桌面代理。

### DNS 与规则

直连 DNS 和远程 DNS 支持 `udp://`、`tcp://`、`tls://`、`https://` 和 `quic://`。例如 `udp://223.5.5.5`、`tls://dns.alidns.com`、`https://cloudflare-dns.com/dns-query`。HTTPS DNS 地址不能包含账号、查询参数或片段。

节点域名使用直连 DNS 解析；规则及全局模式的远程 DNS 经所选节点查询，直连模式使用直连 DNS。直连 DNS 自身使用域名时通过系统解析器引导。IPv6、DNS 缓存、嗅探、局域网访问和私网绕行可在设置中调整。

内置与 AeroBoxForAndroid 同来源的中国大陆 IP、中国大陆域名、广告拦截规则，安装包附带初始 SRS 数据，运行时在线更新并缓存，默认每 1440 分钟更新。中国大陆规则默认直连，广告拦截默认关闭。规则支持直连、代理和拦截，以及域名、域名后缀、域名关键字、IP 网段和端口条件；全局与直连模式忽略普通分流和广告规则，IPv6 等网络限制仍生效。

可添加在线 JSON / SRS 规则或编辑本地规则。SRS 由 Rust 直接读取，编辑后保存为 JSON，无需外部编译器。规则来源及许可见 [resources/rules/README.md](resources/rules/README.md)。

订阅、规则下载和出口 IP 检测使用当前运行的代理；停止后直连。代理失败时不会为下载自动改走直连。

## 数据与备份

数据位于 `$XDG_CONFIG_HOME/AeroBoxForLinux/`，未设置时使用 `~/.config/AeroBoxForLinux/`。`state.json` 保存设置、订阅和规则信息，规则缓存也位于此目录。订阅及备份包含连接凭据，请妥善保管。

当前数据要求 `schema_version: 2`，备份要求 `aerobox-linux-backup`、`version: 2`。旧版数据和 v1 备份直接拒绝，不做迁移或兼容；遇到旧数据时可在恢复界面备份原文件并重新初始化。

设置中的备份功能导出订阅、凭据、规则及设置；恢复时合并资源，重名资源生成副本，不覆盖现有资源。窗口尺寸和登录启动保留本机值。缺少规则数据或校验失败时不写入半份状态。恢复默认设置保留订阅、节点、规则、当前选择及窗口尺寸。

## 开发

```sh
sudo pacman -S --needed rust gcc make cmake pkgconf gtk4 libadwaita gtksourceview5 librsvg
git clone https://github.com/imengying/AeroBoxForLinux.git
cd AeroBoxForLinux
cargo build --release --locked
./target/release/AeroBox
```

Rust 工具链固定为 1.100.0，见 `rust-toolchain.toml`；依赖由 `Cargo.lock` 锁定。桌面库要求 GTK ≥ 4.10、libadwaita ≥ 1.5、GtkSourceView ≥ 5.6。Ubuntu 24.04 开发包为 `libgtk-4-dev libadwaita-1-dev libgtksourceview-5-dev librsvg2-common pkg-config cmake`。

```sh
make test     # 格式、Clippy、单元与集成测试
make wayland  # headless Wayland 界面测试
make package  # 生成 target/packages/*.tar.gz
make clean
```

普通集成测试使用临时目录、回环地址和临时端口，验证实际流量、节点与模式切换、回滚、下载、测速和启停，不依赖外部内核，不启动特权 TUN。

额外测试按需显式运行，测试服务端不属于应用运行依赖：

```sh
# 隔离的 user/network namespace 内验证 IPv4/IPv6 TUN 与停止后的网络清理
cargo test --test tun managed_tun_routes_traffic_and_restores_network_in_namespace -- --ignored
# 与独立 sing-box 测试服务端验证 TCP 和 UDP 协议互通
AEROBOX_TEST_PEER=/path/to/sing-box cargo test --test interop -- --ignored
# Naive HTTP/2、HTTP/3 的独立 Go 回显服务端
(cd vendor/shoes/tests/fixtures/naive-peer && go build -o /tmp/aerobox-naive-peer .)
AEROBOX_NAIVE_PEER=/tmp/aerobox-naive-peer cargo test --test naive_interop -- --ignored
```

TUN 测试需要 `unshare`、`ip`、`nft` 和 `/dev/net/tun`；所有路由更改均限制在测试命名空间内。

界面测试需要 Weston、Sway 和 `dbus-run-session`，使用隔离的 XDG 目录和 D-Bus 会话。`AEROBOX_TEST_SCALE=1.25 make wayland` 验证 1.25 倍缩放，`AEROBOX_TEST_SCALE=2 make wayland` 验证 2 倍缩放；截图与日志位于 `target/wayland/`。可通过 `CARGO_TARGET_DIR` 将生成文件放到仓库外。

`src/runtime.rs` 组装原生运行配置，`engine.rs` 管理连接生命周期和事务回滚，`protocol/` 严格转换节点参数，`model.rs` 管理数据与原子存储，`ui/` 为 GTK 界面。`vendor/` 包含静态编译的第三方实现，`tests/` 包含集成测试。GitHub Actions 在 amd64 / arm64 构建，推送 `v*` 标签后发布安装包。

## 来源与许可

项目源于 GUI-for-Cores / GUI.for.SingBox，遵循 [GPL-3.0](LICENSE)。界面参考 [FlClash](https://github.com/chen08209/FlClash)，订阅流程参考 [Hiddify](https://github.com/hiddify/hiddify-app)。协议引擎及其他第三方代码见 [THIRD_PARTY.md](THIRD_PARTY.md) 与 `licenses/`；相关许可随安装包分发。
