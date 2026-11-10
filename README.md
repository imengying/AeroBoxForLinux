# AeroBox

面向 Linux / Wayland 的 sing-box 图形管理器，使用 **Rust、GTK4、libadwaita 和 GtkSourceView 5**。原生侧栏、卡片、表单和代码编辑器，支持浅色、深色及跟随系统主题。

首页集中显示出口 IP、上传下载速度、出站模式、系统代理与 TUN 开关，以及连接数、运行时间和整体内存。右下角悬浮按钮负责启动和停止内核，滚动页面时保持可见；IPv6 开关位于设置中。配置选择、编辑和重载集中在配置页。

## Arch Linux 安装成品

从 [GitHub Releases](https://github.com/imengying/AeroBoxForLinux/releases) 下载：Intel / AMD 电脑选择 `AeroBoxForLinux-linux-amd64.tar.gz`，ARM64 设备选择 `AeroBoxForLinux-linux-arm64.tar.gz`。

```sh
sudo pacman -S --needed gtk4 libadwaita gtksourceview5 librsvg
tar -xzf AeroBoxForLinux-linux-amd64.tar.gz
cd AeroBoxForLinux-linux-amd64
./install.sh
```

安装到 `~/.local/bin/AeroBox` 后，在应用菜单启动 **AeroBox**。也可以直接运行解压目录中的 `./AeroBox`。运行成品不需要 Rust、Go、Node.js、npm 或 Bun。

程序需要 Wayland 会话。文件选择、剪贴板和窗口缩放使用 GTK 原生接口。Sway / Hyprland 请安装并配置桌面对应的 xdg-desktop-portal 后端。

重新运行安装器即可更新；`./uninstall.sh` 卸载程序并保留用户数据。自定义位置使用 `PREFIX=/目标目录 ./install.sh`，卸载时使用相同的 `PREFIX`。系统级安装可运行 `sudo env PREFIX=/usr/local ./install.sh`；图形界面以普通用户启动。

## 使用

1. 在设置中下载 sing-box 1.14 或更新的内核，或指定已有内核路径。内置安装器从 sing-box 官方 GitHub Release 下载并校验 SHA256。
2. 通过链接、剪贴板或本地文件导入订阅；导入时自动解析，成功后入库。支持 sing-box JSON、常见 Clash YAML、Base64 及 SS / VMess / VLESS / Trojan / Hysteria2 / TUIC / SOCKS / HTTP 节点链接。
3. 选择内置的「智能分流」「代理优先」或「直连网络」，编辑配置并勾选要关联的订阅。也可导入原始 sing-box JSON。
4. 预览并检查配置后启动内核。通过节点页切换节点和测试延迟，通过连接页查看、筛选和断开连接，通过日志页排查错误。

系统代理支持 GNOME 和 KDE Plasma，停止代理时恢复本次修改前的设置。Sway / Hyprland 等窗口管理器可使用 TUN，或在各应用中填写本地 HTTP / SOCKS 代理。关闭主窗口会停止本程序启动的内核并恢复代理。

网络设置统一控制 IPv6、局域网访问、私网绕行、流量嗅探、DNS 劫持、DNS 缓存与广告拦截；设置作用于生成配置，保留原始 JSON。运行中修改设置会先检查配置，启动失败时尝试恢复原连接。出站模式可直接切换，无需重启内核。规则模式使用配置中的分流规则；全局模式使用配置的代理出口；直连模式全部直连。全局与直连优先于局域网绕行、广告拦截和普通分流规则，IPv6 禁用等网络限制仍生效。切换模式与节点时会确认内核实际状态，并断开旧连接，让新连接使用新出口。

设置的「内核」页显示实际版本、文件路径和运行状态，可检查当前配置、启动/停止、重启及查看日志。重载与重启先检查配置，失败时保留或恢复原连接；运行中先停止内核再更新文件。

日志级别默认为 `error`，已有数据中明确保存的其他等级会保留。默认使用软件绘制以降低启动内存；需要图形加速时可在设置中开启「硬件加速」，重启应用后生效。已有的 `GSK_RENDERER` 环境变量优先。

界面遵循 [GNOME 排版规范](https://developer.gnome.org/hig/guidelines/typography.html)，参考 Papers 与 Loupe：使用桌面系统字体，标题、正文和辅助文字采用统一的相对大小，弹窗和编辑器跟随同一比例。设置中的「文字大小」支持 100%–150% 实时预览，保存后保留；默认 120%。「清晰文字」开启字形像素对齐，可关闭以使用系统的渲染设置。

首页内存汇总 AeroBox 与正在运行的内核，优先使用按比例分摊共享页的 PSS；权限受限时统一回退 RSS，口径显示在提示中。它表示应用整体占用，不是整机内存使用量。

内置局域网、国内常用域名和常见广告三组可编辑基础规则，随程序提供，不需要先下载。国内与广告列表是小型基础列表，可按需要扩展或导入其他规则集；可从配置页或规则集页点击「添加内置」恢复这些资源。

订阅、规则集和内核下载在连接时自动使用当前内核的代理入口，停止时直连，不读取独立下载代理设置。出口检测也使用同一路径，分别显示 IPv4 和 IPv6；无法连接相应检测服务时显示不可用。

TUN 在设置或首页中启用，支持 System、gVisor 和 Mixed 协议栈、MTU 与严格路由。需要为 **sing-box 内核**授予网络管理权限，可在设置中点击「授权」（需要 polkit 和 libcap），或手动运行：

```sh
sudo setcap cap_net_admin,cap_net_bind_service=+ep /实际路径/sing-box
```

内核更新会替换文件，需要重新授予权限。

## 配置与订阅

配置默认保存在 `${XDG_CONFIG_HOME:-~/.config}/AeroBoxForLinux/state.json`，内核、规则集和生成配置位于同一目录。可使用 `AeroBox --data-dir /目录` 指定独立目录。

写入使用原子替换，配置目录仅当前用户可访问。不读取或迁移旧项目的数据目录。

订阅支持普通 HTTP / HTTPS 地址、Hiddify / sing-box / Clash 导入链接，以及本地 JSON、YAML、Base64 或节点链接内容。文件导入后保存解析结果，无需保留原文件；远程订阅默认每 24 小时自动更新，可在订阅设置中关闭或调整为 1–168 小时。列表显示节点数量、更新时间、流量额度和有效期；流量与有效期以服务端提供的信息为准。

自动更新仅在应用运行时执行，失败后保留原节点并延后重试；更新正在使用的订阅时，会先校验生成配置，再重载，失败则恢复原连接。导入不会自动切换配置，可在配置页关联订阅。设置按常规、网络、虚拟网卡和内核分组，修改后使用右上角「保存」。

订阅导入流程、更新信息和设置分组参考 [Hiddify](https://github.com/hiddify/hiddify-app)。规则集支持直接填写域名、IP 网段、进程名或端口生成匹配条件，复杂规则仍可用 JSON 编辑。

## 从源码构建

```sh
sudo pacman -S --needed rust gcc make pkgconf gtk4 libadwaita gtksourceview5 librsvg
git clone https://github.com/imengying/AeroBoxForLinux.git
cd AeroBoxForLinux
cargo build --release --locked
./target/release/AeroBox
```

Rust 版本要求见 `Cargo.toml`。桌面库要求 GTK ≥ 4.10、libadwaita ≥ 1.4、GtkSourceView ≥ 5.6；Ubuntu 24.04 对应开发包为 `libgtk-4-dev libadwaita-1-dev libgtksourceview-5-dev librsvg2-common pkg-config`。librsvg 用于系统主题中的 SVG 图标；AeroBox 自身图标内嵌 PNG。

```sh
make test     # 格式、Clippy 和单元测试
make wayland  # 无 DISPLAY 的 headless Weston 测试，结果位于 target/wayland/
make package  # target/packages/ 下的 tar.gz
make clean    # 清理 target/ 中的构建、打包和测试产物
```

已有 sing-box 内核时，可运行 `SINGBOX_TEST_CORE=/内核路径/sing-box cargo test`，额外验证三种出站模式、IPv6 与 TUN 配置组合、启动与恢复、Clash API 和 SRS 规则集编译 / 反编译。测试使用隔离目录和临时端口，不启动 TUN 或修改主机路由。

`make wayland` 还需要 Weston 和 `dbus-run-session`，Arch Linux 可安装 `weston dbus`。界面测试使用隔离的 XDG 目录和 D-Bus 会话，截图及日志保存在 `target/wayland/`。`AEROBOX_TEST_SCALE=2 make wayland` 可检查 2 倍显示缩放，截图保存到 `target/wayland/scale-2/`。可用 `CARGO_TARGET_DIR=/其他目录 make package` 或 `make wayland` 将所有生成文件放到仓库外。

GitHub Actions 在 Linux amd64 / arm64 分别测试、编译和打包；分支构建产物位于 Actions，推送 `v*` 标签后自动发布到 Releases。每个架构发布一个包含程序、安装器和运行说明的 `.tar.gz`。

## 目录结构

```text
.github/workflows/  构建与发布流程
src/                Rust 源码，ui/ 为 GTK 界面
tests/              内核与数据处理集成测试
resources/          界面样式、图标、桌面入口
scripts/            安装、卸载、打包和 Wayland 检查脚本
Cargo.toml          项目与依赖声明
Cargo.lock          固定依赖版本
rust-toolchain.toml Rust 工具链
Makefile            常用开发命令
README.md           使用与开发说明
LICENSE             项目许可证
```

`src/model.rs` 管理数据、内置资源与原子存储，`engine.rs` 管理内核与 Clash API，`config.rs` 应用网络设置，`network.rs` 处理下载路径、IP 检测与内存统计，`platform.rs` 对接桌面代理及启动器；`subscription.rs` 与 `traffic.rs` 分别处理订阅解析和实时速率。

生成文件统一存放在 Git 忽略的 `target/` 中：`release/` 为程序，`packages/` 为安装包，`wayland/` 为界面检查结果。源码目录不保存构建缓存、安装包或演示截图。

## 来源与许可

基于 GUI-for-Cores / GUI.for.SingBox，遵循 GPL-3.0，见 [LICENSE](LICENSE)。
