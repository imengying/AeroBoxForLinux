# AeroBox

面向 Linux / Wayland 的 sing-box 图形管理器，使用 **Rust、GTK4、libadwaita 和 GtkSourceView 5**。原生侧栏、卡片、表单和代码编辑器，支持浅色、深色及跟随系统主题。

概览提供连接控制、规则 / 全局 / 直连模式、系统代理与 TUN 开关，以及实时速度、累计流量、连接数、内存占用和 IPv4 / IPv6 出口检测。配置选择、编辑和重载集中在配置页。界面使用与 AeroBoxForAndroid 相同的飞机图标，窄窗口下统计卡片自动排列为两列。

## Arch Linux 安装成品

从 [GitHub Releases](https://github.com/imengying/AeroBoxForLinux/releases) 下载：Intel / AMD 电脑选择 `AeroBoxForLinux-linux-amd64.tar.gz`，ARM64 设备选择 `AeroBoxForLinux-linux-arm64.tar.gz`。

```sh
sudo pacman -S --needed gtk4 libadwaita gtksourceview5
tar -xzf AeroBoxForLinux-linux-amd64.tar.gz
cd AeroBoxForLinux-linux-amd64
./install.sh
```

安装到 `~/.local/bin/AeroBox` 后，在应用菜单启动 **AeroBox**。也可以直接运行解压目录中的 `./AeroBox`。运行成品不需要 Rust、Go、Node.js、npm 或 Bun。

程序需要 Wayland 会话。文件选择、剪贴板和窗口缩放使用 GTK 原生接口。Sway / Hyprland 请安装并配置桌面对应的 xdg-desktop-portal 后端。

重新运行安装器即可更新；`./uninstall.sh` 卸载程序并保留用户数据。自定义位置使用 `PREFIX=/目标目录 ./install.sh`，卸载时使用相同的 `PREFIX`。系统级安装可运行 `sudo env PREFIX=/usr/local ./install.sh`；图形界面以普通用户启动。

## 使用

1. 在设置中下载 sing-box 1.14 或更新的内核，或指定已有内核路径。内置安装器从 sing-box 官方 GitHub Release 下载并校验 SHA256。
2. 添加订阅并更新，查看和编辑节点。支持 sing-box JSON、常见 Clash YAML、Base64 及 SS / VMess / VLESS / Trojan / Hysteria2 / TUIC / SOCKS / HTTP 节点链接。
3. 选择内置的「智能分流」「代理优先」或「直连网络」，编辑配置并勾选要关联的订阅。也可导入原始 sing-box JSON，或通过脚本转换生成结果。
4. 预览并检查配置后启动内核。通过代理页切换节点和测试延迟，通过连接页查看、筛选和断开连接，通过日志页排查错误。

系统代理支持 GNOME 和 KDE Plasma，停止代理时恢复本次修改前的设置。Sway / Hyprland 等窗口管理器可使用 TUN，或在各应用中填写本地 HTTP / SOCKS 代理。关闭主窗口会停止本程序启动的内核并恢复代理。

网络设置统一控制 IPv6、局域网访问、私网绕行、流量嗅探、DNS 劫持、DNS 缓存与广告拦截；设置作用于生成配置，保留原始 JSON。运行中修改设置会先检查配置，启动失败时尝试恢复原连接。出站模式可直接切换，无需重启内核。

内置局域网、国内常用域名和常见广告三组可编辑基础规则，随程序提供，不需要先下载。国内与广告列表是小型基础列表，可按需要扩展或导入其他规则集；旧数据可从配置页或规则集页点击「添加内置」。

订阅、规则集和内核下载在连接时自动使用当前内核的代理入口，停止时直连，不读取独立下载代理设置。出口检测也使用同一路径，分别显示 IPv4 和 IPv6；无法连接相应检测服务时显示不可用。

TUN 在设置或概览中启用，支持 System、gVisor 和 Mixed 协议栈、MTU 与严格路由。需要为 **sing-box 内核**授予网络管理权限，可在设置中点击「授权」（需要 polkit 和 libcap），或手动运行：

```sh
sudo setcap cap_net_admin,cap_net_bind_service=+ep /实际路径/sing-box
```

内核更新会替换文件，需要重新授予权限。

## 数据与脚本

数据保存在 `${XDG_DATA_HOME:-~/.local/share}/singbox/state.json`，内核、规则集和生成配置位于同一数据目录。可使用 `AeroBox --data-dir /目录` 指定独立数据目录。

数据采用 JSON 格式，配置保存失败时保留编辑内容；写入数据使用原子替换。支持导入 sing-box JSON 配置和订阅地址。

配置脚本提供 `onGenerate(config)`，订阅脚本提供 `onSubscribe(nodes)`；返回转换后的 JSON 对象或节点数组，支持 `async` 函数。脚本通过内嵌 QuickJS 执行，最多运行 5 秒，使用独立的 32 MiB 内存限额。例如：

```js
function onSubscribe(nodes) {
  return nodes.filter(node => !node.tag.includes("剩余流量"));
}
```

脚本仅处理传入的数据，没有文件、网络、进程、浏览器或插件 API。

## 从源码构建

```sh
sudo pacman -S --needed rust gcc make pkgconf gtk4 libadwaita gtksourceview5
git clone https://github.com/imengying/AeroBoxForLinux.git
cd AeroBoxForLinux
cargo build --release --locked
./target/release/AeroBox
```

Rust 版本要求见 `Cargo.toml`。桌面库要求 GTK ≥ 4.10、libadwaita ≥ 1.4、GtkSourceView ≥ 5.6；Ubuntu 24.04 对应开发包为 `libgtk-4-dev libadwaita-1-dev libgtksourceview-5-dev pkg-config`。

```sh
make test     # 格式、Clippy 和单元测试
make wayland  # 无 DISPLAY 的 headless Weston 测试，结果位于 target/wayland/
make package  # target/packages/ 下的 tar.gz
make clean    # 清理 target/ 中的构建、打包和测试产物
```

已有 sing-box 内核时，可运行 `SINGBOX_TEST_CORE=/内核路径/sing-box cargo test`，额外验证三种出站模式、IPv6 与 TUN 配置组合、启动与恢复、Clash API 和 SRS 规则集编译 / 反编译。测试使用隔离目录和临时端口，不启动 TUN 或修改主机路由。

`make wayland` 还需要 Weston 和 `dbus-run-session`，Arch Linux 可安装 `weston dbus`。界面测试使用隔离的 XDG 目录和 D-Bus 会话，截图及日志保存在 `target/wayland/`。可用 `CARGO_TARGET_DIR=/其他目录 make package` 或 `make wayland` 将所有生成文件放到仓库外。

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

`src/model.rs` 管理数据、内置资源与原子存储，`engine.rs` 管理内核与 Clash API，`config.rs` 应用网络设置，`network.rs` 处理下载路径、IP 检测与内存统计，`platform.rs` 对接桌面代理及启动器；`subscription.rs`、`script.rs`、`traffic.rs` 分别处理订阅、脚本和实时速率。

生成文件统一存放在 Git 忽略的 `target/` 中：`release/` 为程序，`packages/` 为安装包，`wayland/` 为界面检查结果。源码目录不保存构建缓存、安装包或演示截图。

## 来源与许可

基于 GUI-for-Cores / GUI.for.SingBox，遵循 GPL-3.0，见 [LICENSE](LICENSE)。
