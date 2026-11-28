# 开发

```sh
sudo pacman -S --needed rust gcc make cmake pkgconf gtk4 libadwaita gtksourceview5 librsvg
git clone https://github.com/imengying/AeroBoxForLinux.git
cd AeroBoxForLinux
cargo build --release --locked
./target/release/AeroBox
```

Rust 工具链固定为 1.100.0，见 `rust-toolchain.toml`；依赖由 `Cargo.lock` 锁定。应用面向 GNOME 51 及以上的 Wayland 会话，桌面库要求 GTK ≥ 4.10、libadwaita ≥ 1.5、GtkSourceView ≥ 5.6。Ubuntu 构建依赖为 `libgtk-4-dev libadwaita-1-dev libgtksourceview-5-dev librsvg2-common pkg-config cmake`。

```sh
make test     # 格式、Clippy、单元与集成测试
make wayland  # headless Wayland 界面测试
make package  # 生成 target/packages/*.tar.gz
make clean
```

应用的本机代理入口固定为 `127.0.0.1:2080`，设置中不保存监听端口或局域网开关。普通集成测试通过独立服务实例使用临时目录、回环地址和临时端口，验证实际流量、节点与模式切换、回滚、下载、测速和启停，不依赖外部内核，不启动特权 TUN。慢规则下载测试同时持续查询状态，验证在线更新不会被首页轮询打断；传输测试检查分享链接缺省路径、Host 和免认证 SOCKS 的实际请求。

`make test` 和 GitHub Actions 还运行 `scripts/test-protocols.sh --unit`，覆盖内置传输、DNS、TLS 与密码组件的回归测试。这个模式无需 Go、独立协议服务端或内核 kTLS 支持。组件测试以主项目的 `Cargo.lock` 为基础解析测试依赖，结束时清理临时锁文件。

`scripts/check-network.sh` 检查网络任务的归属，并验证 Vision 分帧状态机和基准工具。持续模糊测试、性能对比与连接日志说明见 [网络诊断与验证](network-validation.md)。这些开发工具不随应用安装。


`Protocol interoperability` 是独立工作流，在 main 推送、pull request、每周及手动触发时运行。使用 ubuntu-latest、固定 Go 工具链和依赖，以及经过 SHA256 校验的 sing-box 1.14.4、Xray 26.10.31，覆盖 XHTTP、Naive HTTP/2 / HTTP/3、VMess、SS 插件、TUIC、ECH、TLS 与应用协议互通，不重复运行 `--unit` 测试。标签发布执行 Rust 应用、网络组件、Wayland 和安装包检查，不构建外部 Go 测试服务或运行性能基准工具。参考服务端仅用于开发验证，不打包进 Release；打标签前检查主分支的两条工作流。kTLS 和特权 TUN 环境测试仍单独运行。

额外测试按需显式运行，测试服务端不属于应用运行依赖：

```sh
# 混合协议订阅、字段保留，以及真实 TLS ClientHello / 会话恢复
cargo test --test subscription_profiles --test tls_profiles
# 隔离命名空间内验证 TUN TCP/UDP/DNS、断网与崩溃恢复、停止清理
cargo test --test tun managed_tun_routes_traffic_and_restores_network_in_namespace -- --ignored
# 与独立 sing-box / Xray 服务端验证协议及 WS/gRPC/HTTP/XHTTP/Vision/REALITY 互通
AEROBOX_TEST_PEER=/path/to/sing-box AEROBOX_TEST_XRAY=/path/to/xray cargo test --test interop -- --ignored
# Naive HTTP/2、HTTP/3 的独立 Go 回显服务端
(cd vendor/shoes/tests/fixtures/naive-peer && go build -o /tmp/aerobox-naive-peer .)
AEROBOX_NAIVE_PEER=/tmp/aerobox-naive-peer cargo test --test naive_interop -- --ignored
# VMess、SS 插件、TUIC 0-RTT/UoT、Naive、ECH 与 TLS 分片：独立 Go 服务互通
scripts/test-protocols.sh
# 还可加入 sing-box、Xray 作为独立服务端
AEROBOX_TEST_PEER=/path/to/sing-box AEROBOX_TEST_XRAY=/path/to/xray scripts/test-protocols.sh
# Linux 6.14+ 且启用 kTLS：增加 ECH/kTLS 组合与 TLS 1.3 密钥更新测试
AEROBOX_TEST_KTLS_REKEY=1 scripts/test-protocols.sh
# 单独验证 kTLS 的密码套件、收发方向、半关闭、异常 EOF 与密钥更新
scripts/test-protocols.sh --ktls
```

独立服务端的传输测试包含 Chrome / Firefox 配置下的 VLESS WebSocket（含 early data）、gRPC、HTTP Upgrade、HTTP/2、Vision、REALITY Vision 和 AnyTLS，检查 TCP 大载荷、回传和 UDP；Vision / REALITY 还验证经 HTTP 和 SOCKS 入口传输的 HTTPS 大载荷，REALITY 额外覆盖空 short-id、显式 ALPN 和 TLS 1.3 密码套件。ECH 测试另外覆盖 Chrome / Firefox、TLS 分片，以及强制 HelloRetryRequest、配置轮换和拒绝早期数据后的重发；kTLS 组合通过 `AEROBOX_TEST_KTLS_REKEY=1` 显式启用，启用后失败不会自动降级。测试使用临时证书与合成凭据。TLS 测试直接检查发出的 ClientHello，并完成混合密钥交换、Brotli 证书解压、握手重试和会话恢复。

设置 `AEROBOX_TEST_PEER` 运行协议脚本时，还验证应用的 DNS 查询经独立 sing-box REALITY 服务端到达本地 DoH 服务，覆盖 Chrome / Firefox 和有无 Vision；递归查询必须成功，原始非递归查询仍保留原标志。这些测试不访问公共 DNS 或真实订阅。

TUN 测试需要 `timeout`、`unshare`、`ip`、`nft` 和 `/dev/net/tun`，使用独立 SOCKS 测试服务端，覆盖 IPv4/IPv6 数据报、UDP/TCP DNS 接管、切换网关、断网恢复与停止，以及强制结束进程后的恢复；所有路由更改均限制在测试命名空间内。

kTLS 测试显式运行，要求 Linux 6.14+、`CONFIG_TLS` 以及 AES-GCM / ChaCha20-Poly1305 内核算法。模块化内核可先执行 `sudo modprobe tls`；Ubuntu 托管 runner 可能未提供该模块，因此普通 CI 不运行这三项环境测试。`--ktls` 下的错误仍会使测试失败，不会静默跳过。

界面测试需要 Weston、Sway 和 `dbus-run-session`，使用隔离的 XDG 目录和 D-Bus 会话。`make wayland` 构建启用 `ui-smoke` 的开发程序，测试数据、截图逻辑及 `--smoke-test` 入口仅在该选项下编译。正式构建不启用此选项。`AEROBOX_TEST_SCALE=1.25 make wayland` 验证 1.25 倍缩放，并运行安装器检查桌面启动器与窗口标识、重复启动和启动恢复窗口；`AEROBOX_TEST_SCALE=2 make wayland` 验证 2 倍缩放。截图与日志位于 `target/wayland/`。可通过 `CARGO_TARGET_DIR` 将生成文件放到仓库外。

界面检查包含全屏与恢复窗口、缩放临界宽度、大字号侧栏和悬浮按钮避让。默认使用 1400×1000 逻辑桌面，`AEROBOX_TEST_WIDTH=1920` 可检查更宽的桌面；桌面缩放与应用的宽屏布局分别验证，普通窗口保持用户设置的字号。

`src/runtime.rs` 组装原生运行配置，`engine.rs` 管理连接生命周期和事务回滚，`protocol/` 严格转换节点参数，`model.rs` 管理数据与原子存储，`ui/` 为 GTK 界面。`vendor/` 保存带本项目修改的第三方源码，`tests/` 包含集成测试。GitHub Actions 使用 `ubuntu-latest`，仅构建 amd64，推送 `v*` 标签后发布安装包。

## 文件布局

- `src/`：AeroBox 的数据、连接管理、协议转换与桌面界面。
- `src/ui/`：页面与共用组件；`smoke.rs` 负责 Wayland 界面回归。
- `resources/icons/`、`resources/styles/`：图标与 Material 3 样式。桌面入口由 `platform.rs` 按实际安装路径生成。
- `resources/rules/`：初始规则数据及来源说明。
- `build.rs`：构建时将资源清单编译到 Cargo 输出目录，不在源码中保存生成的资源包。需要 `glib-compile-resources`（GLib 开发工具）。
- `tests/`：应用的集成测试与测试服务端。
- `tools/protocol-checks/`：网络任务静态检查与 Vision 状态机模糊测试。
- `examples/network-bench.rs`：基准测试使用的隔离应用进程，由 `scripts/bench-network.py` 驱动。
- `vendor/`：第三方源码及对应许可，`support/` 保存共享密码组件。
- `scripts/`：安装、卸载、打包和 Wayland 验证。
- `docs/`：开发说明、协议支持、网络验证和第三方来源。
- `target/`：编译产物、安装包和截图，不提交到 Git。

AeroBox 作为一个应用构建、测试和发布；连接管理和界面共用同一份状态，没有独立内核的安装或升级流程。

安装包使用明确的文件清单，只包含正式程序、安装与卸载脚本和图标。许可、使用与开发文档保留在仓库，源码、测试、截图、基准工具及已嵌入程序的规则数据不重复打包。`scripts/check-package.py` 在 CI 中检查归档内容，并在临时目录验证安装与卸载。

界面参考 [Material 3 色彩角色](https://m3.material.io/styles/color/roles)，使用 GTK 原生控件及桌面字体渲染；配色、卡片、选中状态和间距统一在 `resources/styles/` 管理。

Chrome133 的参考互通测试还覆盖 ALPS、Brotli、独立密钥共享、客户端证书认证、REALITY 认证失败和 TLS 1.2 重协商。`scripts/test-protocols.sh` 构建测试用 Go 服务端并运行生产连接路径。密码组件的完整独立测试可用 `cargo test --manifest-path vendor/support/aerobox-crypto/Cargo.toml` 运行；`tests/fixtures` 中的 CBC peer，以及上述脚本生成的 `AEROBOX_TLS_PROFILE_PEER` / `AEROBOX_TLS12_RENEGOTIATION_PEER`，用于显式运行对应 ignored 互通测试。TLS 重协商参考服务端的补丁只用于测试，由上游源码哈希和补丁后哈希校验。
