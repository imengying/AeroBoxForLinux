# 协议与订阅

支持 Shadowsocks（含 SS2022）、VMess、VLESS、Trojan、AnyTLS、Hysteria2、TUIC、Naive、SOCKS 和 HTTP。受支持的传输和安全参数按实际实现转换；未知字段和未实现参数会明确报告位置，避免导入后静默丢失设置。不提供 ShadowTLS、Snell。

Clash 订阅为未使用 TLS 的节点附带 `client-fingerprint` 时，该字段不参与连接，也不会导致节点被跳过；启用 TLS 后会校验并应用指定指纹。

Shadowsocks 支持应用内实现的 `obfs-local`（HTTP / TLS 混淆）和 `v2ray-plugin`（WebSocket、TLS、Xray mux 帧、QUIC）。Clash 的 `plugin-opts` 和 SIP003 分享链接参数会转换到同一实现；插件证书文件在启动时读取。原生 SS UDP 直接使用服务器的 UDP 端口，TCP 插件不会改变 UDP 的线协议。WebSocket mux 当前每个连接使用一个逻辑流，不跨连接共享会话；QUIC 则复用会话中的双向流。

`client-fingerprint: chrome` / `firefox`、分享链接 `fp` 和 JSON `tls.utls` 使用应用内的 Rust TLS 实现，覆盖普通 TLS 与 REALITY。Chrome 按 [sing-box 1.14.4](https://github.com/SagerNet/sing-box/tree/v1.14.4/common/tls)固定使用的 [uTLS 1.8.7 Chrome133 模板](https://github.com/metacubex/utls/blob/v1.8.7/u_parrots.go)构造握手：15 种真实密码套件（包括 TLS 1.2 CBC / RSA）、GREASE、扩展顺序随机化、Brotli 证书解压及 h2 ALPS 17613。X25519MLKEM768 与 X25519 分别生成独立密钥。ALPS 17513/17613 的参数交换、重试、恢复和早期数据由 TLS 层实现，但应用 Chrome 配置按固定模板关闭会话恢复及 0-RTT。

普通 Chrome TLS 1.2 允许一次服务端发起的安全重协商，校验此前 Finished、证书、ALPN 和 EMS，重新认证后再继续发送应用数据。Chrome 的显式版本、密码套件、曲线设置必须与模板相符；Vision / ECH / REALITY 内部仍强制 TLS 1.3。Chrome133 是 TCP TLS 模板，不能用于 QUIC。Firefox 仍是基于实际能力的 Firefox120 风格布局，提供第二份独立 P-256 共享，不宣称完整浏览器模拟。两者都不包含浏览器的 HTTP 行为。

未启用 ECH 时带 GREASE ECH；启用后使用真实加密 ClientHello。REALITY Chrome 握手移除混合交换，只使用参与认证的 X25519 共享；其特殊证书验签规则仅限 REALITY。

启用 `tls.utls` 而未填写指纹时使用 Chrome。普通 TCP 浏览器握手默认 ALPN 为 `h2`、`http/1.1`；WebSocket / HTTP Upgrade / HTTPS 代理默认 `http/1.1`，gRPC / HTTP2 / Naive 默认 `h2`（Naive QUIC 使用 `h3`）。节点显式指定的 ALPN 会保留，传输开始前校验协商结果，避免 HTTP 版本错配。REALITY 支持显式 ALPN 和已实现的 TLS 1.3 密码套件。

VMess / VLESS 的用户标识支持 UUID 和字符串。VLESS 支持 `encryption: none` 与 `mlkem768x25519plus` 原生加密（`native` / `xorpub` / `random`，`0rtt` / `1rtt`），Clash、JSON 与分享链接均保留参数。REALITY 未填写 `short-id` 时使用协议的空 ID。AnyTLS 支持 `idle-session-check-interval`、`idle-session-timeout`（整数秒）、`min-idle-session` 和 `client-metadata`，UDP 通过原生 UoT v2 传输；`udp: false` 或 `udp-over-tcp: false` 会禁用 UDP。

导入和更新保留有效节点，无法导入的节点记录序号、名称和具体字段原因；界面提示跳过数量，不另设导入结果页面。

协议名称相同不代表所有参数组合都已完成互通验证。节点导入、运行配置校验和本地协议测试覆盖各自的边界；具体服务端仍须用实际连接验证。

VMess 同时支持 AEAD（`alter_id: 0`）与仍在使用的旧认证协议（`alter_id: 1–65535`），载荷加密支持 `auto`、`aes-128-gcm`、`chacha20-poly1305`、`aes-128-cfb`、`none` 和 `zero`，支持 TCP、UDP、TLS 及已有传输组合。`global_padding` 与 `authenticated_length` 按所选密码方案应用。Clash 的 `alterId` 和分享链接的 `aid` 会保留并校验。

VLESS 的 `xtls-rprx-vision` 使用 TLS、REALITY 或 VLESS 原生加密，不与 WebSocket、gRPC 等额外传输或多路复用叠加；Vision UDP 使用 XUDP。节点声明 `network: "tcp"` 时禁止该节点转发 UDP，开启 UoT 或多路复用也不会覆盖此限制。

VMess / VLESS 支持普通 UDP、XUDP 与 `packetaddr` 编码；VLESS 默认 XUDP，VMess 默认普通 UDP，`packet_encoding` 可设为 `"xudp"`、`"packetaddr"` 或空字符串。`packetaddr` 在发送前按节点 DNS 策略解析目标域名并编码 IP 地址。XUDP 支持跨传输分片发送最长 65535 字节的数据报；空数据报在线协议中没有 UDP 载荷语义，需使用 `packetaddr` 或支持空包的原生 UDP 编码。导入时检查用户标识、密钥、TLS 参数和内联证书，订阅更新保留有效节点并报告无效项；证书文件在启动时读取检查。

Hysteria2 支持 Salamander 混淆、Brutal 带宽参数和端口跳跃。Clash 的 `ports`、`hop-interval`（整数秒或 `15-30` 范围）、`up` / `down`（支持 bps / Kbps / Mbps / Gbps / Tbps 单位）以及分享链接 `mport` 会保留；JSON 使用 `server_ports`、`hop_interval`、`hop_interval_max`、`up_mbps` / `down_mbps`。带宽保留小数，缺省为自动控制。

TUIC 支持 `udp_relay_mode: native`、`udp_relay_mode: quic` 和独立的 `udp_over_stream`（SagerNet UoT v2），后者不能与显式 UDP relay mode 同用。`heartbeat`、Clash `heartbeat-interval` 支持毫秒精度；`disable-sni` 保留证书验证，只控制线上 SNI。TUIC 的 `zero_rtt_handshake` / Clash `reduce-rtt` 启用 TLS 1.3 会话恢复与 0-RTT；首次连接完成完整握手，后续连接使用服务端票据。早期 TCP 数据有界缓存，服务端验证完成且确认拒绝早期数据后才重发；网络错误不会触发盲目重放，UDP 在认证完成后发送。要求仅混合密钥交换的配置不能使用 0-RTT。

节点支持 `connect_timeout`，例如 `250ms`、`1.5s`、`1m30s`，统一限制节点 DNS 解析和连接尝试的耗时。TCP 节点还支持 `disable_tcp_keep_alive`、`tcp_keep_alive` 和 `tcp_keep_alive_interval`；保活时间接受正数毫秒时长，按 Linux 套接字的秒精度向上取整，例如 `250ms` 为 1 秒、`1.5s` 为 2 秒，结果上限 32767 秒。这些 TCP 设置不适用于 QUIC。

Naive 支持 HTTP/2 与 HTTP/3。HTTP/2 的 `stream_receive_window` 按上游 Naive/Cronet 的语义设置**连接窗口**，单流窗口为其一半（向下取整）；默认分别为 128 MiB、64 MiB。HTTP/3 的 `stream_receive_window` 与 `quic_session_receive_window` 分别控制单流和连接窗口，默认 6 MiB、15 MiB，独立生效。零表示默认；HTTP/2 不接受非零 QUIC 连接窗口。受内存预算限制，单流窗口范围为 16 KiB–64 MiB，连接窗口为 16 KiB–128 MiB，HTTP/2 的连接窗口因此至少 32 KiB。支持这些参数不代表复现 Chromium 的全部网络行为。

`tls.handshake_timeout` 控制 TLS、REALITY 和 QUIC 握手等待时间，支持毫秒精度，缺省为 15 秒；超时会关闭连接。Clash `handshake-timeout` 的数字按秒转换。

gRPC / HTTP2 传输支持 `idle_timeout` 和 `ping_timeout`；gRPC 还支持 `permit_without_stream`。空闲达到设定时间后发送 PING，有接收活动时推迟检查，未在期限内收到确认则关闭失效连接。`idle_timeout` 缺省或为零时关闭检查，`ping_timeout` 缺省或为零时使用 15 秒。

`tcp_fast_open`、`tcp_multi_path` 使用 Linux 的 TCP Fast Open 和 MPTCP 套接字；它们只适用于 TCP 传输。MPTCP 是否使用多条路径取决于操作系统和服务端配置。`udp_fragment` 控制 IPv4 / IPv6 UDP 套接字的分片策略，并同步作用于 QUIC 和 Hysteria2 端口跳跃创建的套接字。

ECH 支持 `tls.ech.enabled`、内联 PEM `config`、PEM 文件 `config_path` 和 DNS HTTPS 记录发现；`query_server_name` 可覆盖查询域名。Clash `ech-opts.config` 按其格式接收 base64 ECHConfigList。TCP TLS 和 QUIC 均支持 ECH，HTTPS 记录按 TTL 缓存。服务端轮换配置时，仅在公用名称的证书和握手验证通过后重试一次，新的配置在第二次握手成功后缓存；不会降级为明文 ClientHello。ECH 需要 DNS 形式的 TLS 服务名及启用 SNI，不能与 REALITY 同用。

`tls.fragment` 拆分 ClientHello 的 TCP 发送，`tls.record_fragment` 拆分 TLS 记录，两者支持普通 TLS 与 REALITY。`fragment_fallback_delay` 为等待 TCP 确认的备用延时，缺省为 `500ms`。分片不适用于 QUIC；与 ECH 同用时拆分的是加密 ClientHello 外层的公开 SNI。

`tls.kernel_tx` / `tls.kernel_rx` 分别启用 Linux kTLS 发送和接收，可以单独开启。支持 TLS 1.2 / 1.3 的 AES-128-GCM、AES-256-GCM、ChaCha20-Poly1305，并处理会话票据、密钥更新、关闭通知和半关闭。TLS 1.3 密钥更新要求 Linux 6.14 或更新版本及相应 kTLS 配置；操作系统缺少能力会返回具体错误。kTLS 需要直接 TCP 承载，不能与 QUIC、REALITY、Vision 的原始 TLS 切换或嵌套加密承载组合。Chrome 的 TLS 1.2 安全重协商连接也不能交给 kTLS；Chrome 的 TLS 1.3 连接可以。


互通测试入口为 `scripts/test-protocols.sh`，使用固定依赖的独立 Go 服务。`scripts/test-protocols.sh --ktls` 单独运行全部 kTLS 环境测试，要求 Linux 6.14+ 且已启用 kTLS 与所需密码算法；普通 `--unit` 回归不依赖这些内核能力。
