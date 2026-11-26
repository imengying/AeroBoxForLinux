# 网络诊断与验证

参考 [Concord](https://github.com/chen08209/concord/tree/b3fab9e0fb81330c65bf62dea47caef845468747) 的分阶段诊断、协议状态机验证、任务归属检查和性能测量思路，以下工具直接检查 AeroBox 的现有实现。应用仍作为一个整体构建和运行；这些工具只用于开发。

## 连接诊断

连接失败日志包含目标、错误类别和失败阶段，例如：

```text
connection peer=127.0.0.1:12345 kind=UnexpectedEof: target=example.test:443 route=["node-0"]: stage=relay_download: stage=vless_response received=1 expected=2: ...
```

- `outbound_setup`：出站连接尚未完成。
- `dns`：包含查询名、记录类型、DNS 配置名与耗时；`dns_exchange` 进一步标明上游传输、IP 和端口。
- `dns_bootstrap`：解析 DNS 上游自身的域名失败，保留原始错误类型和超时标记。
- `connect`、`tls_handshake`、`reality_handshake`：连接或握手失败及耗时。
- `relay_upload`、`relay_download`：从本地入口看上传或下载方向失败。
- `vless_response`：VLESS 响应头收到的字节数和需要的字节数。

诊断包装保留原始错误链和错误类别，DNS 建连保留、请求期限与资源上限判断仍使用原始标记。日志不添加节点密码、UUID、私钥或订阅地址；目标域名和上游地址属于排障信息，分享前可自行脱敏。

默认日志级别为 ERROR，可以在设置中实时调整。连接结束按错误类型和阶段分级，系统代理入口和 TUN TCP 使用同一规则：

| 情况 | 级别 |
| --- | --- |
| 主动取消连接、规则拦截、DNS NXDOMAIN / 无地址回答 | DEBUG |
| 已进入转发阶段的连接重置、断管、对端断开 | DEBUG |
| DNS SERVFAIL、请求超时、连接拒绝或网络不可达 | WARN |
| VLESS 对端在返回响应头之前关闭连接或超时 | WARN |
| 用户态 TLS 已建立后缺少 `close_notify` 的截断 | WARN |
| 证书 / 认证失败、损坏的协议数据、已收到部分 VLESS 响应头后截断、其他未分类故障 | ERROR |

参考 [sing-box 的连接关闭分级](https://github.com/SagerNet/sing-box/blob/testing/route/conn.go)及 [Mihomo 的连接诊断](https://github.com/MetaCubeX/mihomo/blob/Meta/tunnel/tunnel.go)，避免把取消或普通连接结束全记为 ERROR。判断使用错误类型与上下文，不匹配日志字符串；握手阶段的重置仍保留为 ERROR。NXDOMAIN 是否来自广告拦截无法仅凭响应码判断。

降低日志级别不改变失败结果、超时或重试语义。TLS 异常关闭前已经读取的有效载荷先转发、刷新，再返回原始错误；缺少关闭通知不会被转换成成功 EOF。VLESS 没有目标连接失败的状态码，因此零字节响应保留为连接警告；已收到部分响应头后截断仍为 ERROR。主动取消立即终止转发。双栈 DNS 查询都未得到地址时，保留较严重的失败，避免另一个地址族的空回答掩盖超时或 SERVFAIL。

`tests/diagnostics.rs` 使用真实本地 DNS/TLS/代理连接检查分级、设置即时生效和响应数据；组件测试另外检查错误链及反压下的转发。排查具体节点时可临时使用 WARN 或 DEBUG；ERROR 默认不显示上表中的警告和调试事件。

首页出口检测同时查询 IPv4 和已启用的 IPv6，每种地址族依次尝试自己的服务，成功后立即更新界面。IPv6 较慢或失败不会阻止 IPv4 显示。单次请求及连接最长 12 秒，总预算 30 秒。启动连接后检测使用当前代理入口，失败不会绕过代理直连。回归测试使用本地 CONNECT + TLS 服务模拟超过 5 秒的首次建连，以及 IPv6 等待时 IPv4 先行显示，不需要真实订阅或公共检测接口。

## 网络不可用时启动

参考 [Mihomo 的 DoH 客户端](https://github.com/MetaCubeX/mihomo/blob/Meta/dns/doh.go)，配置准备与联网查询分离。启动时校验 DNS 地址、依赖关系和出站配置，首次查询再解析上游域名并建立连接；没有网络不会仅因远程 DNS 域名暂时无法解析而阻止本地服务启动。

首次解析与连接重建共用请求时限和串行初始化锁。超时或取消释放初始化锁，之后的请求可重试；成功后复用连接。不同域名的上游独立初始化，某个域名解析失败时仍可尝试其他已配置的上游。不会绕过所选代理或额外改用未配置的公共 DNS。移除了附加到所有 DNS 准备错误上的 QUIC 内存上限提示，资源耗尽仍通过原始错误报告。

`tests/routing_dns.rs` 验证不可用 DNS 下启动、恢复后不重启即可通过所选节点访问，以及 HTTP / SOCKS 入口的一致性。组件测试覆盖首次初始化的时限、并发等待与取消、多个上游、无效配置和 QUIC 资源约束。首次使用且尚无缓存的远程规则仍需成功下载后才能启用，避免缺少规则时悄悄改变分流。

## 任务归属检查

```sh
scripts/check-network.sh
```

检查器使用 `syn` 遍历 `vendor/shoes/src/lib.rs` 引用的生产模块，识别 Tokio 启动函数、导入别名、运行时句柄及宏中的直接启动表达式。网络任务应交给现有的 `NetworkTasks`，或由局部 `JoinSet`、中止守卫、明确在 `Drop` 中中止的字段持有。借用的 `JoinSet` 不自动视为安全归属。少量运行时适配边界在检查器内逐项列明，新增启动点需要重新审核。

这是一项语法检查，不是 Rust 类型分析或生命周期证明。跨函数传递的函数指针、复杂过程宏展开和隐藏在第三方接口中的任务仍需代码审核。现有任务取消与应用启停测试继续负责验证实际行为。

## Vision 状态机模糊测试

```sh
# 固定输入回归包含在 check-network.sh 中
scripts/fuzz-vision.sh 60
```

轻量工具直接编译生产 `vision_unpad.rs`，生成有效帧、错误命令、UUID 前缀、不同分片、Pending、正常 EOF 和传输异常。期望载荷在生成输入时独立记录，验证不丢失、不重复、END / DIRECT 时序和有限输入下的终止。

脚本在固定 Rust 工具链上启用 LLVM 覆盖率插桩与 libFuzzer，不启用内存 sanitizer。范围是 Vision 去填充状态机；真实异步 TLS、身份校验与流关闭语义由组件及互通测试验证。不能将状态机测试通过理解为全部协议已接受模糊测试。

输入语料和崩溃输入分别位于 `target/protocol-fuzz/corpus/`、`artifacts/`。每周及手动 GitHub Actions 运行 120 秒并保留这两个目录。复现单个输入：

```sh
target/protocol-fuzz/x86_64-unknown-linux-gnu/release/vision /path/to/crash-input
```

## 网络基准

```sh
cargo build --release --locked --example network-bench
python3 scripts/bench-network.py \
  --candidate target/release/examples/network-bench \
  --baseline /path/to/baseline/network-bench \
  --sing-box /path/to/sing-box \
  --output target/bench-comparison \
  --rounds 5 --mib 64 --operations 500
```

`--baseline`、`--sing-box` 可省略。提供 sing-box 时增加与独立 Shadowsocks AES-128-GCM 服务端的测试，否则只测直连。每个版本、协议和轮次启动新应用进程，并交替候选与基线的顺序。数据接收端、负载生成器及可选协议服务端使用独立进程；全部地址为回环地址，凭据为合成数据，不启动系统代理或 TUN，不读取用户配置。

测量包括上下行吞吐量、64 字节回显延迟、短连接速率、应用 CPU 时间、预热后 RSS 和累计峰值 RSS。每段载荷校验内容与长度；中途失败仍写入标记为未完成的报告，不输出成功结果。`results.json` 保留逐次样本、p50/p99、二进制哈希、版本、CPU 亲和性和系统计时精度；`report.md` 汇总各项中位数。

这些数值衡量应用的网络服务进程，不包含 GTK 窗口渲染、TUN 或公网条件。Python 负载端也可能成为瓶颈；同一轮的峰值 RSS 包含此前负载，极短测试的 CPU 时间可能低于系统计时精度。应在空闲机器上使用 release 构建、多轮相同负载，保留原始样本；脚本不自动宣称性能提升，也不以固定速度作为 CI 门槛。可使用 `--core-cpus` 和 `--server-cpus` 指定进程 CPU 列表。

仅验证工具可运行时：

```sh
cargo build --locked --example network-bench
python3 scripts/bench-network.py \
  --candidate target/debug/examples/network-bench \
  --output target/bench-smoke --rounds 1 --mib 1 --operations 10 --smoke
```

结果目录必须尚不存在；`--smoke` 允许 debug 构建并将结果标为工具验证，不能用于性能结论。
