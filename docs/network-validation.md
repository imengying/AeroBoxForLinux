# 网络诊断与验证

参考 [Concord](https://github.com/chen08209/concord/tree/b3fab9e0fb81330c65bf62dea47caef845468747) 的分阶段诊断、协议状态机验证、任务归属检查和性能测量思路，以下工具直接检查 AeroBox 的现有实现。应用仍作为一个整体构建和运行；这些工具只用于开发。

## 连接诊断

连接失败日志包含目标、错误类别和失败阶段，例如：

```text
connection peer=127.0.0.1:12345 kind=UnexpectedEof: target=example.test:443 route=["node-0"]: stage=relay_download: stage=vless_response received=1 expected=2: ...
```

- `outbound_setup`：出站连接尚未完成。
- `dns`：包含查询名、记录类型、DNS 配置名与耗时；`dns_exchange` 进一步标明上游传输、IP 和端口。
- `connect`、`tls_handshake`、`reality_handshake`：连接或握手失败及耗时。
- `relay_upload`、`relay_download`：从本地入口看上传或下载方向失败。
- `vless_response`：VLESS 响应头收到的字节数和需要的字节数。

诊断包装保留原始错误链和错误类别，DNS 建连保留、请求期限与资源上限判断仍使用原始标记。日志不添加节点密码、UUID、私钥或订阅地址；目标域名和上游地址属于排障信息，分享前可自行脱敏。

本地 DNS 规则主动生成的拒绝以 DEBUG 记录；上游返回的 NXDOMAIN、SERVFAIL、超时与 TLS 非正常截断仍保留错误。不能仅凭 NXDOMAIN 判断发生了广告拦截，也不能将缺少 `close_notify` 的截断统一视为正常 EOF。

首页出口检测同时查询 IPv4 和已启用的 IPv6，每种地址族依次尝试自己的服务，成功后立即更新界面。IPv6 较慢或失败不会阻止 IPv4 显示。单次请求及连接最长 12 秒，总预算 30 秒。启动连接后检测使用当前代理入口，失败不会绕过代理直连。回归测试使用本地 CONNECT + TLS 服务模拟超过 5 秒的首次建连，以及 IPv6 等待时 IPv4 先行显示，不需要真实订阅或公共检测接口。

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
