# AeroBox RustCrypto provider

这个 Rust 2024 crate 为 AeroBox 提供显式选择的 `rustls 0.23.46` 密码提供者，
支持 TLS 1.2、TLS 1.3 和 QUIC 所需的包保护及头部保护。它以固定版本
`rustls-rustcrypto 0.0.2-alpha` 为基础，补齐签名、证书校验、P-521、TLS 记录和
QUIC 接口。密码运算均使用 RustCrypto。

```rust
let config = rustls::ClientConfig::builder_with_provider(
    aerobox_crypto::shared_provider(),
)
.with_safe_default_protocol_versions()?
.with_root_certificates(root_store)
.with_no_client_auth();
```

调用方提供正常的信任根和目标主机名。该 crate 不改变进程的默认提供者，
也不关闭证书或主机名验证；`provider()` 返回可配置的独立实例，
`shared_provider()` 复用同一个 `Arc<CryptoProvider>`。

覆盖三种 TLS 1.3 套件和六种 ECDHE TLS 1.2 套件：AES-128-GCM、
AES-256-GCM、ChaCha20-Poly1305，TLS 1.2 分别支持 ECDSA/RSA 认证。
密钥交换使用 X25519、P-256、P-384、P-521。对上游 alpha 增加了以下适配：

- P-521 ECDSA SHA-256/384/512 验证、TLS SHA-512 签名、PKCS#8/SEC1 私钥和双向认证。
- RSA 签名与验证支持 2048–8192 位密钥、PKCS#1 SHA-256/384/512 和 PSS SHA-256/384/512。
- RSA、P-256/P-384/P-521 签名与 P-521 密钥交换通过可失败的系统熵请求初始化本地随机数生成器；系统随机数故障返回错误。
- 按 rustls 内置提供者的界限设置 AES-GCM 每个 TLS 密钥最多 `2^24` 条记录。
- 按 RFC 9001 设置 QUIC 保密性和完整性界限，支持密钥更新及路径专用 nonce。
- 拒绝 X25519 全零共享秘密，拒绝 NIST 曲线不符合 TLS 要求的压缩公钥编码。
- 接受 ChaCha20 头部保护的完整 32 位计数器范围，先校验输入再修改头部。
- 对过短的 TLS 1.2 ChaCha20 记录返回错误，修复上游整数下溢。
- 修复 AES 记录流量密钥导出的算法标签及 TLS 1.2 完整 IV 组装。

Chrome 133 或显式指定的 TLS 1.2 套件还可启用 `legacy_cbc::suites()` 和
`legacy_rsa::suites()`：四种 ECDHE AES-CBC-SHA 套件，以及四种静态 RSA
AES-GCM/AES-CBC-SHA 套件。普通 `provider()` 保持上述九种 AEAD 套件。
静态 RSA 仅支持客户端密钥传输，并检查证书的 `keyEncipherment` 用途；
RSA 服务端仍可使用 ECDHE 签名认证。CBC 使用独立 MAC 密钥、不可预测的显式 IV，
按密文长度执行全部可能的填充/MAC 检查。它不提供 kTLS 流量密钥导出，
解密吞吐也低于 AEAD。这些是 TLS 协议能力，不涉及旧版应用的数据迁移。

依赖树不含 ring、AWS-LC、OpenSSL、C 密码库或 `cc` 构建依赖。
Rust 的 `libc` 绑定仍用于操作系统随机数及 CPU 能力查询。
此结论只适用于本 crate 的依赖树；完整应用需要另外检查 feature 合并和最终链接产物。
`hpke` 模块提供 ECH 所需的 RFC 9180 基础模式接口，使用 RustCrypto 的 X25519 / P-256 / P-384 / P-521、HKDF 和三种 AEAD；ECH 配置与重试策略在应用传输层处理。测试保留 Linux 的连续上下文/认证用例，并加入九组 RFC 向量，每组 257 条连续消息。REALITY、ML-KEM 和 ML-DSA 由其它模块提供。

上游提供者仍是 alpha，并明确不建议生产使用。本地补充测试不等于安全审计，
也不代表完成全部平台性能或全部证书算法组合的验收。
上游密钥生成遇到操作系统随机数故障时的错误处理也尚未重写。
参考：[RustCrypto 提供者](https://github.com/RustCrypto/rustls-rustcrypto)、
[rustls 密码接口](https://docs.rs/rustls/latest/rustls/crypto/index.html)。

从仓库根目录执行：

```sh
cargo test --offline --manifest-path vendor/support/aerobox-crypto/Cargo.toml
cargo clippy --offline --manifest-path vendor/support/aerobox-crypto/Cargo.toml --all-targets -- -D warnings
```

默认测试在内存中完成，不依赖网络、OpenSSL 可执行文件或系统证书目录。
内容包括全部 TLS 套件、ECDSA/RSA 认证、错误主机名、三种 QUIC 套件的握手和
双向数据加密、密钥更新、全部密钥交换组、低阶/错误公钥、头部边界和数据篡改。
AES-GCM 与 ChaCha20 完整包的预期字节来自
[RFC 9001 附录 A](https://www.rfc-editor.org/rfc/rfc9001.html#appendix-A)。
证书、私钥及额外向量的生成说明见 `tests/fixtures/README.md` 和对应测试注释。

标记为 `ignored` 的互通测试使用本机独立 Go 服务，不访问订阅或用户配置。
`AEROBOX_CBC_PEER` 指向 `tests/fixtures/cbc-peer/main.go` 编译的服务，
覆盖 CBC、静态 RSA、Chrome 133 的 TLS 1.2 协商、会话恢复、OCSP 和双向认证。
其它浏览器组合分别使用 `AEROBOX_TLS_PROFILE_PEER`、`AEROBOX_ECH_PEER`、
`AEROBOX_TLS12_RENEGOTIATION_PEER`；运行对应测试目标并传入 `-- --ignored --test-threads=1`。
