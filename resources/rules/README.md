# Android 同款内置规则

规则列表与 `AeroBoxForAndroid/app/src/main/kotlin/com/aerobox/core/geo/GeoAssetManager.kt` 相同。当前 Android 源码目录没有打包的 `.srs` / `.xz` 文件，因此直接取得该管理器指定的三个 SagerNet 官方二进制规则，作为 Linux 离线首启的完整种子。

取得日期：2026-11-11。运行时使用对应 `rule-set` 分支地址，每 24 小时由 sing-box 后台更新。下载缓存优先于种子；本地种子不是最新更新时间证明。

| 文件 | 官方来源 | 种子所在提交 | SHA-256 |
|---|---|---|---|
| `geoip-cn.srs` | [SagerNet/sing-geoip](https://github.com/SagerNet/sing-geoip/blob/rule-set/geoip-cn.srs) | `eb32cd6ed4a16fcb3bf9a36ccebf28e45716ae84` | `81ada5cafd9d831adc48776f29cdfe55c9713d9287caeef9de925ef30f66cce4` |
| `geosite-cn.srs` | [SagerNet/sing-geosite](https://github.com/SagerNet/sing-geosite/blob/rule-set/geosite-cn.srs) | `23066e3b0833d1484916637dde2b5bae80178045` | `07ce0fef9aa39d9ed1f10b98e9f7f97afb3ac81ae9ae650acef2f72e67ef1484` |
| `geosite-category-ads-all.srs` | [SagerNet/sing-geosite](https://github.com/SagerNet/sing-geosite/blob/rule-set/geosite-category-ads-all.srs) | `23066e3b0833d1484916637dde2b5bae80178045` | `5577fd713d8479b6df9bcfe5832eab9d6d4fd5a34ea5748460618ed30526cb0c` |

两个上游项目声明 GPL-3.0-or-later。原始版权与许可声明分别保存在 [sing-geoip-LICENSE](sing-geoip-LICENSE) 和 [sing-geosite-LICENSE](sing-geosite-LICENSE)。
