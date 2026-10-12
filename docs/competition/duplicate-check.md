# 查重记录：MoonCT

- 检查日期：2026-10-03
- 选题：Certificate Transparency 日志证明验证库；核心对象为 Signed Tree Head、叶子哈希、内部节点哈希、inclusion proof 和主机注入的签名验证器。
- 最终决策：继续建设 MoonCT；在记录的检索范围内未发现成熟的 MoonBit 直接替代实现。
- 复核日期：实现完成前、远程仓库创建前和申报前各复核一次。

## 检索关键词

`certificate transparency`, `CT log`, `Signed Tree Head`, `STH`, `Merkle inclusion proof`, `Merkle consistency proof`, `RFC 6962`, `RFC 9162`, `ct verifier`, `certificate log proof`, `inclusion_root`, `node_hash`, `verify_inclusion`。

## MoonCakes 检索

使用本机 MoonBit 工具链执行 `moon search <keyword> --limit 50`。CT、STH、inclusion proof 和 signed tree head 没有返回专门的 MoonBit CT 日志验证库。返回的相邻结果主要是通用密码、Merkle、证据或 X.509 相关包；这些结果不提供 CT 日志证明工作流。

## GitHub / MoonBit 检索

使用 GitHub CLI 的 MoonBit 仓库和代码检索，并检查注册表中的全部保留指纹。没有发现以 CT 日志 STH、inclusion proof 和 consistency proof 验证为中心的 MoonBit 仓库。`moon_dns` 是权威 DNS 服务器，`dns-checker` 的 DNSSEC 检查是另一套信任链；OCI、WebAssembly Component、PCAP、ELF 和 OpenTelemetry 方向均存在直接或高度相邻项目，因此没有采用这些方向。

## 相邻能力矩阵

| 相邻方向 | 用户/输入 | 中心算法 | 与 MoonCT 的关系 | 判定 |
| --- | --- | --- | --- | --- |
| 通用 Merkle / 证据库 | 任意证据包、通用树或回放数据 | 通用哈希树或证据封装 | 不负责 CT 的 STH、日志树大小和 RFC 6962 审计路径 | 同方向不同功能 |
| X.509 / DER | 证书、DER 字节 | 证书字段解析 | MoonCT 不解析证书，仅验证已准备好的日志叶子与证明 | 同方向不同功能 |
| DNSSEC | DNSKEY、RRSIG、DS | DNS 信任链验证 | MoonCT 不解析 DNS 记录或验证 DNSSEC | 无实质重合 |
| OCI / provenance | 镜像 manifest、SBOM、构建证明 | 内容摘要和供应链证明 | MoonCT 不处理镜像、SBOM 或发布 provenance | 无实质重合 |

## 候选淘汰记录

- MoonDNSSEC：MoonCakes 有 `chgttyyr/moon_dns`，GitHub 另检出 `O6lvl4/dns-checker` 的 DNSSEC 检查实现，中心工作流直接重合，淘汰。
- MoonOCI：MoonCakes 有 `oyjh0381/moonoci`，并有 `mizchi/wacon`、`Hhsqoo/artifactdock` 相邻项目，淘汰。
- MoonWasmComponent：已有 `Milky2018/wasm_component`、`mizchi/mwac`、`mizchi/wite`、`mizchi/wit` 和 `pei0331/moon-wit`，淘汰。
- MoonELF：已有 `moonbit-community/elf`、`wuhaiting321/dwarfscope` 和 `prowk/binschema` 的 ELF 能力，淘汰。
- MoonPCAP：已有 `cghyyrrt/moonbit-pcap`、`usagi-star/mooncap` 等 PCAP/PCAPNG 能力，淘汰。
- MoonOpenTelemetry：已有 `moonbit-community/opentelemetry`、`brickfrog/moontrace` 等实现，淘汰。

## 限制与复核

MoonCakes 搜索依赖公开索引和当前工具链结果；GitHub 搜索依赖公开仓库及 CLI 返回范围。结果不能证明全球不存在同类项目。提交前将再次用最终 API 名称和能力描述反向搜索，并把新增的直接重合项目加入注册表。

## 实现前最终复核

2026-10-03 对最终 API 名称 `MoonCT`、`tree_head_valid`、`proof_shape_valid`、`verify_inclusion` 和 `verify_tree_head` 重新做了 MoonCakes/GitHub 关键词反向检索；未发现直接同名或以 CT 日志 STH inclusion-proof 验证为中心的 MoonBit 项目。现有相邻项目仍按上表保留边界说明。


## 2026-10-30 扩展复核

一致性证明、v1/v2 编解码、CT JSON 和内存日志进入实现范围后，再次用本机 MoonBit 工具链执行有界 `moon search`。这次可以看到相邻包，因此不能沿用“没有邻近 CT 或 Merkle 包”的说法。没有对这些包运行 `moon doc`，下面只记录检索结果本身。

- `mizchi/experimental_crypto/ct`：Certificate Transparency RFC 6962，解析 SCT 列表中的 X.509 扩展，构造已签名条目，计算 log ID，并对照 SPKI 验证 SCT 签名。重心是 SCT 解析和签名验证，不是 Merkle inclusion 或 consistency。MoonCT 仍然不解析 X.509，也不实现签名。
- `wch6766/MoonSecureCodec/lib/merkle`：通用安全编解码工具中的 RFC 6962 Merkle 树、inclusion proof 和数据完整性检查。这是最近的通用 Merkle 邻居，属于供应链编解码，不是 CT 日志的 STH、两种 inclusion、consistency、v1/v2 TransItem 和 CT JSON 库，也不应写成 CT 日志客户端。
- `starlittle/MoonEvidence`：证据包的 Merkle inclusion proof，哈希可配置。输入对象不同。
- `LAOBIAO656/moonreplaykit`：回放证据中的 Merkle 风格证明。工作流不同。
- `mizchi/experimental_crypto/rfc3161`：时间戳令牌，只是相邻的密码能力，不是 CT 证明。

2026-10-03 的查重没有发现直接的 CT 库。2026-10-30 的复核发现了上面这些邻居。其中没有一个同时覆盖 CT 日志 STH、旧式 inclusion 与 RFC 9162 最短路径、consistency、v1/v2 工件、CT JSON 和内存日志。扩展因此留在现有 MoonCT 中，而不是另起一个项目。
