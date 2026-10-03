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
