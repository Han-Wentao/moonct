# MoonCT 严格查重与范围复核

## 本次复核结论（2026-10-13）

本次检查日期为 **2026-10-13**。参赛截止日期是 **2026-10-30**；二者不是同一日期。早期 2026-10-03 记录保留为当时较窄的首版范围证据，不能替代本次对 v0.2.0 扩展范围的复核。

**结论（限定 MoonBit 生态）：在本次记录的 MoonCakes.io 与 MoonBit/GitHub 检索范围内，未发现一个 MoonBit 包覆盖 MoonCT 当前整套 CT 工件工作流；但 RFC 6962 Merkle 根/包含证明存在直接重合，且 GitHub 上另有 JavaScript PKI 工具，对 RFC 6962/9162 Merkle 证明和 CT 日志流程存在直接功能重合。** 因此 MoonCT 不宣称通用 Merkle 算法原创或全球唯一。保留理由仅是提供原生 MoonBit 的 CT 数据模型与协议组合；跨语言实现说明这不是全球范围的新问题，也不消除 MoonCT 的算法重复风险。若评审门槛要求功能在所有语言中都必须新颖，则本项目不满足该门槛。

该结论是有边界的检索结果，不等于不存在任何相似代码或软件。若将项目缩减为通用 Merkle 根/包含证明库，应直接判定与相邻包重合，不应以 MoonCT 名称继续包装。

## 候选能力指纹

- **问题域**：MoonBit 中 CT 日志证明与 CT 工件的跨运行时验证/互操作。
- **主要工作流**：消费叶子、树大小、索引、证明和 STH；校验输入与树形约束；由调用方提供哈希/签名回调；比较计算根与 STH；按需编解码 CT v1/v2 工件或 JSON，并生成/核验 RFC 9162 consistency。
- **核心数据与输出**：`TreeHead`、legacy `InclusionProof`、RFC 9162 `MerkleInclusion`/`MerkleConsistency`、v1 签名与叶子结构、v2 `TransItem`、受限 JSON 消息、`MemoryLog` 检查点；结果为结构化工件、错误或确定性验证结论。
- **明确边界**：不实现哈希或签名原语，不解析 X.509/ASN.1/DER，不做 HTTP 客户端、CT 服务端或密钥发现。

## 检索范围与查询词

### MoonCakes.io

2026-10-13 使用本机 `moon search <query> --limit 100` 检索：`certificate transparency`、`CT log`、`Signed Tree Head`、`RFC 6962`、`RFC 9162`、`Merkle inclusion proof`、`Merkle consistency proof`、`SCT list`、`TransItem`、`inclusion_path`、`consistency_proof`、`verify_inclusion`。检查匹配包的索引说明、包名/版本/下载量，并通过公开源码仓库核对相关实现及测试；结果仅代表当日公开索引。

### GitHub / MoonBit 源码

2026-10-13 使用 GitHub 仓库检索词 `moonbit certificate transparency`、`moonbit RFC 9162`、`moonbit signed tree head`、`moonbit consistency proof`，均未返回完整 CT 日志客户端/验证库。另对代码执行反向检索：`"RFC 6962" language:MoonBit`、`"RFC 9162" language:MoonBit`、`"Signed Tree Head" language:MoonBit`、`"consistency_proof" language:MoonBit`、`"new_memory_log" language:MoonBit`、`"verify_tree_head" language:MoonBit`、`"parse_sct_list" language:MoonBit`。其中 RFC 6962 和 SCT 查询命中下列源码；STH、RFC 9162、consistency、内存日志和 `verify_tree_head` 这些特征词没有命中另一套相同的 CT 工作流。代码搜索受 GitHub 索引/权限/精确字符串影响，不构成全量证明。

## 已核验项目与能力矩阵

| 项目 | 检查到的源码/范围 | 与 MoonCT 的关系 | 判定 |
| --- | --- | --- | --- |
| [MoonSecureCodec](https://github.com/wch6766/moon_secure_codec)；MoonCakes `wch6766/MoonSecureCodec@0.1.1`（索引显示 15 次下载；GitHub 最近推送 2026-08-16） | 检查 `lib/merkle/merkle.mbt`、`merkle_test.mbt` 和 README。实现 `0x00`/`0x01` 域分离、RFC 6962 风格 Merkle 树、树根、逐叶 inclusion proof 生成和 `verify_proof`；测试包括参考向量、奇数叶子数和篡改检测。它的主产品还包括多种 codec、digest、manifest 与供应链审计。 | 与 MoonCT 的 RFC 6962 Merkle hashing/inclusion 基础能力**直接重合**；已确认，不能写成“仅标题相似”。检查到的描述未覆盖 MoonCT 的 STH 语义、RFC 9162 consistency、CT v1/v2 工件和受限 CT JSON 组合。 | 底层算法直接重合；不是当前整套 CT 协议库的单包替代品。 |
| [MoonEvidence](https://github.com/wenlittle/MoonEvidence)；MoonCakes `starlittle/MoonEvidence@0.5.1`（索引显示 49 次下载；GitHub 最近推送 2026-07-11） | 检查 `src/merkle/merkle.mbt`、whitebox/property/golden 测试。其 evidence-pack 产品中的 Merkle 模块计算 RFC 6962 风格 root、生成并验证 inclusion proof，支持配置 `HashAlgorithm`；测试包含树形/篡改用例和 Node.js golden cross-check。 | Merkle 根与 inclusion 算法有**直接能力重合**；其主要输入/输出是 evidence pack，不是 CT STH、RFC 9162 consistency 或 CT wire/JSON 消息工作流。 | 底层算法直接重合；证据包与 CT 日志协议方向相邻。 |
| [mizchi/experimental_crypto](https://github.com/mizchi/experimental_crypto)；MoonCakes `@0.0.2`（索引显示 8,959 次下载；GitHub 最近推送 2026-06-02） | 检查 `ct/ct.mbt` 和 `ct/ct_test.mbt`。解析 SCT list、构建 signed entry、计算 log ID，并用 SPKI 验证 SCT 签名。 | 是最接近的 CT 相邻包，但其核心是证书 SCT 解析/签名验证；没有检索到 Merkle inclusion/consistency 或日志 STH 验证流程。MoonCT 不解析 X.509，也不实现签名算法。 | 同一 CT 方向、不同核心工作流。 |
| [moon-certified](https://github.com/Juwan-Hwang/moon-certified)；MoonCakes `@0.1.1`（索引显示 21 次下载；GitHub 最近推送 2026-08-27） | 检查 `crypto/merkle_tree/merkle_tree.mbt`。实现 SHA-256 通用树与 inclusion proof，奇数层使用 Bitcoin 式节点复制；仓库是广泛算法集合。 | 通用 Merkle inclusion 相邻；奇数叶行为及用途边界不同，不提供 CT 工件或 STH 工作流。 | 算法相邻。 |
| [MoonReplayKit](https://github.com/LAOBIAO656/MoonReplayKit)；MoonCakes `@0.2.0`（索引显示 19 次下载；GitHub 最近推送 2026-07-06） | 检索描述、源码树和测试名称；主流程是确定性状态机回放、检查点/分歧诊断及状态证据树。 | 使用 Merkle 风格 inclusion 证明，但被证明对象是事件/状态转换，不是 CT 日志叶子与 STH。 | 同方向不同问题域。 |
| [mizchi/converge_audit](https://github.com/mizchi/converge_audit) | GitHub `verify_inclusion` 代码搜索命中 `src/audit/merkle`；属审计证据树源码。 | 关键词/算法相邻，没有发现 CT log STH、v1/v2 工件或 RFC 9162 consistency 工作流。 | 相邻命中，非直接替代品。 |
| [@blamejs/pki](https://github.com/blamejs/pki)（JavaScript；Apache-2.0；2026-10-13 API 快照，GitHub 最近推送时间为 2026-10-12 20:40 UTC） | 检查 `lib/merkle.js`、`lib/ct.js`、`test/layer-0-primitives/merkle.test.js`、`ct.test.js` 与 `ct-log-client.test.js`。Merkle 模块覆盖 RFC 6962/9162 根计算及包含/一致性证明生成与验证；CT 模块包含 SCT、STH 与 CT log 客户端路径。 | 对 MoonCT 的证明算法和 CT 日志工作流构成功能层面的直接跨语言重合；该项目是更广的 JS PKI 栈（含 X.509、ASN.1/DER、CMS、PQC），不是 MoonBit 可直接依赖的包。MoonCT 是独立 MoonBit 实现的功能子集，并非全新算法或全球独有能力。 | 强跨语言功能重合；不构成 MoonBit/MoonCakes 直接依赖替代品，但显著削弱全球功能新颖性主张。若比赛不接受跨语言同类实现或功能子集移植，此项目不应以原创新方向申报。 |

## 官方比赛助手规则对照

按本机已安装的 `$osc2026-guide` 指引，参考其竞赛章程与 `supplemental-knowledge.md`：MoonBit 已有高度重合且维护良好的项目时应考虑换方向；若保留相近方向，须说明新增价值、差异和适用场景，并检查来源/许可证。该指南没有针对 MoonCT 给出自动审批或“查无重合”的结论。本次因此将两项 RFC 6962 Merkle 直接能力重合作为明确风险，而不是弱化为零重合。

## 保留范围的理由与决策

**决策：保留 MoonBit 专用 CT 工件/API 层，但将 RFC 6962 Merkle 重合列为实质风险；不把项目描述为算法创新、全球唯一或通用 Merkle 库。** MoonEvidence、MoonSecureCodec 可替代部分 Merkle 基础能力，`@blamejs/pki` 有高度相近的跨语言证明与 CT 工作流。依赖/协作能减少基础算法重复，但这些现有包不能直接提供 MoonBit 下的本库 CT v1/v2 模型、当前 codec/JSON API 与多目标接口；本项目仍自行实现了重合的底层算法，这一点不应淡化。若赛事门槛禁止跨语言同类实现，或要求避免任何低层重复，应停止申报/发布；否则仅以 MoonBit 生态缺少原生 CT 工件组合为贡献边界。

## 复核限制

- MoonCakes 搜索依赖其当日公开索引及本机工具链摘要；下载量和版本是检索时快照。
- GitHub 仓库/代码搜索仅覆盖公开且可被索引的内容；查询词匹配和默认分支会影响命中。
- 源码阅读针对表中明确路径及相关测试，不等于审计每个仓库的所有版本、分支或安全性。
- “MoonBit 包未发现整套替代品”不等于全球没有同类功能；本次已记录 `@blamejs/pki` 跨语言强重合。源码阅读针对明确文件及测试，不构成完整安全审计。

## 初始查重记录（2026-10-03）

2026-10-03 针对当时较窄的 `MoonCT`、`tree_head_valid`、`proof_shape_valid`、`verify_inclusion`、`verify_tree_head` 范围做了 MoonCakes/GitHub 关键词复核。当时结果未发现专门的 CT STH 工作流。该记录形成于 RFC 9162 consistency、v1/v2 codecs、CT JSON 和内存日志扩展之前，不能用来代表本次扩展复核；本次检索补上了此前遗漏的 RFC 6962 Merkle 同类能力。
