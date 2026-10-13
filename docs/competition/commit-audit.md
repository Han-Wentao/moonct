# MoonCT Git 提交有效性审计

完成本轮审计文档提交后，仓库历史为 31 个原始提交；本表选出其中 20 个彼此可区分、可由文件差异复核的实质提交，达到项目 Skill 的 20 个有效提交门槛。SHA 均为完整值。

表内验证证据指最终 HEAD 上保留的实现/测试及本次本地复验：`moon info`、`moon fmt`、`moon check --deny-warn`（wasm/wasm-gc/js/native）、`moon test`（wasm-gc/js，各 26 项）、可运行示例。native 测试需由 GitHub CI 验证，本机没有 C 编译器。

| SHA | 主题 | 变更文件 | 实质工作与验证证据 |
| --- | --- | --- | --- |
| `2bcfe6321dd34a12cfa48280e0a54e7513517eec` | chore: initialize MoonCT project and identity | `.githooks/README.md`, `.githooks/pre-commit`, `.github/workflows/ci.yml`, `.github/workflows/copilot-setup-steps.yml`, `.gitignore`, `AGENTS.md`, `LICENSE`, `README.mbt.md`, `README.md`, `cmd/main/main.mbt`, `cmd/main/moon.pkg`, `docs/competition/duplicate-check.md`, `moon.mod`, `moon.pkg`, `moonct.mbt`, `moonct_test.mbt`, `moonct_wbtest.mbt` | 建立 MoonCT 包结构、身份与初始实现 初始 package、元数据、README、核心源文件与测试；最终全目标检查和 26 项测试验证当前树。 |
| `0cca37e0ecce892f25fc53b60bbc9b1480958a5c` | fix: make proof example warning-free and package metadata accurate | `cmd/main/main.mbt`, `moon.mod`, `moonct.mbt`, `moonct_test.mbt` | 修复证明示例警告并校准包元数据 更新示例、moon.mod、证明 API/测试；最终 wasm-gc 示例和测试通过。 |
| `d1fcf673ced5aa816da88233fd30251adc18f8de` | feat: expose hash and proof shape validation | `moonct.mbt`, `moonct_test.mbt` | 公开哈希形状与证明形状校验 增加可复用结构校验及测试；最终 `hash shape`、`proof shape` 测试通过。 |
| `7f76b03b94b4639a9f3c6c06ee5dfbba51cbb33c` | docs: define RFC 6962 protocol boundary | `docs/protocol-boundary.md` | 定义 RFC 6962 协议边界 记录 API 支持/不支持的协议范围；与最终 `docs/protocol-boundary.md` 一致。 |
| `faec73649c71155fd5bafa00931a4b221498e17a` | test: lock down leaf and node domain separation | `moonct_test.mbt` | 测试叶子与节点域分离 固定 RFC 6962 leaf/node 前缀不混淆的回归测试；最终测试通过。 |
| `b54958578231e79535a619850825aa2bf402246b` | test: reject malformed internal node inputs | `moonct_test.mbt` | 拒绝畸形 Merkle 内部节点 加入错误输入回归测试；最终测试通过。 |
| `8bc6e1b4a190d3bb41745e5d6f59c2d74f2a03ec` | ci: fail builds on MoonBit warnings | `.github/workflows/ci.yml` | CI 对 MoonBit 警告失败 调整 GitHub Actions 的检查门禁；最终四目标 `moon check --deny-warn` 通过。 |
| `638a099a303eee84f140c1916de80aecc8f872bc` | build: record generated MoonBit package interfaces | `cmd/main/pkg.generated.mbti`, `pkg.generated.mbti` | 记录生成的 MoonBit 包接口 提交生成接口文件，保障可复核 API；最终 `moon info` 无接口差异。 |
| `62d04e8c578afcb456cd478d9ed24e9037334b2e` | feat: expose signed tree head invariant validation | `moonct.mbt` | 提供 Signed Tree Head 不变量校验 增加 STH 结构约束 API；与后续 STH 测试共同验证。 |
| `0fe0f9052b1e43cfe1ee53135dcb89fe59731bd4` | test: cover signed tree head invariant failures | `moonct_test.mbt` | 覆盖 Signed Tree Head 不变量失败 加入版本/空树等拒绝路径；最终测试通过。 |
| `6afc7778adacd34ef4b4a7d4c4e0781ad925f033` | test: reject incomplete signed tree head inputs | `moonct_test.mbt` | 拒绝缺失签名输入的 STH 补全签名输入失败测试；最终测试通过。 |
| `4eb1aed5e419b1f562ebce771943f2e3c545ae75` | feat: add CT framing and RFC 9162 Merkle proofs | `bytesutil.mbt`, `error.mbt`, `merkle.mbt`, `tlsio.mbt` | 实现 CT framing 与 RFC 9162 Merkle proofs 增加字节工具、错误模型、RFC 9162 树与传输边界；最终一致性/包含路径测试通过。 |
| `416fc3794871856d49962bb9185e423b3449c9ef` | feat: encode and decode RFC 6962 and RFC 9162 artifacts | `rfc6962.mbt`, `rfc9162.mbt` | 编解码 RFC 6962 与 RFC 9162 工件 加入两代 CT 工件模型与 codec；最终 v1/v2 round-trip 和畸形输入测试通过。 |
| `9095ca5af4e6fcda5a8d2d7238d50c0e76d4045e` | feat: add CT JSON messages and an in-memory log | `jsonct.mbt`, `logmem.mbt` | 增加 CT JSON 消息与内存日志 实现受限 JSON 及日志检查点；最终 JSON、双树根与 checkpoint 测试通过。 |
| `bc9e6a7220d661684749be74ad175a8d00a05fe1` | test: cover RFC vectors, codecs, and log checkpoints | `cmd/main/main.mbt`, `protocol_wbtest.mbt` | 覆盖 RFC vectors、codec 与日志检查点 添加协议向量和端到端测试；最终 26 项测试在 wasm-gc/JS 通过。 |
| `03a3bfd062cc07480f2453a6dcb9978863114cb5` | fix: reject noncanonical base64 padding | `bytesutil.mbt`, `bytesutil_wbtest.mbt` | 拒绝非规范 Base64 padding 增加 pad-bit 和规范编码检查；最终 RFC 4648 测试通过。 |
| `2bda8b37074606450b47689f20c4211c37e8811a` | fix: validate hash bytes at protocol boundaries | `hardening_wbtest.mbt`, `moonct.mbt` | 在协议边界校验哈希字节 加强 32 字节/无符号字节约束；最终 hash-boundary 测试通过。 |
| `453140ebacfe4aed2a281b333ee6821691e50377` | fix: avoid overflow in legacy proof sizing | `hardening_wbtest.mbt`, `moonct.mbt` | 避免旧版证明长度溢出 使用安全边界处理极大树大小；最终 UInt 上界回归测试通过。 |
| `24a42033104bfe6b9fe354b45dc6f4d229794340` | fix: isolate byte readers and atomic opaque writes | `hardening_wbtest.mbt`, `tlsio.mbt` | 隔离字节读取器并保证 opaque writes 原子性 避免输入别名与部分写入；最终输入所有权/原子写测试通过。 |
| `34081924d73ce56d1698b39b08ae496dcb7d5426` | ci: check and test across supported MoonBit targets | `.github/workflows/ci.yml` | 配置跨支持目标的 CI 检查与测试 增加 wasm/wasm-gc/JS/native 矩阵及可运行示例 job；推送后以 GitHub Actions 结果复核。 |

## 审计结论

未把空提交、仅格式化提交或单纯删除文件计入这 20 项。该表不把 31 个原始提交一概宣称有效；它只对列出的 20 个提交给出可核查的工程目的和最终验证证据。native 测试未在本机执行；推送后的 GitHub Actions 运行状态另行核验。
