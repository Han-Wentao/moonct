# MoonCT protocol boundary

MoonCT implements CT-specific proof and artifact behavior from RFC 6962 and RFC 9162. Callers supply hash functions, signatures, and already-decoded or encoded artifacts. The package does not fetch logs or interpret certificate ASN.1.

## Included

- leaf domain separation (`0x00 || leaf`) and node domain separation (`0x01 || left || right`)
- the RFC 6962 level-by-level inclusion fold, including odd-width promotion
- tree-size, leaf-index, hash-length, and legacy proof-shape validation
- callback-based Signed Tree Head signature verification
- RFC 9162 Merkle Tree Hash, both recursive and stack forms
- RFC 9162 minimal inclusion paths and consistency proofs
- RFC 6962 v1 Merkle leaves, SCTs, digitally signed values, and tree-head signed input
- RFC 9162 v2 extensions and TransItem codes `0x0100` through `0x0106`
- restricted CT JSON for STH, inclusion, and consistency messages
- an in-memory log with monotonic timestamps and checkpoint export

## Proof formats and invariants

`verify_inclusion` retains the legacy RFC 6962 path format. For tree size 7, `proof_height(7) == Some(3)`. The RFC 9162 path for index 6 has length 2, and the consistency proof from size 4 to size 7 has length 1. These proof types are not interchangeable.

Consistency generation and verification follow the RFC for `0 < first < second`. When tree sizes are equal, the proof is empty and succeeds only if roots match. `first == 0` or `first > second` returns `BadIndex`; these cases are not forced through the strict algorithm. The wire codec preserves artifact structure; semantic size relationships are enforced by verification.

## Relationship to adjacent implementations

MoonCT is not a claim to invent RFC 6962 Merkle hashing. MoonSecureCodec implements domain-separated RFC 6962 Merkle trees and inclusion-proof creation/verification, and MoonEvidence implements RFC 6962-style roots and inclusion proofs. Those are material overlaps at the Merkle algorithm layer. GitHub also contains the actively maintained JavaScript `@blamejs/pki` toolkit, whose RFC 6962/9162 Merkle code and CT/SCT/STH workflows are a strong cross-language functional comparator. It is not a MoonBit dependency or drop-in package. MoonCT's declared scope is a MoonBit CT API around STH validation, legacy and RFC 9162 proof semantics, consistency proofs, CT v1/v2 artifact codecs, CT JSON, and log checkpoints. It remains independently implemented to provide a runtime-agnostic `Array[Int]` API with caller-injected hashing/signature callbacks and no cryptographic runtime dependency. This target-language distinction is not a claim that the underlying Merkle capability or CT problem is unique. The comparison evidence and limits are in [`competition/duplicate-check.md`](competition/duplicate-check.md).

## Intentionally excluded

SHA-256, ECDSA/Ed25519, X.509/DER parsing, HTTP log clients, CT log servers, and key discovery remain outside MoonCT. The in-memory log is a local data structure, not a network service or a production CT log.

## Implementation size and tests

Physical lines include blank lines. Counts exclude `*_test.mbt`, `*_wbtest.mbt`, `cmd/`, generated `.mbti`, Markdown, and configuration files. They were counted with Python `splitlines()` after formatting.

| File | Physical lines |
| --- | ---: |
| `bytesutil.mbt` | 322 |
| `error.mbt` | 46 |
| `jsonct.mbt` | 1,003 |
| `logmem.mbt` | 363 |
| `merkle.mbt` | 528 |
| `moonct.mbt` | 263 |
| `rfc6962.mbt` | 652 |
| `rfc9162.mbt` | 844 |
| `tlsio.mbt` | 405 |
| **Total** | **4,426** |

The package has 26 MoonBit tests. All passed on wasm-gc and JavaScript locally. `moon check --deny-warn` passed on wasm, wasm-gc, js, and native. Native tests were not runnable locally because no system C compiler (`cc`, `gcc`, or `clang`) is installed; CI is configured to run them on a hosted runner.
