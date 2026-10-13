# MoonCT

MoonCT is a runtime-agnostic MoonBit library for Certificate Transparency (CT) proof logic and log artifacts. It covers the CT-specific path from proof/tree-head inputs through validation and wire/JSON artifacts; it is not a general-purpose Merkle database. The RFC 6962 leaf/node hashing and inclusion-proof capability overlaps directly with existing MoonBit Merkle libraries; an actively maintained JavaScript PKI toolkit also implements closely related RFC 6962/9162 and CT workflows. The source-level comparison and its impact on the project’s novelty claim are disclosed in [`docs/competition/duplicate-check.md`](docs/competition/duplicate-check.md).

## What it implements

- RFC 6962 domain-separated leaf/node hashing and the legacy level-by-level inclusion proof, with tree-size, index, hash-length, and proof-shape checks.
- RFC 9162 Merkle Tree Hash (recursive and stack forms), minimal inclusion paths, and consistency proof generation/verification.
- RFC 6962 v1 signed-value, SCT, Merkle-leaf, and tree-head input codecs; RFC 9162 v2 TransItem codecs for the supported `0x0100`–`0x0106` range.
- Restricted CT JSON encoding/decoding for STH, inclusion, and consistency messages.
- An in-memory log with monotonic timestamps, checkpoints, inclusion proofs, and consistency proofs.

The library does **not** implement SHA-256, signature algorithms, X.509/ASN.1/DER parsing, network clients, CT log servers, or log-key discovery. Hashing and STH signature verification are supplied by the caller. Passing an injected test hash does not constitute cryptographic verification.

## Proof-format boundary

The legacy RFC 6962 proof and RFC 9162 minimal inclusion path are different formats. For a tree of size 7, `proof_height(7)` is 3, while `inclusion_path` for index 6 has length 2. The consistency proof from size 4 to size 7 has length 1. `proof_shape_valid` prevents the shorter RFC 9162 path from being passed as a legacy proof. Equal-size consistency proofs are empty and accepted only when the roots match; invalid size relationships are rejected.

## Try it from source

This repository is the available distribution. **MoonCT has not been published to MoonCakes.io**, so `moon add Han-Wentao/moonct@0.2.0` is not an available installation command. MoonCakes publication is intentionally separate.

```sh
git clone https://github.com/Han-Wentao/moonct.git
cd moonct
moon test --target wasm-gc
moon run --target wasm-gc cmd/main
```

The runnable demonstration uses a deterministic sample hash (not SHA-256) and prints:

```text
legacy inclusion height for tree size 7: 3
RFC 9162 inclusion path length for index 6: 2
RFC 9162 consistency proof length from 4 to 7: 1
```

The generated public interface is in [`pkg.generated.mbti`](pkg.generated.mbti); package and protocol notes are in [`docs/api-design.md`](docs/api-design.md) and [`docs/protocol-boundary.md`](docs/protocol-boundary.md).

## Verification

Run these commands from the repository root:

```sh
moon fmt --check
moon check --target wasm --deny-warn
moon check --target wasm-gc --deny-warn
moon check --target js --deny-warn
moon check --target native --deny-warn
moon test --target wasm-gc
moon test --target js
moon run --target wasm-gc cmd/main
```

On the recorded local run, both test targets passed all 26 tests; all four `moon check --deny-warn` targets passed. Native tests could not be executed locally because no `cc`, `gcc`, or `clang` is installed; the CI workflow includes native tests. The implementation count is 4,426 physical lines across non-test library `.mbt` files; see the per-file accounting in [`docs/protocol-boundary.md`](docs/protocol-boundary.md).

## License and disclosure

Apache-2.0. AI assistance is disclosed in [`AI-USE.md`](AI-USE.md). No third-party implementation source is included as a dependency.
