# MoonCT

MoonCT is a runtime-agnostic MoonBit library for Certificate Transparency proofs and log artifacts. It keeps the original RFC 6962 level-by-level inclusion verifier and adds RFC 9162 Merkle tree hashes, minimal inclusion paths, consistency proofs, v1/v2 wire codecs, restricted CT JSON, and an in-memory log. Callers inject SHA-256 and signature checks. The library does not implement those primitives, parse X.509, or speak HTTP.

## Two inclusion formats

The legacy verifier and the RFC 9162 minimal path are not interchangeable.

- `proof_height(7)` is `Some(3)`. Every legacy inclusion proof for a tree of size 7 has three siblings.
- `inclusion_path` for index 6 in that same tree has length 2.
- `consistency_proof` from size 4 to size 7 has length 1.
- `proof_shape_valid` rejects the length-2 RFC 9162 path when it is presented to the legacy verifier.

Equal tree sizes use an empty consistency proof only when the two roots match. A zero first size, or a first size larger than the second, is `BadIndex`. When the sizes differ, an empty consistency path fails before the power-of-two prepend.

## Scope

Included:

- legacy leaf and node domain separation and inclusion folding
- RFC 9162 recursive and stack Merkle tree hashes
- RFC 9162 inclusion and consistency generation and verification
- RFC 6962 v1 Merkle leaves, SCTs, digitally signed values, and tree-head signed input
- RFC 9162 v2 TransItem values `0x0100` through `0x0106`
- RFC 6962 JSON for STH, inclusion, and consistency messages
- an in-memory log with monotonic timestamps, checkpoints, and proof export

Excluded:

- SHA-256, ECDSA, Ed25519, and any other cryptographic primitive
- X.509, ASN.1, and DER parsing
- HTTP clients, CT log servers, and key discovery

Public bytes stay `Array[Int]`. Legacy tree size and leaf index stay `UInt`. New CT sizes and timestamps use `UInt64`. Node hashes are 32 bytes.

## Example

`moon run cmd/main` builds seven sample leaves with an injected mix function, not SHA-256, and prints:

```text
legacy inclusion height for tree size 7: 3
RFC 9162 inclusion path length for index 6: 2
RFC 9162 consistency proof length from 4 to 7: 1
```

## Verification

Commands run for this expansion:

```text
moon fmt --check
moon check --deny-warn
moon check --deny-warn --target wasm-gc
moon check --deny-warn --target js
moon test
moon run cmd/main
```

`moon check --deny-warn` passes for the default wasm target, wasm-gc, and js. Native was not run because this environment has no C toolchain. `moon test` passes 22 tests. Non-test library `.mbt` sources, excluding `cmd/`, tests, and generated `.mbti`, contain 4412 physical lines. The per-file count is in `docs/protocol-boundary.md`.

## License

Apache-2.0. MoonCT is an original MoonBit implementation of the public RFC 6962 and RFC 9162 descriptions. It does not copy another project's source.
