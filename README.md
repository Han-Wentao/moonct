# MoonCT

MoonCT is a runtime-agnostic MoonBit library for validating Certificate Transparency Merkle proofs. It models Signed Tree Head fields, RFC 6962 leaf/node domain separation, inclusion-proof folding, proof-shape checks, tree-head invariant checks, and host-supplied signature verification.

## Scope

The library deliberately does not implement SHA-256, ECDSA/Ed25519, X.509 parsing, HTTP clients, or a CT log server. Callers inject `sha256` and signature verification so the same proof core can run on wasm, wasm-gc, JavaScript, and native hosts without hidden FFI assumptions.

## Example

```moonbit
let leaf = @moonct.leaf_hash(sha256, certificate_leaf_bytes)
let accepted = @moonct.verify_inclusion(sha256, leaf.unwrap(), proof, tree_head)
```

The public API uses `Array[Int]` as a portable byte-vector representation. A host adapter can convert its byte type at the boundary and keep the proof algorithm deterministic.

## Verification

```text
moon check
moon test
moon fmt --check
moon run cmd/main
```

## License

Apache-2.0. The project is an original implementation. It follows the public RFC 6962/RFC 9162 protocol descriptions and delegates cryptographic primitives to the caller; it does not copy code from an upstream implementation.

## Public validation helpers

`is_valid_hash`, `proof_shape_valid`, and `tree_head_valid` expose cheap structural checks for adapters that want to reject malformed data before invoking cryptographic work.
