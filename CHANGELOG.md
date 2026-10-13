# Changelog

## 0.2.0 - 2026-10-13

- Added RFC 9162 Merkle Tree Hashes, minimal inclusion paths, and consistency proof generation and verification while retaining the legacy RFC 6962 verifier.
- Added supported RFC 6962 v1 and RFC 9162 v2 artifact codecs, restricted CT JSON, and an in-memory log.
- Recorded 4,426 physical lines of non-test library MoonBit and 26 passing tests on each of wasm-gc and JavaScript.
- Documented RFC 6962 Merkle overlap with MoonSecureCodec and MoonEvidence, plus the cross-language CT/Merkle overlap with `@blamejs/pki`; no algorithm-uniqueness claim is made.
- Added a source-only usage path; MoonCakes.io publication remains separate and has not been performed.

## 0.1.0 - 2026-10-03

- Added runtime-agnostic RFC 6962 leaf and node hashing boundaries.
- Added inclusion-proof folding, tree-size checks, and proof-shape validation.
- Added callback-based Signed Tree Head signature verification.
- Added deterministic tests, CI, protocol documentation, and a runnable example.
