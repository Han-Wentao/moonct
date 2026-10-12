# Changelog

## 0.2.0 - 2026-10-30

- Added RFC 9162 Merkle tree hashes, minimal inclusion paths, and consistency proofs without changing the legacy inclusion verifier.
- Added RFC 6962 v1 and RFC 9162 v2 artifact codecs, restricted CT JSON, and an in-memory log.
- Recorded 4412 physical lines of non-test library MoonBit and 22 passing tests.
- This version is recorded in `moon.mod`. It is not a new GitHub release.

## 0.1.0 - 2026-10-03

- Added runtime-agnostic RFC 6962 leaf and node hashing boundaries.
- Added inclusion-proof folding, tree-size checks, and proof-shape validation.
- Added callback-based Signed Tree Head signature verification.
- Added deterministic tests, CI, protocol documentation, and a runnable example.
