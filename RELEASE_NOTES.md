# MoonCT 0.2.0

Version 0.2.0 expands the local library. It is recorded in `moon.mod` and these notes. It has not been published as a GitHub release.

The expansion keeps `verify_inclusion` behavior and adds RFC 9162 tree hashes, minimal inclusion paths, consistency proofs, v1 and v2 codecs, CT JSON, and an in-memory log. Cryptography, X.509 parsing, and network I/O remain outside the package.

Validation for this expansion: 22 MoonBit tests pass, `moon check --deny-warn` passes on wasm, wasm-gc, and js, formatting passes, and `moon run cmd/main` prints 3, 2, and 1. Non-test library sources contain 4412 physical lines.

# MoonCT 0.1.0

MoonCT 0.1.0 is the first reusable MoonBit Certificate Transparency proof core. It verifies RFC 6962 inclusion paths against a supplied tree head, validates proof shape before hashing, and delegates cryptographic primitives to the host.

Validation performed for this release: 14 MoonBit tests pass, `moon check --deny-warn` passes, formatting passes, and the runnable command example reports a bounded proof height.
