# MoonCT 0.2.0

MoonCT 0.2.0 expands the CT-specific protocol surface while preserving the legacy RFC 6962 inclusion verifier. It adds RFC 9162 tree hashes, minimal inclusion paths, consistency proofs, supported v1/v2 artifact codecs, restricted CT JSON, and in-memory log checkpoints.

This is an original MoonBit implementation of protocol behavior, not a port of a third-party codebase. The RFC 6962 Merkle inclusion algorithm overlaps with MoonSecureCodec and MoonEvidence. GitHub also has an actively maintained JavaScript PKI toolkit, `@blamejs/pki`, with closely related RFC 6962/9162 proof and CT workflows. MoonCT is not claimed as a globally unique algorithm or a drop-in replacement for that PKI stack. See the dated source-level review in `docs/competition/duplicate-check.md`.

## Verification

- `moon fmt --check` passed.
- `moon check --deny-warn` passed for wasm, wasm-gc, js, and native.
- `moon test --target wasm-gc` and `moon test --target js` each passed 26 tests.
- The local native test could not run because the environment has no `cc`, `gcc`, or `clang`; the repository CI workflow runs the native test target.
- `moon run --target wasm-gc cmd/main` printed the expected proof measurements `3`, `2`, and `1`.
- Non-test library implementation contains 4,426 physical `.mbt` lines.

Cryptographic primitives, certificate parsing, and network access remain caller responsibilities and are not implemented here. The package is available from this GitHub source repository; it has not been uploaded to MoonCakes.io.

# MoonCT 0.1.0

MoonCT 0.1.0 was the initial RFC 6962 inclusion-proof core. It validated proof shape and delegated cryptographic primitives to the host.

The recorded initial validation was 14 passing MoonBit tests, warning-free checks, formatting, and a runnable proof-height example.
