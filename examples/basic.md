# Basic proof-shape demonstration

Run the executable example from the repository root:

```sh
moon run --target wasm-gc cmd/main
```

The example creates seven sample leaves with an injected deterministic mixing function (not a cryptographic hash), then reports:

```text
legacy inclusion height for tree size 7: 3
RFC 9162 inclusion path length for index 6: 2
RFC 9162 consistency proof length from 4 to 7: 1
```

This small example demonstrates why the legacy RFC 6962 path and RFC 9162 minimal path must not be confused. The test suite covers the cryptographic callback boundary, malformed input, encoding, and proof verification; see the repository verification commands in `README.md`.
