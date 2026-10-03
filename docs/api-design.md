# API design

The public API uses `Array[Int]` for bytes so adapters can bridge MoonBit targets without forcing one runtime-specific byte container. `Hash` is an alias with a strict 32-element invariant checked at every hashing boundary.

`leaf_hash` and `node_hash` return `Option` rather than throwing. `inclusion_root` returns `None` for invalid shape, malformed hashes, or an incomplete path. `verify_inclusion` then compares the derived root with a tree head of the same tree size.

Cryptographic primitives are injected as functions. This keeps the package small and lets a host select a vetted SHA-256 and signature implementation.
