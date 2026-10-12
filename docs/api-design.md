# API design

Bytes remain `Array[Int]`. `Hash` is that array with a 32-byte check at every hashing boundary. Legacy tree size and leaf index remain `UInt`, so `TreeHead`, `InclusionProof`, `verify_inclusion`, `proof_height`, and `verify_tree_head` keep their existing types. RFC 9162 sizes and timestamps use `UInt64`.

`leaf_hash` and `node_hash` still return `Option`. `inclusion_root` returns `None` for an invalid shape, a malformed hash, or an incomplete legacy path. `verify_inclusion` then compares that root with a tree head of the same size. It folds one sibling per level.

`merkle_tree_hash` and `merkle_tree_hash_by_stack` must agree. `inclusion_path` builds the RFC 9162 minimal path, and `verify_merkle_inclusion` checks it, including the extra shift. `consistency_proof` and `verify_consistency` cover prefix growth. Equal sizes are accepted only with an empty proof and equal roots. These names are separate from the legacy API; there is no alias that pretends the old fold is the RFC 9162 path.

Codec functions copy caller buffers and return `CtError`. v1 extensions are raw opaque bytes. v2 extensions are typed, strictly ascending, and reject type 65535. TransItem uses one 16-bit type and no extra version byte. Reserved, experimental, and private type ranges are `Unsupported`; other unknown codes are `BadEnum`. JSON is a restricted parser: unsigned integers only, standard padded base64, no duplicate keys, and stable key order for STH, inclusion, and consistency messages.

`MemoryLog` stores raw leaves, requires strictly increasing timestamps, and recomputes both Merkle roots before returning one. It does not verify signatures. Checkpoint and proof encoders only format data the caller has already checked. Cryptographic functions stay injected, so the package has no hidden FFI and no network dependency.
