# MoonCT protocol boundary

MoonCT implements the deterministic RFC 6962 Merkle inclusion layer. It accepts already-decoded leaf bytes, audit paths, tree size, root hash, and host-provided Signed Tree Head signature inputs.

## Included

- leaf domain separation (`0x00 || leaf`)
- node domain separation (`0x01 || left || right`)
- RFC-style audit-path folding with odd-width promotion
- tree-size, leaf-index, hash-length, and path-shape validation
- callback-based Signed Tree Head signature verification

## Intentionally excluded

Certificate parsing, ASN.1/DER, SHA-256, ECDSA/Ed25519, HTTP log clients, log serving, consistency proofs, and key discovery are host or follow-up components. Keeping these boundaries explicit prevents a portable proof library from silently making security claims about code it does not own.
