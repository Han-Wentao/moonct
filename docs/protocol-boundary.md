# MoonCT protocol boundary

MoonCT implements deterministic Certificate Transparency proof logic from RFC 6962 and RFC 9162. Callers supply leaf bytes, hashes, signatures, and already-decoded or encoded artifacts. The package does not fetch logs or interpret certificate ASN.1.

## Included

- leaf domain separation (`0x00 || leaf`) and node domain separation (`0x01 || left || right`)
- the original level-by-level inclusion fold, including odd-width promotion
- tree-size, leaf-index, hash-length, and legacy proof-shape validation
- callback-based Signed Tree Head signature verification
- RFC 9162 Merkle tree hash, both recursive and stack forms
- RFC 9162 minimal inclusion paths and consistency proofs
- RFC 6962 v1 Merkle leaves, SCTs, digitally signed values, and tree-head signed input
- RFC 9162 v2 extensions and TransItem codes `0x0100` through `0x0106`
- restricted CT JSON for STH, inclusion, and consistency messages
- an in-memory log with monotonic timestamps and checkpoint export

## Proof formats

`verify_inclusion` is unchanged. For tree size 7 it expects the legacy height, `proof_height(7) == Some(3)`. The RFC 9162 path for index 6 in that tree has length 2, and the consistency proof from 4 to 7 has length 1. `proof_shape_valid` rejects that shorter path because the formats are not interchangeable.

Consistency generation and verification follow the RFC for `0 < first < second`. An empty path is rejected before the power-of-two prepend when the sizes differ. `first == second` is a practical boundary: the proof is empty and the roots must be equal. `first == 0` or `first > second` returns `BadIndex` and is not forced through the strict algorithm. The wire codec does not apply this size relation; verification does.

## Intentionally excluded

SHA-256, ECDSA/Ed25519, X.509/DER parsing, HTTP log clients, CT log servers, and key discovery remain outside MoonCT. Consistency proofs are now inside the library. Keeping the remaining boundaries explicit prevents the package from claiming cryptographic or transport behavior it does not implement.

## Implementation size

Physical lines below include blank lines. The count excludes `*_test.mbt`, `*_wbtest.mbt`, `cmd/`, generated `.mbti`, Markdown, and configuration files. It was taken with Python `splitlines` after `moon fmt`.

| File | Physical lines |
| --- | ---: |
| `bytesutil.mbt` | 322 |
| `error.mbt` | 46 |
| `jsonct.mbt` | 1003 |
| `logmem.mbt` | 363 |
| `merkle.mbt` | 528 |
| `moonct.mbt` | 254 |
| `rfc6962.mbt` | 652 |
| `rfc9162.mbt` | 844 |
| `tlsio.mbt` | 400 |
| Total | 4412 |

The total is 4412. The sources are protocol, codec, JSON, and log logic, not repeated placeholders.
