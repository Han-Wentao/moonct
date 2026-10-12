# Security policy

MoonCT checks proof structure and Merkle relations. It does not implement SHA-256 or signatures, and it does not parse certificates. Report suspected acceptance of an invalid inclusion or consistency proof, a codec that accepts a malformed artifact, or a trust-boundary or documentation error privately to the maintainer before public disclosure.

Do not send private keys or certificate material in an issue. Reproduction cases should use synthetic 32-byte hashes and a deterministic test hash whenever possible.
