# Basic adapter flow

The host supplies its own SHA-256. Existing adapters can keep constructing an `InclusionProof` and calling `verify_inclusion`. RFC 9162 callers use `inclusion_path`, `verify_merkle_inclusion`, `consistency_proof`, and `verify_consistency` instead. On the seven-entry sample in `cmd/main`, the legacy height is 3, the minimal path for index 6 has length 2, and the consistency proof from 4 to 7 has length 1. The package never opens a network connection or selects a signature algorithm.
