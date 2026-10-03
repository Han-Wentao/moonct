# MoonCT 0.1.0

MoonCT 0.1.0 is the first reusable MoonBit Certificate Transparency proof core. It verifies RFC 6962 inclusion paths against a supplied tree head, validates proof shape before hashing, and delegates cryptographic primitives to the host.

Validation performed for this release: 14 MoonBit tests pass, `moon check --deny-warn` passes, formatting passes, and the runnable command example reports a bounded proof height.
