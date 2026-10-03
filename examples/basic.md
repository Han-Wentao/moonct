# Basic adapter flow

The host computes a leaf hash with its vetted SHA-256 function, constructs an `InclusionProof`, and compares the derived root with a `TreeHead`. The package never opens a network connection or chooses a signature algorithm.
