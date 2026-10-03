///| A compact, dependency-free Certificate Transparency Merkle proof core.

///|
/// The caller supplies SHA-256 and signature verification so this package can
/// remain runtime-agnostic and reuse the platform's cryptographic primitives.
pub type Hash = Array[Int]

///|
/// A signed tree head's public fields.
pub struct TreeHead {
  version : UInt
  timestamp : UInt
  tree_size : UInt
  root_hash : Hash
}

///|
/// An inclusion proof for a leaf.
pub struct InclusionProof {
  leaf_index : UInt
  tree_size : UInt
  audit_path : Array[Hash]
}

///|
fn valid_hash(hash : Hash) -> Bool {
  hash.length() == 32
}

///|
fn same_hash(left : Hash, right : Hash) -> Bool {
  if left.length() != right.length() {
    false
  } else {
    let mut equal = true
    for i = 0; i < left.length(); i = i + 1 {
      if left[i] != right[i] {
        equal = false
      }
    }
    equal
  }
}

///|
fn prefixed(prefix : Int, payload : Array[Int]) -> Array[Int] {
  let result : Array[Int] = Array::make(payload.length() + 1, 0)
  result[0] = prefix
  for i = 0; i < payload.length(); i = i + 1 {
    result[i + 1] = payload[i]
  }
  result
}

///|
fn joined(left : Hash, right : Hash) -> Array[Int] {
  let result : Array[Int] = Array::make(65, 0)
  result[0] = 1
  for i = 0; i < 32; i = i + 1 {
    result[i + 1] = left[i]
    result[i + 33] = right[i]
  }
  result
}

///|
/// Compute the RFC 6962 leaf hash. The supplied function should be SHA-256.
pub fn leaf_hash(sha256 : (Array[Int]) -> Hash, leaf : Array[Int]) -> Hash? {
  let result = sha256(prefixed(0, leaf))
  if valid_hash(result) {
    Some(result)
  } else {
    None
  }
}

///|
/// Compute the RFC 6962 internal-node hash.
pub fn node_hash(
  sha256 : (Array[Int]) -> Hash,
  left : Hash,
  right : Hash,
) -> Hash? {
  if !valid_hash(left) || !valid_hash(right) {
    None
  } else {
    let result = sha256(joined(left, right))
    if valid_hash(result) {
      Some(result)
    } else {
      None
    }
  }
}

///|
/// Calculate the root implied by an inclusion proof.
pub fn inclusion_root(
  sha256 : (Array[Int]) -> Hash,
  leaf : Hash,
  proof : InclusionProof,
) -> Hash? {
  if !valid_hash(leaf) ||
    proof.tree_size == 0U ||
    proof.leaf_index >= proof.tree_size {
    None
  } else {
    let mut node = leaf
    let mut index = proof.leaf_index
    let mut width = proof.tree_size
    let mut path_index = 0
    let mut valid = true
    while width > 1U && valid {
      if path_index >= proof.audit_path.length() {
        valid = false
      } else {
        let sibling = proof.audit_path[path_index]
        if !valid_hash(sibling) {
          valid = false
        } else {
          let next = if index % 2U == 1U || index == width - 1U {
            node_hash(sha256, sibling, node)
          } else {
            node_hash(sha256, node, sibling)
          }
          match next {
            Some(value) => node = value
            None => valid = false
          }
          index = index / 2U
          width = (width + 1U) / 2U
          path_index = path_index + 1
        }
      }
    }
    if valid && path_index == proof.audit_path.length() {
      Some(node)
    } else {
      None
    }
  }
}

///|
/// Verify an inclusion proof against a tree head.
pub fn verify_inclusion(
  sha256 : (Array[Int]) -> Hash,
  leaf : Hash,
  proof : InclusionProof,
  head : TreeHead,
) -> Bool {
  if proof.tree_size != head.tree_size || !valid_hash(head.root_hash) {
    false
  } else {
    match inclusion_root(sha256, leaf, proof) {
      Some(root) => same_hash(root, head.root_hash)
      None => false
    }
  }
}

///|
/// Verify the signed tree head using a host-provided signature verifier.
pub fn verify_tree_head(
  head : TreeHead,
  signature : Array[Int],
  signed_bytes : Array[Int],
  public_key : Array[Int],
  verify_signature : (Array[Int], Array[Int], Array[Int]) -> Bool,
) -> Bool {
  head.version == 0U &&
  head.tree_size > 0U &&
  valid_hash(head.root_hash) &&
  signature.length() > 0 &&
  public_key.length() > 0 &&
  verify_signature(public_key, signed_bytes, signature)
}

///|
/// Return the height of the proof tree for a non-empty tree.
pub fn proof_height(tree_size : UInt) -> UInt? {
  if tree_size == 0U {
    None
  } else {
    let mut width = tree_size
    let mut height = 0U
    while width > 1U {
      width = (width + 1U) / 2U
      height = height + 1U
    }
    Some(height)
  }
}

///|
/// Construct a tree head value.
pub fn new_tree_head(
  version : UInt,
  timestamp : UInt,
  tree_size : UInt,
  root_hash : Hash,
) -> TreeHead {
  { version, timestamp, tree_size, root_hash, }
}

///|
/// Construct an inclusion proof.
pub fn new_inclusion_proof(
  leaf_index : UInt,
  tree_size : UInt,
  audit_path : Array[Hash],
) -> InclusionProof {
  { leaf_index, tree_size, audit_path, }
}
