///|
/// Caller-supplied SHA-256. MoonCT never implements the hash itself.
pub type Sha256 = (Array[Int32]) -> Hash

///|
/// RFC 9162 minimal inclusion path. This is not the legacy level-fold proof.
pub struct MerkleInclusion {
  leaf_index : UInt64
  tree_size : UInt64
  path : Array[Hash]
}

///|
/// RFC 9162 consistency proof between two prefixes of one entry list.
pub struct MerkleConsistency {
  first_size : UInt64
  second_size : UInt64
  proof : Array[Hash]
}

///|
fn u64_as_int(value : UInt64) -> Result[Int32, CtError] {
  if value > 2147483647UL {
    Err(CtError::Overflow)
  } else {
    Ok(value.to_int())
  }
}

///|
fn require_hash(hash : Hash) -> Result[Hash, CtError] {
  if is_valid_hash(hash) {
    Ok(hash)
  } else {
    Err(CtError::BadHash)
  }
}

///|
/// Largest power of two strictly smaller than `n`. `n` must be greater than 1.
fn largest_power_below(n : UInt64) -> UInt64 {
  let mut k = 1UL
  let mut growing = true
  while growing {
    let next = k << 1
    if next == 0UL || next >= n {
      growing = false
    } else {
      k = next
    }
  }
  k
}

///|
/// HASH of the empty input, which is the root of an empty Merkle tree.
pub fn empty_tree_hash(sha256 : Sha256) -> Result[Hash, CtError] {
  require_hash(sha256([]))
}

///|
fn hash_leaf(sha256 : Sha256, entry : Array[Int32]) -> Result[Hash, CtError] {
  match leaf_hash(sha256, entry) {
    Some(hash) => Ok(hash)
    None => Err(CtError::BadHash)
  }
}

///|
fn hash_node(
  sha256 : Sha256,
  left : Hash,
  right : Hash,
) -> Result[Hash, CtError] {
  match node_hash(sha256, left, right) {
    Some(hash) => Ok(hash)
    None => Err(CtError::BadHash)
  }
}

///|
fn hash_range(
  sha256 : Sha256,
  entries : Array[Array[Int32]],
  start : Int32,
  end : Int32,
) -> Result[Hash, CtError] {
  let count = end - start
  if count < 0 || start < 0 || end > entries.length() {
    Err(CtError::BadIndex)
  } else if count == 0 {
    empty_tree_hash(sha256)
  } else if count == 1 {
    hash_leaf(sha256, entries[start])
  } else {
    let k = largest_power_below(count.to_uint64()).to_int()
    match hash_range(sha256, entries, start, start + k) {
      Err(err) => Err(err)
      Ok(left) =>
        match hash_range(sha256, entries, start + k, end) {
          Err(err) => Err(err)
          Ok(right) => hash_node(sha256, left, right)
        }
    }
  }
}

///|
/// RFC 9162 Merkle Tree Hash of raw log entries.
pub fn merkle_tree_hash(
  sha256 : Sha256,
  entries : Array[Array[Int32]],
) -> Result[Hash, CtError] {
  hash_range(sha256, entries, 0, entries.length())
}

///|
fn trailing_ones(index : Int32) -> Int32 {
  let mut count = 0
  let mut value = index
  while value % 2 == 1 {
    count = count + 1
    value = value / 2
  }
  count
}

///|
fn pop_hash(stack : Array[Hash]) -> Result[Hash, CtError] {
  match stack.pop() {
    Some(hash) => Ok(hash)
    None => Err(CtError::BadProof)
  }
}

///|
fn merge_top(sha256 : Sha256, stack : Array[Hash]) -> Result[Unit, CtError] {
  match pop_hash(stack) {
    Err(err) => Err(err)
    Ok(right) =>
      match pop_hash(stack) {
        Err(err) => Err(err)
        Ok(left) =>
          match hash_node(sha256, left, right) {
            Err(err) => Err(err)
            Ok(parent) => {
              stack.push(parent)
              Ok(())
            }
          }
      }
  }
}

///|
/// Iterative RFC 9162 tree hash. It must agree with `merkle_tree_hash`.
pub fn merkle_tree_hash_by_stack(
  sha256 : Sha256,
  entries : Array[Array[Int32]],
) -> Result[Hash, CtError] {
  if entries.length() == 0 {
    empty_tree_hash(sha256)
  } else {
    let stack = Array(capacity=entries.length())
    let mut failed : CtError? = None
    for i in 0..<entries.length() {
      if failed is None {
        match hash_leaf(sha256, entries[i]) {
          Err(err) => failed = Some(err)
          Ok(hash) => {
            stack.push(hash)
            let merges = trailing_ones(i)
            let mut step = 0
            while step < merges && failed is None {
              match merge_top(sha256, stack) {
                Err(err) => failed = Some(err)
                Ok(_) => ()
              }
              step = step + 1
            }
          }
        }
      }
    }
    while stack.length() > 1 && failed is None {
      match merge_top(sha256, stack) {
        Err(err) => failed = Some(err)
        Ok(_) => ()
      }
    }
    match failed {
      Some(err) => Err(err)
      None =>
        if stack.length() == 1 && is_valid_hash(stack[0]) {
          Ok(stack[0])
        } else {
          Err(CtError::BadHash)
        }
    }
  }
}

///|
fn path_range(
  sha256 : Sha256,
  entries : Array[Array[Int32]],
  start : Int32,
  end : Int32,
  index : Int32,
) -> Result[Array[Hash], CtError] {
  let count = end - start
  if count <= 0 || index < 0 || index >= count {
    Err(CtError::BadIndex)
  } else if count == 1 {
    Ok(Array(capacity=0))
  } else {
    let k = largest_power_below(count.to_uint64()).to_int()
    if index < k {
      match path_range(sha256, entries, start, start + k, index) {
        Err(err) => Err(err)
        Ok(prefix) =>
          match hash_range(sha256, entries, start + k, end) {
            Err(err) => Err(err)
            Ok(sibling) => {
              prefix.push(sibling)
              Ok(prefix)
            }
          }
      }
    } else {
      match path_range(sha256, entries, start + k, end, index - k) {
        Err(err) => Err(err)
        Ok(prefix) =>
          match hash_range(sha256, entries, start, start + k) {
            Err(err) => Err(err)
            Ok(sibling) => {
              prefix.push(sibling)
              Ok(prefix)
            }
          }
      }
    }
  }
}

///|
/// Build the minimal RFC 9162 inclusion path for one raw entry.
pub fn inclusion_path(
  sha256 : Sha256,
  entries : Array[Array[Int32]],
  index : UInt64,
) -> Result[MerkleInclusion, CtError] {
  let tree_size = entries.length().to_uint64()
  if tree_size == 0UL || index >= tree_size {
    Err(CtError::BadIndex)
  } else {
    match u64_as_int(index) {
      Err(err) => Err(err)
      Ok(index_at) =>
        match path_range(sha256, entries, 0, entries.length(), index_at) {
          Err(err) => Err(err)
          Ok(path) => Ok({ leaf_index: index, tree_size, path, })
        }
    }
  }
}

///|
fn hashes_valid(path : Array[Hash]) -> Bool {
  let mut valid = true
  let mut i = 0
  while i < path.length() && valid {
    if !is_valid_hash(path[i]) {
      valid = false
    }
    i = i + 1
  }
  valid
}

///|
/// Verify an RFC 9162 inclusion path, including the extra shift from section 2.1.3.2.
pub fn verify_merkle_inclusion(
  sha256 : Sha256,
  leaf : Hash,
  proof : MerkleInclusion,
  root : Hash,
) -> Bool {
  if !is_valid_hash(leaf) || !is_valid_hash(root) || !hashes_valid(proof.path) {
    false
  } else if proof.tree_size == 0UL || proof.leaf_index >= proof.tree_size {
    false
  } else {
    let mut fn_ = proof.leaf_index
    let mut sn = proof.tree_size - 1UL
    let mut rolling = leaf
    let mut valid = true
    let mut i = 0
    while i < proof.path.length() && valid {
      let sibling = proof.path[i]
      if sn == 0UL {
        valid = false
      } else if (fn_ & 1UL) == 1UL || fn_ == sn {
        match hash_node(sha256, sibling, rolling) {
          Err(_) => valid = false
          Ok(next) => rolling = next
        }
        if valid && (fn_ & 1UL) == 0UL {
          while (fn_ & 1UL) == 0UL && fn_ != 0UL && valid {
            fn_ = fn_ >> 1
            sn = sn >> 1
          }
        }
      } else {
        match hash_node(sha256, rolling, sibling) {
          Err(_) => valid = false
          Ok(next) => rolling = next
        }
      }
      if valid {
        fn_ = fn_ >> 1
        sn = sn >> 1
        i = i + 1
      }
    }
    valid && i == proof.path.length() && sn == 0UL && same_hash(rolling, root)
  }
}

///|
pub fn require_merkle_inclusion(
  sha256 : Sha256,
  leaf : Hash,
  proof : MerkleInclusion,
  root : Hash,
) -> Result[Unit, CtError] {
  if verify_merkle_inclusion(sha256, leaf, proof, root) {
    Ok(())
  } else {
    Err(CtError::BadProof)
  }
}

///|
fn subproof(
  sha256 : Sha256,
  entries : Array[Array[Int32]],
  start : Int32,
  end : Int32,
  count : Int32,
  known : Bool,
) -> Result[Array[Hash], CtError] {
  let width = end - start
  if count <= 0 || count > width || start < 0 || end > entries.length() {
    Err(CtError::BadIndex)
  } else if count == width {
    if known {
      Ok(Array(capacity=0))
    } else {
      match hash_range(sha256, entries, start, end) {
        Err(err) => Err(err)
        Ok(hash) => Ok([hash])
      }
    }
  } else {
    let k = largest_power_below(width.to_uint64()).to_int()
    if count <= k {
      match subproof(sha256, entries, start, start + k, count, known) {
        Err(err) => Err(err)
        Ok(prefix) =>
          match hash_range(sha256, entries, start + k, end) {
            Err(err) => Err(err)
            Ok(sibling) => {
              prefix.push(sibling)
              Ok(prefix)
            }
          }
      }
    } else {
      match subproof(sha256, entries, start + k, end, count - k, false) {
        Err(err) => Err(err)
        Ok(prefix) =>
          match hash_range(sha256, entries, start, start + k) {
            Err(err) => Err(err)
            Ok(sibling) => {
              prefix.push(sibling)
              Ok(prefix)
            }
          }
      }
    }
  }
}

///|
/// Build an RFC 9162 consistency proof for the prefix of length `first_size`.
/// Equal sizes return an empty proof. The RFC algorithm itself covers only a
/// strict prefix.
pub fn consistency_proof(
  sha256 : Sha256,
  entries : Array[Array[Int32]],
  first_size : UInt64,
) -> Result[MerkleConsistency, CtError] {
  let second_size = entries.length().to_uint64()
  if first_size == 0UL || first_size > second_size {
    Err(CtError::BadIndex)
  } else if first_size == second_size {
    Ok({ first_size, second_size, proof: Array(capacity=0), })
  } else {
    match u64_as_int(first_size) {
      Err(err) => Err(err)
      Ok(count) =>
        match subproof(sha256, entries, 0, entries.length(), count, true) {
          Err(err) => Err(err)
          Ok(proof) => Ok({ first_size, second_size, proof, })
        }
    }
  }
}

///|
/// `first` is an exact power of two when it is nonzero and has one bit set.
pub fn is_power_of_two_u64(value : UInt64) -> Bool {
  value != 0UL && (value & (value - 1UL)) == 0UL
}

///|
fn copy_proof(first : Hash, proof : Array[Hash], prepend : Bool) -> Array[Hash] {
  let out = Array(capacity=proof.length() + 1)
  if prepend {
    out.push(first)
  }
  for i in 0..<proof.length() {
    out.push(proof[i])
  }
  out
}

///|
/// Verify RFC 9162 consistency. Equal sizes are accepted only with an empty proof.
pub fn verify_consistency(
  sha256 : Sha256,
  first_hash : Hash,
  second_hash : Hash,
  proof : MerkleConsistency,
) -> Bool {
  if !is_valid_hash(first_hash) ||
    !is_valid_hash(second_hash) ||
    !hashes_valid(proof.proof) {
    false
  } else if proof.first_size == 0UL || proof.first_size > proof.second_size {
    false
  } else if proof.first_size == proof.second_size {
    proof.proof.length() == 0 && same_hash(first_hash, second_hash)
  } else if proof.proof.length() == 0 {
    false
  } else {
    let nodes = copy_proof(
      first_hash,
      proof.proof,
      is_power_of_two_u64(proof.first_size),
    )
    let mut fn_ = proof.first_size - 1UL
    let mut sn = proof.second_size - 1UL
    if (fn_ & 1UL) == 1UL {
      while (fn_ & 1UL) == 1UL {
        fn_ = fn_ >> 1
        sn = sn >> 1
      }
    }
    let mut fr = nodes[0]
    let mut sr = nodes[0]
    let mut valid = true
    let mut i = 1
    while i < nodes.length() && valid {
      let sibling = nodes[i]
      if sn == 0UL {
        valid = false
      } else if (fn_ & 1UL) == 1UL || fn_ == sn {
        match hash_node(sha256, sibling, fr) {
          Err(_) => valid = false
          Ok(next) => fr = next
        }
        if valid {
          match hash_node(sha256, sibling, sr) {
            Err(_) => valid = false
            Ok(next) => sr = next
          }
        }
        if valid && (fn_ & 1UL) == 0UL {
          while (fn_ & 1UL) == 0UL && fn_ != 0UL {
            fn_ = fn_ >> 1
            sn = sn >> 1
          }
        }
      } else {
        match hash_node(sha256, sr, sibling) {
          Err(_) => valid = false
          Ok(next) => sr = next
        }
      }
      if valid {
        fn_ = fn_ >> 1
        sn = sn >> 1
        i = i + 1
      }
    }
    valid &&
    i == nodes.length() &&
    sn == 0UL &&
    same_hash(fr, first_hash) &&
    same_hash(sr, second_hash)
  }
}

///|
pub fn require_consistency(
  sha256 : Sha256,
  first_hash : Hash,
  second_hash : Hash,
  proof : MerkleConsistency,
) -> Result[Unit, CtError] {
  if verify_consistency(sha256, first_hash, second_hash, proof) {
    Ok(())
  } else {
    Err(CtError::BadProof)
  }
}
