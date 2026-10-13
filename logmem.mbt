///|
/// Checkpoint signed by a host. MoonCT does not verify the signature itself.
pub struct LogCheckpoint {
  timestamp : UInt64
  tree_size : UInt64
  root_hash : Hash
}

///|
/// In-memory RFC 6962 log. Entries are raw Merkle tree leaves, not parsed certificates.
pub struct MemoryLog {
  entries : Array[Array[Int32]]
  leaves : Array[Hash]
  mut latest_timestamp : UInt64
  mut saw_timestamp : Bool
}

///|
/// Create an empty log. Its root is the hash of the empty input.
pub fn new_memory_log() -> MemoryLog {
  {
    entries: Array(capacity=8),
    leaves: Array(capacity=8),
    latest_timestamp: 0UL,
    saw_timestamp: false,
  }
}

///|
/// Number of appended leaves.
pub fn MemoryLog::size(self : Self) -> UInt64 {
  self.entries.length().to_uint64()
}

///|
/// Timestamp of the newest leaf. An empty log has no timestamp.
pub fn MemoryLog::latest_time(self : Self) -> Result[UInt64, CtError] {
  if self.saw_timestamp {
    Ok(self.latest_timestamp)
  } else {
    Err(CtError::EmptyInput)
  }
}

///|
fn timestamp_in_order(
  log : MemoryLog,
  timestamp : UInt64,
) -> Result[Unit, CtError] {
  if log.saw_timestamp && timestamp <= log.latest_timestamp {
    Err(CtError::OutOfOrder)
  } else {
    Ok(())
  }
}

///|
fn MemoryLog::remember(
  self : Self,
  timestamp : UInt64,
  entry : Array[Int32],
  leaf : Hash,
) -> Unit {
  self.entries.push(entry)
  self.leaves.push(leaf)
  self.latest_timestamp = timestamp
  self.saw_timestamp = true
}

///|
/// Append one raw leaf. Timestamps must strictly increase. Empty leaf bytes are allowed.
pub fn MemoryLog::append(
  self : Self,
  sha256 : Sha256,
  timestamp : UInt64,
  entry : Array[Int32],
) -> Result[Unit, CtError] {
  match timestamp_in_order(self, timestamp) {
    Err(err) => Err(err)
    Ok(_) =>
      if !bytes_in_range(entry) {
        Err(CtError::BadByte)
      } else {
        let stored = bytes_copy(entry)
        match hash_leaf(sha256, stored) {
          Err(err) => Err(err)
          Ok(leaf) => {
            self.remember(timestamp, stored, bytes_copy(leaf))
            Ok(())
          }
        }
      }
  }
}

///|
/// Encode a v1 MerkleTreeLeaf and append it under the entry timestamp.
pub fn MemoryLog::append_v1_leaf(
  self : Self,
  sha256 : Sha256,
  entry : V1TimestampedEntry,
) -> Result[Unit, CtError] {
  match timestamp_in_order(self, entry.timestamp) {
    Err(err) => Err(err)
    Ok(_) =>
      match encode_v1_merkle_leaf(entry) {
        Err(err) => Err(err)
        Ok(bytes) => self.append(sha256, entry.timestamp, bytes)
      }
  }
}

///|
/// Copy one stored leaf. The index is a zero-based tree position.
pub fn MemoryLog::entry_at(
  self : Self,
  index : UInt64,
) -> Result[Array[Int32], CtError] {
  match u64_as_int(index) {
    Err(err) => Err(err)
    Ok(at) =>
      if at < 0 || at >= self.entries.length() {
        Err(CtError::BadIndex)
      } else {
        Ok(bytes_copy(self.entries[at]))
      }
  }
}

///|
fn leaves_match(log : MemoryLog, sha256 : Sha256) -> Result[Unit, CtError] {
  if log.entries.length() != log.leaves.length() {
    Err(CtError::BadProof)
  } else {
    let mut failed : CtError? = None
    for i in 0..<log.entries.length() {
      if failed is None {
        match hash_leaf(sha256, log.entries[i]) {
          Err(err) => failed = Some(err)
          Ok(hash) =>
            if !bytes_equal(hash, log.leaves[i]) {
              failed = Some(CtError::BadProof)
            }
        }
      }
    }
    match failed {
      Some(err) => Err(err)
      None => Ok(())
    }
  }
}

///|
fn roots_agree(
  sha256 : Sha256,
  entries : Array[Array[Int32]],
) -> Result[Hash, CtError] {
  match merkle_tree_hash(sha256, entries) {
    Err(err) => Err(err)
    Ok(recursive) =>
      match merkle_tree_hash_by_stack(sha256, entries) {
        Err(err) => Err(err)
        Ok(stacked) =>
          if bytes_equal(recursive, stacked) {
            Ok(recursive)
          } else {
            Err(CtError::BadProof)
          }
      }
  }
}

///|
/// Recompute the RFC 9162 root and require the recursive and stack forms to agree.
pub fn MemoryLog::root(self : Self, sha256 : Sha256) -> Result[Hash, CtError] {
  match leaves_match(self, sha256) {
    Err(err) => Err(err)
    Ok(_) => roots_agree(sha256, self.entries)
  }
}

///|
fn prefix_entries(
  log : MemoryLog,
  count : Int32,
) -> Result[Array[Array[Int32]], CtError] {
  if count < 0 || count > log.entries.length() {
    Err(CtError::BadIndex)
  } else {
    let out = Array(capacity=count)
    for i in 0..<count {
      out.push(bytes_copy(log.entries[i]))
    }
    Ok(out)
  }
}

///|
/// Root of the first `tree_size` leaves, checked with both Merkle algorithms.
pub fn MemoryLog::root_through(
  self : Self,
  sha256 : Sha256,
  tree_size : UInt64,
) -> Result[Hash, CtError] {
  if tree_size > self.size() {
    Err(CtError::BadIndex)
  } else {
    match u64_as_int(tree_size) {
      Err(err) => Err(err)
      Ok(count) =>
        match prefix_entries(self, count) {
          Err(err) => Err(err)
          Ok(entries) => roots_agree(sha256, entries)
        }
    }
  }
}

///|
/// Minimal RFC 9162 inclusion path for a stored leaf.
pub fn MemoryLog::inclusion(
  self : Self,
  sha256 : Sha256,
  index : UInt64,
) -> Result[MerkleInclusion, CtError] {
  inclusion_path(sha256, self.entries, index)
}

///|
/// RFC 9162 consistency proof from `first_size` to the current tree.
pub fn MemoryLog::consistency(
  self : Self,
  sha256 : Sha256,
  first_size : UInt64,
) -> Result[MerkleConsistency, CtError] {
  consistency_proof(sha256, self.entries, first_size)
}

///|
/// Check one stored leaf against the recomputed root.
pub fn MemoryLog::verify_leaf(
  self : Self,
  sha256 : Sha256,
  index : UInt64,
) -> Result[Unit, CtError] {
  match self.entry_at(index) {
    Err(err) => Err(err)
    Ok(entry) =>
      match hash_leaf(sha256, entry) {
        Err(err) => Err(err)
        Ok(leaf) =>
          match self.inclusion(sha256, index) {
            Err(err) => Err(err)
            Ok(proof) =>
              match self.root(sha256) {
                Err(err) => Err(err)
                Ok(root) => require_merkle_inclusion(sha256, leaf, proof, root)
              }
          }
      }
  }
}

///|
/// Check that `first_hash` is a prefix of the current log.
pub fn MemoryLog::verify_prefix(
  self : Self,
  sha256 : Sha256,
  first_size : UInt64,
  first_hash : Hash,
) -> Result[Unit, CtError] {
  match self.consistency(sha256, first_size) {
    Err(err) => Err(err)
    Ok(proof) =>
      match self.root(sha256) {
        Err(err) => Err(err)
        Ok(second_hash) =>
          require_consistency(sha256, first_hash, second_hash, proof)
      }
  }
}

///|
/// Audit every stored leaf, then return the agreed root.
pub fn MemoryLog::audit(self : Self, sha256 : Sha256) -> Result[Hash, CtError] {
  match self.root(sha256) {
    Err(err) => Err(err)
    Ok(root) => {
      let mut failed : CtError? = None
      let mut i = 0
      while i < self.entries.length() && failed is None {
        match self.verify_leaf(sha256, i.to_uint64()) {
          Err(err) => failed = Some(err)
          Ok(_) => ()
        }
        i = i + 1
      }
      match failed {
        Some(err) => Err(err)
        None => Ok(root)
      }
    }
  }
}

///|
/// Build a checkpoint. Its timestamp may equal, but not precede, the latest leaf.
pub fn MemoryLog::checkpoint(
  self : Self,
  sha256 : Sha256,
  timestamp : UInt64,
) -> Result[LogCheckpoint, CtError] {
  if self.saw_timestamp && timestamp < self.latest_timestamp {
    Err(CtError::OutOfOrder)
  } else {
    match self.root(sha256) {
      Err(err) => Err(err)
      Ok(root_hash) => Ok({ timestamp, tree_size: self.size(), root_hash, })
    }
  }
}

///|
/// Encode a checkpoint as an RFC 6962 get-sth JSON object.
pub fn encode_checkpoint_sth(
  checkpoint : LogCheckpoint,
  signature : Array[Int32],
) -> Result[String, CtError] {
  if !bytes_in_range(checkpoint.root_hash) {
    Err(CtError::BadByte)
  } else if !is_valid_hash(checkpoint.root_hash) {
    Err(CtError::BadHash)
  } else if !bytes_in_range(signature) {
    Err(CtError::BadByte)
  } else if signature.length() == 0 {
    Err(CtError::EmptyInput)
  } else {
    encode_sth_message({
      tree_size: checkpoint.tree_size,
      timestamp: checkpoint.timestamp,
      sha256_root_hash: bytes_copy(checkpoint.root_hash),
      tree_head_signature: bytes_copy(signature),
    })
  }
}

///|
/// Encode an inclusion proof as the RFC 6962 get-proof-by-hash JSON object.
pub fn encode_log_inclusion(proof : MerkleInclusion) -> Result[String, CtError] {
  encode_inclusion_message({
    leaf_index: proof.leaf_index,
    audit_path: copy_hashes(proof.path),
  })
}

///|
/// Encode a consistency proof as the RFC 6962 get-sth-consistency JSON object.
pub fn encode_log_consistency(
  proof : MerkleConsistency,
) -> Result[String, CtError] {
  encode_consistency_message({ consistency: copy_hashes(proof.proof), })
}
