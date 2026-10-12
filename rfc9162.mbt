///|
/// One RFC 9162 extension. Type 65535 is reserved and rejected.
pub struct CtExtension {
  type_code : Int
  data : Array[Int]
}

///|
/// RFC 9162 TimestampedCertificateEntryDataV2, shared by x509 and precert entries.
pub struct V2CertificateEntry {
  timestamp : UInt64
  issuer_key_hash : Hash
  tbs_certificate : Array[Int]
  extensions : Array[CtExtension]
}

///|
/// RFC 9162 SignedCertificateTimestampDataV2. The signature is not verified here.
pub struct V2SignedCertificateTimestamp {
  log_id : Array[Int]
  timestamp : UInt64
  extensions : Array[CtExtension]
  signature : Array[Int]
}

///|
/// RFC 9162 TreeHeadDataV2. It is nested inside a signed tree head, not a TransItem.
pub struct V2TreeHead {
  timestamp : UInt64
  tree_size : UInt64
  root_hash : Hash
  extensions : Array[CtExtension]
}

///|
pub struct V2SignedTreeHead {
  log_id : Array[Int]
  tree_head : V2TreeHead
  signature : Array[Int]
}

///|
pub struct V2ConsistencyProof {
  log_id : Array[Int]
  tree_size_1 : UInt64
  tree_size_2 : UInt64
  consistency_path : Array[Hash]
}

///|
pub struct V2InclusionProof {
  log_id : Array[Int]
  tree_size : UInt64
  leaf_index : UInt64
  inclusion_path : Array[Hash]
}

///|
/// RFC 9162 TransItem. The 16-bit code carries the version; there is no extra version byte.
pub enum TransItem {
  X509EntryV2(V2CertificateEntry)
  PrecertEntryV2(V2CertificateEntry)
  X509SctV2(V2SignedCertificateTimestamp)
  PrecertSctV2(V2SignedCertificateTimestamp)
  SignedTreeHeadV2(V2SignedTreeHead)
  ConsistencyProofV2(V2ConsistencyProof)
  InclusionProofV2(V2InclusionProof)
}

///|
fn inner_framing(err : CtError) -> CtError {
  match err {
    Truncated => CtError::BadLength
    other => other
  }
}

///|
pub fn trans_type_code(item : TransItem) -> Int {
  match item {
    X509EntryV2(_) => 0x0100
    PrecertEntryV2(_) => 0x0101
    X509SctV2(_) => 0x0102
    PrecertSctV2(_) => 0x0103
    SignedTreeHeadV2(_) => 0x0104
    ConsistencyProofV2(_) => 0x0105
    InclusionProofV2(_) => 0x0106
  }
}

///|
fn accept_trans_code(code : Int) -> Result[Int, CtError] {
  if code < 0 || code > ct_u16_max() {
    Err(CtError::Overflow)
  } else if code <= 0x00FF ||
    (code >= 0xE000 && code <= 0xEFFF) ||
    code >= 0xF000 {
    Err(CtError::Unsupported)
  } else {
    Ok(code)
  }
}

///|
fn check_extension_list(
  extensions : Array[CtExtension],
) -> Result[Unit, CtError] {
  let mut previous = -1
  let mut failed : CtError? = None
  let mut i = 0
  while i < extensions.length() && failed is None {
    let item = extensions[i]
    if !bytes_in_range(item.data) {
      failed = Some(CtError::BadByte)
    } else if item.data.length() > ct_u16_max() {
      failed = Some(CtError::BadLength)
    } else if item.type_code == 65535 {
      failed = Some(CtError::Unsupported)
    } else if item.type_code < 0 || item.type_code > ct_u16_max() {
      failed = Some(CtError::BadEnum(item.type_code))
    } else if previous == item.type_code {
      failed = Some(CtError::Duplicate)
    } else if previous > item.type_code {
      failed = Some(CtError::OutOfOrder)
    } else {
      previous = item.type_code
    }
    i = i + 1
  }
  match failed {
    Some(err) => Err(err)
    None => Ok(())
  }
}

///|
fn copy_extensions(extensions : Array[CtExtension]) -> Array[CtExtension] {
  let out = Array(capacity=extensions.length())
  for i in 0..<extensions.length() {
    let item = extensions[i]
    out.push({ type_code: item.type_code, data: bytes_copy(item.data), })
  }
  out
}

///|
fn copy_hashes(hashes : Array[Hash]) -> Array[Hash] {
  let out = Array(capacity=hashes.length())
  for i in 0..<hashes.length() {
    out.push(bytes_copy(hashes[i]))
  }
  out
}

///|
pub fn new_ct_extension(
  type_code : Int,
  data : Array[Int],
) -> Result[CtExtension, CtError] {
  let item = { type_code, data: bytes_copy(data), }
  let list = Array(capacity=1)
  list.push(item)
  match check_extension_list(list) {
    Err(err) => Err(err)
    Ok(_) => Ok(item)
  }
}

///|
fn check_node_hash(hash : Hash) -> Result[Hash, CtError] {
  if !bytes_in_range(hash) {
    Err(CtError::BadByte)
  } else if !is_valid_hash(hash) {
    Err(CtError::BadHash)
  } else {
    Ok(bytes_copy(hash))
  }
}

///|
fn check_hash_list(hashes : Array[Hash]) -> Result[Array[Hash], CtError] {
  let mut failed : CtError? = None
  let mut i = 0
  while i < hashes.length() && failed is None {
    match check_node_hash(hashes[i]) {
      Err(err) => failed = Some(err)
      Ok(_) => ()
    }
    i = i + 1
  }
  match failed {
    Some(err) => Err(err)
    None => Ok(copy_hashes(hashes))
  }
}

///|
fn check_v2_log_id(log_id : Array[Int]) -> Result[Array[Int], CtError] {
  if !bytes_in_range(log_id) {
    Err(CtError::BadByte)
  } else if log_id.length() < 2 || log_id.length() > 127 {
    Err(CtError::BadLength)
  } else {
    Ok(bytes_copy(log_id))
  }
}

///|
fn check_v2_signature(signature : Array[Int]) -> Result[Array[Int], CtError] {
  if !bytes_in_range(signature) {
    Err(CtError::BadByte)
  } else if signature.length() == 0 || signature.length() > ct_u16_max() {
    Err(CtError::BadLength)
  } else {
    Ok(bytes_copy(signature))
  }
}

///|
fn check_tbs(tbs : Array[Int]) -> Result[Array[Int], CtError] {
  if !bytes_in_range(tbs) {
    Err(CtError::BadByte)
  } else if tbs.length() == 0 || tbs.length() > ct_u24_max() {
    Err(CtError::BadLength)
  } else {
    Ok(bytes_copy(tbs))
  }
}

///|
pub fn new_v2_certificate_entry(
  timestamp : UInt64,
  issuer_key_hash : Hash,
  tbs_certificate : Array[Int],
  extensions : Array[CtExtension],
) -> Result[V2CertificateEntry, CtError] {
  match check_node_hash(issuer_key_hash) {
    Err(err) => Err(err)
    Ok(issuer) =>
      match check_tbs(tbs_certificate) {
        Err(err) => Err(err)
        Ok(tbs) =>
          match check_extension_list(extensions) {
            Err(err) => Err(err)
            Ok(_) =>
              Ok({
                timestamp,
                issuer_key_hash: issuer,
                tbs_certificate: tbs,
                extensions: copy_extensions(extensions),
              })
          }
      }
  }
}

///|
pub fn new_v2_sct(
  log_id : Array[Int],
  timestamp : UInt64,
  extensions : Array[CtExtension],
  signature : Array[Int],
) -> Result[V2SignedCertificateTimestamp, CtError] {
  match check_v2_log_id(log_id) {
    Err(err) => Err(err)
    Ok(id) =>
      match check_extension_list(extensions) {
        Err(err) => Err(err)
        Ok(_) =>
          match check_v2_signature(signature) {
            Err(err) => Err(err)
            Ok(sig) =>
              Ok({
                log_id: id,
                timestamp,
                extensions: copy_extensions(extensions),
                signature: sig,
              })
          }
      }
  }
}

///|
pub fn new_v2_tree_head(
  timestamp : UInt64,
  tree_size : UInt64,
  root_hash : Hash,
  extensions : Array[CtExtension],
) -> Result[V2TreeHead, CtError] {
  match check_node_hash(root_hash) {
    Err(err) => Err(err)
    Ok(root) =>
      match check_extension_list(extensions) {
        Err(err) => Err(err)
        Ok(_) =>
          Ok({
            timestamp,
            tree_size,
            root_hash: root,
            extensions: copy_extensions(extensions),
          })
      }
  }
}

///|
pub fn new_v2_signed_tree_head(
  log_id : Array[Int],
  tree_head : V2TreeHead,
  signature : Array[Int],
) -> Result[V2SignedTreeHead, CtError] {
  match
    new_v2_tree_head(
      tree_head.timestamp,
      tree_head.tree_size,
      tree_head.root_hash,
      tree_head.extensions,
    ) {
    Err(err) => Err(err)
    Ok(head) =>
      match check_v2_log_id(log_id) {
        Err(err) => Err(err)
        Ok(id) =>
          match check_v2_signature(signature) {
            Err(err) => Err(err)
            Ok(sig) => Ok({ log_id: id, tree_head: head, signature: sig, })
          }
      }
  }
}

///|
pub fn new_v2_consistency(
  log_id : Array[Int],
  tree_size_1 : UInt64,
  tree_size_2 : UInt64,
  consistency_path : Array[Hash],
) -> Result[V2ConsistencyProof, CtError] {
  match check_v2_log_id(log_id) {
    Err(err) => Err(err)
    Ok(id) =>
      match check_hash_list(consistency_path) {
        Err(err) => Err(err)
        Ok(path) =>
          Ok({ log_id: id, tree_size_1, tree_size_2, consistency_path: path, })
      }
  }
}

///|
pub fn new_v2_inclusion(
  log_id : Array[Int],
  tree_size : UInt64,
  leaf_index : UInt64,
  inclusion_path : Array[Hash],
) -> Result[V2InclusionProof, CtError] {
  match check_v2_log_id(log_id) {
    Err(err) => Err(err)
    Ok(id) =>
      match check_hash_list(inclusion_path) {
        Err(err) => Err(err)
        Ok(path) =>
          Ok({ log_id: id, tree_size, leaf_index, inclusion_path: path, })
      }
  }
}

///|
fn parse_extensions(body : Array[Int]) -> Result[Array[CtExtension], CtError] {
  let reader = new_byte_reader(body)
  let out = Array(capacity=4)
  let mut failed : CtError? = None
  while reader.remaining() > 0 && failed is None {
    match reader.read_u16() {
      Err(err) => failed = Some(inner_framing(err))
      Ok(type_code) =>
        match reader.read_opaque(2, 0, ct_u16_max()) {
          Err(err) => failed = Some(inner_framing(err))
          Ok(data) => out.push({ type_code, data, })
        }
    }
  }
  match failed {
    Some(err) => Err(err)
    None =>
      match check_extension_list(out) {
        Err(err) => Err(err)
        Ok(_) => Ok(out)
      }
  }
}

///|
fn parse_hash_vector(body : Array[Int]) -> Result[Array[Hash], CtError] {
  let reader = new_byte_reader(body)
  let out = Array(capacity=4)
  let mut failed : CtError? = None
  while reader.remaining() > 0 && failed is None {
    match reader.read_node_hash() {
      Err(err) => failed = Some(inner_framing(err))
      Ok(hash) => out.push(hash)
    }
  }
  match failed {
    Some(err) => Err(err)
    None => Ok(out)
  }
}

///|
fn ByteReader::read_node_hash(self : Self) -> Result[Hash, CtError] {
  match self.read_u8() {
    Err(err) => Err(err)
    Ok(length) =>
      if length != 32 {
        Err(CtError::BadHash)
      } else {
        self.read_bytes(32)
      }
  }
}

///|
fn ByteReader::read_extension_list(
  self : Self,
) -> Result[Array[CtExtension], CtError] {
  match self.read_opaque(2, 0, ct_u16_max()) {
    Err(err) => Err(err)
    Ok(body) => parse_extensions(body)
  }
}

///|
fn ByteReader::read_hash_vector(self : Self) -> Result[Array[Hash], CtError] {
  match self.read_opaque(2, 0, ct_u16_max()) {
    Err(err) => Err(err)
    Ok(body) => parse_hash_vector(body)
  }
}

///|
fn ByteReader::read_v2_log_id(self : Self) -> Result[Array[Int], CtError] {
  self.read_opaque(1, 2, 127)
}

///|
fn WriteGate::put_node_hash(self : Self, hash : Hash) -> Unit {
  match check_node_hash(hash) {
    Err(err) => self.note(Err(err))
    Ok(copy) => {
      self.put_u8(32)
      self.put_bytes(copy)
    }
  }
}

///|
fn WriteGate::put_extensions(
  self : Self,
  extensions : Array[CtExtension],
) -> Unit {
  match check_extension_list(extensions) {
    Err(err) => self.note(Err(err))
    Ok(_) => {
      let nested = new_write_gate()
      for i in 0..<extensions.length() {
        let item = extensions[i]
        nested.put_u16(item.type_code)
        nested.put_opaque(2, item.data, 0, ct_u16_max())
      }
      match nested.finish() {
        Err(err) => self.note(Err(err))
        Ok(body) => self.put_opaque(2, body, 0, ct_u16_max())
      }
    }
  }
}

///|
fn WriteGate::put_hash_vector(self : Self, hashes : Array[Hash]) -> Unit {
  match check_hash_list(hashes) {
    Err(err) => self.note(Err(err))
    Ok(copy) => {
      let nested = new_write_gate()
      for i in 0..<copy.length() {
        nested.put_node_hash(copy[i])
      }
      match nested.finish() {
        Err(err) => self.note(Err(err))
        Ok(body) => self.put_opaque(2, body, 0, ct_u16_max())
      }
    }
  }
}

///|
fn WriteGate::put_v2_log_id(self : Self, log_id : Array[Int]) -> Unit {
  self.put_opaque(1, log_id, 2, 127)
}

///|
fn WriteGate::put_v2_certificate_entry(
  self : Self,
  entry : V2CertificateEntry,
) -> Unit {
  self.put_u64(entry.timestamp)
  self.put_node_hash(entry.issuer_key_hash)
  self.put_opaque(3, entry.tbs_certificate, 1, ct_u24_max())
  self.put_extensions(entry.extensions)
}

///|
fn ByteReader::read_v2_certificate_entry(
  self : Self,
) -> Result[V2CertificateEntry, CtError] {
  match self.read_u64() {
    Err(err) => Err(err)
    Ok(timestamp) =>
      match self.read_node_hash() {
        Err(err) => Err(err)
        Ok(issuer_key_hash) =>
          match self.read_opaque(3, 1, ct_u24_max()) {
            Err(err) => Err(err)
            Ok(tbs_certificate) =>
              match self.read_extension_list() {
                Err(err) => Err(err)
                Ok(extensions) =>
                  Ok({
                    timestamp,
                    issuer_key_hash,
                    tbs_certificate,
                    extensions,
                  })
              }
          }
      }
  }
}

///|
fn WriteGate::put_v2_sct(
  self : Self,
  sct : V2SignedCertificateTimestamp,
) -> Unit {
  self.put_v2_log_id(sct.log_id)
  self.put_u64(sct.timestamp)
  self.put_extensions(sct.extensions)
  self.put_opaque(2, sct.signature, 1, ct_u16_max())
}

///|
fn ByteReader::read_v2_sct(
  self : Self,
) -> Result[V2SignedCertificateTimestamp, CtError] {
  match self.read_v2_log_id() {
    Err(err) => Err(err)
    Ok(log_id) =>
      match self.read_u64() {
        Err(err) => Err(err)
        Ok(timestamp) =>
          match self.read_extension_list() {
            Err(err) => Err(err)
            Ok(extensions) =>
              match self.read_opaque(2, 1, ct_u16_max()) {
                Err(err) => Err(err)
                Ok(signature) =>
                  Ok({ log_id, timestamp, extensions, signature, })
              }
          }
      }
  }
}

///|
fn WriteGate::put_v2_tree_head(self : Self, head : V2TreeHead) -> Unit {
  self.put_u64(head.timestamp)
  self.put_u64(head.tree_size)
  self.put_node_hash(head.root_hash)
  self.put_extensions(head.extensions)
}

///|
fn ByteReader::read_v2_tree_head(self : Self) -> Result[V2TreeHead, CtError] {
  match self.read_u64() {
    Err(err) => Err(err)
    Ok(timestamp) =>
      match self.read_u64() {
        Err(err) => Err(err)
        Ok(tree_size) =>
          match self.read_node_hash() {
            Err(err) => Err(err)
            Ok(root_hash) =>
              match self.read_extension_list() {
                Err(err) => Err(err)
                Ok(extensions) =>
                  Ok({ timestamp, tree_size, root_hash, extensions, })
              }
          }
      }
  }
}

///|
fn WriteGate::put_v2_signed_tree_head(
  self : Self,
  head : V2SignedTreeHead,
) -> Unit {
  self.put_v2_log_id(head.log_id)
  self.put_v2_tree_head(head.tree_head)
  self.put_opaque(2, head.signature, 1, ct_u16_max())
}

///|
fn ByteReader::read_v2_signed_tree_head(
  self : Self,
) -> Result[V2SignedTreeHead, CtError] {
  match self.read_v2_log_id() {
    Err(err) => Err(err)
    Ok(log_id) =>
      match self.read_v2_tree_head() {
        Err(err) => Err(err)
        Ok(tree_head) =>
          match self.read_opaque(2, 1, ct_u16_max()) {
            Err(err) => Err(err)
            Ok(signature) => Ok({ log_id, tree_head, signature, })
          }
      }
  }
}

///|
fn WriteGate::put_v2_consistency(
  self : Self,
  proof : V2ConsistencyProof,
) -> Unit {
  self.put_v2_log_id(proof.log_id)
  self.put_u64(proof.tree_size_1)
  self.put_u64(proof.tree_size_2)
  self.put_hash_vector(proof.consistency_path)
}

///|
fn ByteReader::read_v2_consistency(
  self : Self,
) -> Result[V2ConsistencyProof, CtError] {
  match self.read_v2_log_id() {
    Err(err) => Err(err)
    Ok(log_id) =>
      match self.read_u64() {
        Err(err) => Err(err)
        Ok(tree_size_1) =>
          match self.read_u64() {
            Err(err) => Err(err)
            Ok(tree_size_2) =>
              match self.read_hash_vector() {
                Err(err) => Err(err)
                Ok(consistency_path) =>
                  Ok({ log_id, tree_size_1, tree_size_2, consistency_path, })
              }
          }
      }
  }
}

///|
fn WriteGate::put_v2_inclusion(self : Self, proof : V2InclusionProof) -> Unit {
  self.put_v2_log_id(proof.log_id)
  self.put_u64(proof.tree_size)
  self.put_u64(proof.leaf_index)
  self.put_hash_vector(proof.inclusion_path)
}

///|
fn ByteReader::read_v2_inclusion(
  self : Self,
) -> Result[V2InclusionProof, CtError] {
  match self.read_v2_log_id() {
    Err(err) => Err(err)
    Ok(log_id) =>
      match self.read_u64() {
        Err(err) => Err(err)
        Ok(tree_size) =>
          match self.read_u64() {
            Err(err) => Err(err)
            Ok(leaf_index) =>
              match self.read_hash_vector() {
                Err(err) => Err(err)
                Ok(inclusion_path) =>
                  Ok({ log_id, tree_size, leaf_index, inclusion_path, })
              }
          }
      }
  }
}

///|
fn WriteGate::put_trans_item(self : Self, item : TransItem) -> Unit {
  self.put_u16(trans_type_code(item))
  match item {
    X509EntryV2(entry) => self.put_v2_certificate_entry(entry)
    PrecertEntryV2(entry) => self.put_v2_certificate_entry(entry)
    X509SctV2(sct) => self.put_v2_sct(sct)
    PrecertSctV2(sct) => self.put_v2_sct(sct)
    SignedTreeHeadV2(head) => self.put_v2_signed_tree_head(head)
    ConsistencyProofV2(proof) => self.put_v2_consistency(proof)
    InclusionProofV2(proof) => self.put_v2_inclusion(proof)
  }
}

///|
fn ByteReader::read_trans_body(
  self : Self,
  code : Int,
) -> Result[TransItem, CtError] {
  if code == 0x0100 {
    match self.read_v2_certificate_entry() {
      Err(err) => Err(err)
      Ok(entry) => Ok(TransItem::X509EntryV2(entry))
    }
  } else if code == 0x0101 {
    match self.read_v2_certificate_entry() {
      Err(err) => Err(err)
      Ok(entry) => Ok(TransItem::PrecertEntryV2(entry))
    }
  } else if code == 0x0102 {
    match self.read_v2_sct() {
      Err(err) => Err(err)
      Ok(sct) => Ok(TransItem::X509SctV2(sct))
    }
  } else if code == 0x0103 {
    match self.read_v2_sct() {
      Err(err) => Err(err)
      Ok(sct) => Ok(TransItem::PrecertSctV2(sct))
    }
  } else if code == 0x0104 {
    match self.read_v2_signed_tree_head() {
      Err(err) => Err(err)
      Ok(head) => Ok(TransItem::SignedTreeHeadV2(head))
    }
  } else if code == 0x0105 {
    match self.read_v2_consistency() {
      Err(err) => Err(err)
      Ok(proof) => Ok(TransItem::ConsistencyProofV2(proof))
    }
  } else if code == 0x0106 {
    match self.read_v2_inclusion() {
      Err(err) => Err(err)
      Ok(proof) => Ok(TransItem::InclusionProofV2(proof))
    }
  } else {
    Err(CtError::BadEnum(code))
  }
}

///|
fn ByteReader::read_trans_item(self : Self) -> Result[TransItem, CtError] {
  match self.read_u16() {
    Err(err) => Err(err)
    Ok(code) =>
      match accept_trans_code(code) {
        Err(err) => Err(err)
        Ok(accepted) => self.read_trans_body(accepted)
      }
  }
}

///|
pub fn encode_trans_item(item : TransItem) -> Result[Array[Int], CtError] {
  let gate = new_write_gate()
  gate.put_trans_item(item)
  gate.finish()
}

///|
pub fn decode_trans_item(bytes : Array[Int]) -> Result[TransItem, CtError] {
  let reader = new_byte_reader(bytes)
  match reader.read_trans_item() {
    Err(err) => Err(err)
    Ok(item) =>
      match reader.expect_exhausted() {
        Err(err) => Err(err)
        Ok(_) => Ok(item)
      }
  }
}

///|
pub fn inclusion_from_trans(
  item : TransItem,
) -> Result[MerkleInclusion, CtError] {
  match item {
    InclusionProofV2(proof) =>
      Ok({
        leaf_index: proof.leaf_index,
        tree_size: proof.tree_size,
        path: proof.inclusion_path,
      })
    _ => Err(CtError::Unsupported)
  }
}

///|
pub fn consistency_from_trans(
  item : TransItem,
) -> Result[MerkleConsistency, CtError] {
  match item {
    ConsistencyProofV2(proof) =>
      Ok({
        first_size: proof.tree_size_1,
        second_size: proof.tree_size_2,
        proof: proof.consistency_path,
      })
    _ => Err(CtError::Unsupported)
  }
}

///|
/// Verify a v2 inclusion TransItem with the RFC 9162 minimal path rules.
pub fn verify_trans_inclusion(
  sha256 : Sha256,
  leaf : Hash,
  item : TransItem,
  root : Hash,
) -> Result[Unit, CtError] {
  match inclusion_from_trans(item) {
    Err(err) => Err(err)
    Ok(proof) => require_merkle_inclusion(sha256, leaf, proof, root)
  }
}

///|
/// Verify a v2 consistency TransItem. Equal sizes still require an empty path.
pub fn verify_trans_consistency(
  sha256 : Sha256,
  first_hash : Hash,
  second_hash : Hash,
  item : TransItem,
) -> Result[Unit, CtError] {
  match consistency_from_trans(item) {
    Err(err) => Err(err)
    Ok(proof) => require_consistency(sha256, first_hash, second_hash, proof)
  }
}
