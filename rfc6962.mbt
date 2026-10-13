///|
/// RFC 6962 HashAlgorithm. Names avoid `None` and the injected `Sha256` alias.
pub enum HashAlgorithm {
  HashNone
  Md5
  Sha1
  Sha224
  Sha256Alg
  Sha384
  Sha512
}

///|
/// RFC 6962 SignatureAlgorithm.
pub enum SignatureAlgorithm {
  Anonymous
  Rsa
  Dsa
  Ecdsa
}

///|
/// Certificate or precertificate body carried by a v1 timestamped entry.
pub enum V1LeafBody {
  X509Body(Array[Int32])
  PrecertBody(Array[Int32], Array[Int32])
}

///|
/// RFC 6962 DigitallySigned. The signature bytes are opaque to MoonCT.
pub struct DigitallySigned {
  hash_algorithm : HashAlgorithm
  signature_algorithm : SignatureAlgorithm
  signature : Array[Int32]
}

///|
/// RFC 6962 TimestampedEntry. Extensions are raw bytes, not the v2 type vector.
pub struct V1TimestampedEntry {
  timestamp : UInt64
  body : V1LeafBody
  extensions : Array[Int32]
}

///|
/// RFC 6962 MerkleTreeLeaf. Version and leaf type are fixed to v1/timestamped_entry.
pub struct V1MerkleTreeLeaf {
  entry : V1TimestampedEntry
}

///|
/// RFC 6962 SignedCertificateTimestamp without the signed certificate bytes.
pub struct V1SignedCertificateTimestamp {
  log_id : Array[Int32]
  timestamp : UInt64
  extensions : Array[Int32]
  signature : DigitallySigned
}

///|
/// Fields covered by a v1 tree-head signature, excluding the signature itself.
pub struct V1TreeHeadSigned {
  timestamp : UInt64
  tree_size : UInt64
  root_hash : Hash
}

///|
pub fn hash_algorithm_code(algorithm : HashAlgorithm) -> Int32 {
  match algorithm {
    HashNone => 0
    Md5 => 1
    Sha1 => 2
    Sha224 => 3
    Sha256Alg => 4
    Sha384 => 5
    Sha512 => 6
  }
}

///|
/// Map a wire byte to a hash algorithm. Unknown codes are `BadEnum`.
pub fn hash_algorithm_from_code(code : Int32) -> Result[HashAlgorithm, CtError] {
  if code == 0 {
    Ok(HashAlgorithm::HashNone)
  } else if code == 1 {
    Ok(HashAlgorithm::Md5)
  } else if code == 2 {
    Ok(HashAlgorithm::Sha1)
  } else if code == 3 {
    Ok(HashAlgorithm::Sha224)
  } else if code == 4 {
    Ok(HashAlgorithm::Sha256Alg)
  } else if code == 5 {
    Ok(HashAlgorithm::Sha384)
  } else if code == 6 {
    Ok(HashAlgorithm::Sha512)
  } else {
    Err(CtError::BadEnum(code))
  }
}

///|
pub fn signature_algorithm_code(algorithm : SignatureAlgorithm) -> Int32 {
  match algorithm {
    Anonymous => 0
    Rsa => 1
    Dsa => 2
    Ecdsa => 3
  }
}

///|
pub fn signature_algorithm_from_code(
  code : Int32,
) -> Result[SignatureAlgorithm, CtError] {
  if code == 0 {
    Ok(SignatureAlgorithm::Anonymous)
  } else if code == 1 {
    Ok(SignatureAlgorithm::Rsa)
  } else if code == 2 {
    Ok(SignatureAlgorithm::Dsa)
  } else if code == 3 {
    Ok(SignatureAlgorithm::Ecdsa)
  } else {
    Err(CtError::BadEnum(code))
  }
}

///|
fn validate_v1_body(body : V1LeafBody) -> Result[Unit, CtError] {
  match body {
    X509Body(certificate) =>
      if !bytes_in_range(certificate) {
        Err(CtError::BadByte)
      } else if certificate.length() == 0 || certificate.length() > ct_u24_max() {
        Err(CtError::BadLength)
      } else {
        Ok(())
      }
    PrecertBody(issuer, tbs) =>
      if !bytes_in_range(issuer) || !bytes_in_range(tbs) {
        Err(CtError::BadByte)
      } else if issuer.length() != 32 {
        Err(CtError::BadHash)
      } else if tbs.length() == 0 || tbs.length() > ct_u24_max() {
        Err(CtError::BadLength)
      } else {
        Ok(())
      }
  }
}

///|
pub fn v1_x509_body(certificate : Array[Int32]) -> Result[V1LeafBody, CtError] {
  let body = V1LeafBody::X509Body(bytes_copy(certificate))
  match validate_v1_body(body) {
    Err(err) => Err(err)
    Ok(_) => Ok(body)
  }
}

///|
pub fn v1_precert_body(
  issuer_key_hash : Array[Int32],
  tbs_certificate : Array[Int32],
) -> Result[V1LeafBody, CtError] {
  let body = V1LeafBody::PrecertBody(
    bytes_copy(issuer_key_hash),
    bytes_copy(tbs_certificate),
  )
  match validate_v1_body(body) {
    Err(err) => Err(err)
    Ok(_) => Ok(body)
  }
}

///|
fn copy_v1_body(body : V1LeafBody) -> V1LeafBody {
  match body {
    X509Body(certificate) => V1LeafBody::X509Body(bytes_copy(certificate))
    PrecertBody(issuer, tbs) =>
      V1LeafBody::PrecertBody(bytes_copy(issuer), bytes_copy(tbs))
  }
}

///|
pub fn new_digitally_signed(
  hash_algorithm : HashAlgorithm,
  signature_algorithm : SignatureAlgorithm,
  signature : Array[Int32],
) -> Result[DigitallySigned, CtError] {
  if !bytes_in_range(signature) {
    Err(CtError::BadByte)
  } else if signature.length() > ct_u16_max() {
    Err(CtError::BadLength)
  } else {
    Ok({
      hash_algorithm,
      signature_algorithm,
      signature: bytes_copy(signature),
    })
  }
}

///|
pub fn new_v1_timestamped_entry(
  timestamp : UInt64,
  body : V1LeafBody,
  extensions : Array[Int32],
) -> Result[V1TimestampedEntry, CtError] {
  if !bytes_in_range(extensions) {
    Err(CtError::BadByte)
  } else if extensions.length() > ct_u16_max() {
    Err(CtError::BadLength)
  } else {
    match validate_v1_body(body) {
      Err(err) => Err(err)
      Ok(_) =>
        Ok({
          timestamp,
          body: copy_v1_body(body),
          extensions: bytes_copy(extensions),
        })
    }
  }
}

///|
fn validate_v1_log_id(log_id : Array[Int32]) -> Result[Unit, CtError] {
  if !bytes_in_range(log_id) {
    Err(CtError::BadByte)
  } else if log_id.length() != 32 {
    Err(CtError::BadHash)
  } else {
    Ok(())
  }
}

///|
pub fn new_v1_sct(
  log_id : Array[Int32],
  timestamp : UInt64,
  extensions : Array[Int32],
  signature : DigitallySigned,
) -> Result[V1SignedCertificateTimestamp, CtError] {
  match validate_v1_log_id(log_id) {
    Err(err) => Err(err)
    Ok(_) =>
      if !bytes_in_range(extensions) || !bytes_in_range(signature.signature) {
        Err(CtError::BadByte)
      } else if extensions.length() > ct_u16_max() ||
        signature.signature.length() > ct_u16_max() {
        Err(CtError::BadLength)
      } else {
        Ok({
          log_id: bytes_copy(log_id),
          timestamp,
          extensions: bytes_copy(extensions),
          signature: {
            hash_algorithm: signature.hash_algorithm,
            signature_algorithm: signature.signature_algorithm,
            signature: bytes_copy(signature.signature),
          },
        })
      }
  }
}

///|
fn WriteGate::put_digitally_signed(
  self : Self,
  value : DigitallySigned,
) -> Unit {
  self.put_u8(hash_algorithm_code(value.hash_algorithm))
  self.put_u8(signature_algorithm_code(value.signature_algorithm))
  self.put_opaque(2, value.signature, 0, ct_u16_max())
}

///|
pub fn encode_digitally_signed(
  value : DigitallySigned,
) -> Result[Array[Int32], CtError] {
  let gate = new_write_gate()
  gate.put_digitally_signed(value)
  gate.finish()
}

///|
fn ByteReader::read_digitally_signed(
  self : Self,
) -> Result[DigitallySigned, CtError] {
  match self.read_u8() {
    Err(err) => Err(err)
    Ok(hash_code) =>
      match hash_algorithm_from_code(hash_code) {
        Err(err) => Err(err)
        Ok(hash_algorithm) =>
          match self.read_u8() {
            Err(err) => Err(err)
            Ok(sig_code) =>
              match signature_algorithm_from_code(sig_code) {
                Err(err) => Err(err)
                Ok(signature_algorithm) =>
                  match self.read_opaque(2, 0, ct_u16_max()) {
                    Err(err) => Err(err)
                    Ok(signature) =>
                      Ok({ hash_algorithm, signature_algorithm, signature, })
                  }
              }
          }
      }
  }
}

///|
pub fn decode_digitally_signed(
  bytes : Array[Int32],
) -> Result[DigitallySigned, CtError] {
  let reader = new_byte_reader(bytes)
  match reader.read_digitally_signed() {
    Err(err) => Err(err)
    Ok(value) =>
      match reader.expect_exhausted() {
        Err(err) => Err(err)
        Ok(_) => Ok(value)
      }
  }
}

///|
fn WriteGate::put_v1_entry_body(self : Self, body : V1LeafBody) -> Unit {
  match body {
    X509Body(certificate) => {
      self.put_u16(0)
      self.put_opaque(3, certificate, 1, ct_u24_max())
    }
    PrecertBody(issuer, tbs) => {
      self.put_u16(1)
      if !bytes_in_range(issuer) {
        self.note(Err(CtError::BadByte))
      } else if issuer.length() != 32 {
        self.note(Err(CtError::BadHash))
      } else {
        self.put_bytes(issuer)
      }
      self.put_opaque(3, tbs, 1, ct_u24_max())
    }
  }
}

///|
fn ByteReader::read_v1_entry_body(self : Self) -> Result[V1LeafBody, CtError] {
  match self.read_u16() {
    Err(err) => Err(err)
    Ok(code) =>
      if code == 0 {
        match self.read_opaque(3, 1, ct_u24_max()) {
          Err(err) => Err(err)
          Ok(certificate) => Ok(V1LeafBody::X509Body(certificate))
        }
      } else if code == 1 {
        match self.read_bytes(32) {
          Err(err) => Err(err)
          Ok(issuer) =>
            match self.read_opaque(3, 1, ct_u24_max()) {
              Err(err) => Err(err)
              Ok(tbs) => Ok(V1LeafBody::PrecertBody(issuer, tbs))
            }
        }
      } else {
        Err(CtError::BadEnum(code))
      }
  }
}

///|
fn WriteGate::put_v1_timestamped_entry(
  self : Self,
  entry : V1TimestampedEntry,
) -> Unit {
  self.put_u64(entry.timestamp)
  self.put_v1_entry_body(entry.body)
  self.put_opaque(2, entry.extensions, 0, ct_u16_max())
}

///|
fn ByteReader::read_v1_timestamped_entry(
  self : Self,
) -> Result[V1TimestampedEntry, CtError] {
  match self.read_u64() {
    Err(err) => Err(err)
    Ok(timestamp) =>
      match self.read_v1_entry_body() {
        Err(err) => Err(err)
        Ok(body) =>
          match self.read_opaque(2, 0, ct_u16_max()) {
            Err(err) => Err(err)
            Ok(extensions) => Ok({ timestamp, body, extensions, })
          }
      }
  }
}

///|
pub fn encode_v1_timestamped_entry(
  entry : V1TimestampedEntry,
) -> Result[Array[Int32], CtError] {
  let gate = new_write_gate()
  gate.put_v1_timestamped_entry(entry)
  gate.finish()
}

///|
pub fn decode_v1_timestamped_entry(
  bytes : Array[Int32],
) -> Result[V1TimestampedEntry, CtError] {
  let reader = new_byte_reader(bytes)
  match reader.read_v1_timestamped_entry() {
    Err(err) => Err(err)
    Ok(entry) =>
      match reader.expect_exhausted() {
        Err(err) => Err(err)
        Ok(_) => Ok(entry)
      }
  }
}

///|
fn WriteGate::put_v1_merkle_leaf(
  self : Self,
  entry : V1TimestampedEntry,
) -> Unit {
  self.put_u8(0)
  self.put_u8(0)
  self.put_v1_timestamped_entry(entry)
}

///|
/// Encode a v1 MerkleTreeLeaf. The version and leaf type are both written as 0.
pub fn encode_v1_merkle_leaf(
  entry : V1TimestampedEntry,
) -> Result[Array[Int32], CtError] {
  let gate = new_write_gate()
  gate.put_v1_merkle_leaf(entry)
  gate.finish()
}

///|
fn ByteReader::read_v1_merkle_leaf(
  self : Self,
) -> Result[V1MerkleTreeLeaf, CtError] {
  match self.read_u8() {
    Err(err) => Err(err)
    Ok(version) =>
      if version != 0 {
        Err(CtError::Unsupported)
      } else {
        match self.read_u8() {
          Err(err) => Err(err)
          Ok(leaf_type) =>
            if leaf_type != 0 {
              Err(CtError::BadEnum(leaf_type))
            } else {
              match self.read_v1_timestamped_entry() {
                Err(err) => Err(err)
                Ok(entry) => Ok({ entry, })
              }
            }
        }
      }
  }
}

///|
pub fn decode_v1_merkle_leaf(
  bytes : Array[Int32],
) -> Result[V1MerkleTreeLeaf, CtError] {
  let reader = new_byte_reader(bytes)
  match reader.read_v1_merkle_leaf() {
    Err(err) => Err(err)
    Ok(leaf) =>
      match reader.expect_exhausted() {
        Err(err) => Err(err)
        Ok(_) => Ok(leaf)
      }
  }
}

///|
fn WriteGate::put_v1_sct(
  self : Self,
  sct : V1SignedCertificateTimestamp,
) -> Unit {
  self.put_u8(0)
  if !bytes_in_range(sct.log_id) {
    self.note(Err(CtError::BadByte))
  } else if sct.log_id.length() != 32 {
    self.note(Err(CtError::BadHash))
  } else {
    self.put_bytes(sct.log_id)
  }
  self.put_u64(sct.timestamp)
  self.put_opaque(2, sct.extensions, 0, ct_u16_max())
  self.put_digitally_signed(sct.signature)
}

///|
pub fn encode_v1_sct(
  sct : V1SignedCertificateTimestamp,
) -> Result[Array[Int32], CtError] {
  let gate = new_write_gate()
  gate.put_v1_sct(sct)
  gate.finish()
}

///|
fn ByteReader::read_v1_sct(
  self : Self,
) -> Result[V1SignedCertificateTimestamp, CtError] {
  match self.read_u8() {
    Err(err) => Err(err)
    Ok(version) =>
      if version != 0 {
        Err(CtError::Unsupported)
      } else {
        match self.read_bytes(32) {
          Err(err) => Err(err)
          Ok(log_id) =>
            match self.read_u64() {
              Err(err) => Err(err)
              Ok(timestamp) =>
                match self.read_opaque(2, 0, ct_u16_max()) {
                  Err(err) => Err(err)
                  Ok(extensions) =>
                    match self.read_digitally_signed() {
                      Err(err) => Err(err)
                      Ok(signature) =>
                        Ok({ log_id, timestamp, extensions, signature, })
                    }
                }
            }
        }
      }
  }
}

///|
pub fn decode_v1_sct(
  bytes : Array[Int32],
) -> Result[V1SignedCertificateTimestamp, CtError] {
  let reader = new_byte_reader(bytes)
  match reader.read_v1_sct() {
    Err(err) => Err(err)
    Ok(sct) =>
      match reader.expect_exhausted() {
        Err(err) => Err(err)
        Ok(_) => Ok(sct)
      }
  }
}

///|
fn WriteGate::put_v1_signed_prefix(self : Self, signature_type : Int32) -> Unit {
  self.put_u8(0)
  self.put_u8(signature_type)
}

///|
/// Bytes covered by a v1 SCT signature. This is not a MerkleTreeLeaf.
pub fn v1_sct_signed_input(
  entry : V1TimestampedEntry,
) -> Result[Array[Int32], CtError] {
  let gate = new_write_gate()
  gate.put_v1_signed_prefix(0)
  gate.put_v1_timestamped_entry(entry)
  gate.finish()
}

///|
/// Bytes covered by a v1 tree-head signature (`signature_type = tree_hash`).
pub fn v1_tree_head_signed_input(
  timestamp : UInt64,
  tree_size : UInt64,
  root_hash : Hash,
) -> Result[Array[Int32], CtError] {
  if !bytes_in_range(root_hash) {
    Err(CtError::BadByte)
  } else if !is_valid_hash(root_hash) {
    Err(CtError::BadHash)
  } else {
    let gate = new_write_gate()
    gate.put_v1_signed_prefix(1)
    gate.put_u64(timestamp)
    gate.put_u64(tree_size)
    gate.put_bytes(root_hash)
    gate.finish()
  }
}

///|
pub fn decode_v1_tree_head_signed_input(
  bytes : Array[Int32],
) -> Result[V1TreeHeadSigned, CtError] {
  let reader = new_byte_reader(bytes)
  match reader.read_u8() {
    Err(err) => Err(err)
    Ok(version) =>
      if version != 0 {
        Err(CtError::Unsupported)
      } else {
        match reader.read_u8() {
          Err(err) => Err(err)
          Ok(signature_type) =>
            if signature_type != 1 {
              Err(CtError::BadEnum(signature_type))
            } else {
              match reader.read_u64() {
                Err(err) => Err(err)
                Ok(timestamp) =>
                  match reader.read_u64() {
                    Err(err) => Err(err)
                    Ok(tree_size) =>
                      match reader.read_bytes(32) {
                        Err(err) => Err(err)
                        Ok(root_hash) =>
                          match reader.expect_exhausted() {
                            Err(err) => Err(err)
                            Ok(_) => Ok({ timestamp, tree_size, root_hash, })
                          }
                      }
                  }
              }
            }
        }
      }
  }
}

///|
/// Report whether an SCT's timestamp and extensions bind the supplied entry.
pub fn v1_sct_binds_entry(
  sct : V1SignedCertificateTimestamp,
  entry : V1TimestampedEntry,
) -> Result[Unit, CtError] {
  if sct.timestamp != entry.timestamp ||
    !bytes_equal(sct.extensions, entry.extensions) {
    Err(CtError::BadProof)
  } else {
    Ok(())
  }
}
