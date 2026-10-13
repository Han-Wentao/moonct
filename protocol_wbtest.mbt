///|
fn mix_hash(input : Array[Int32]) -> Array[Int32] {
  let out = Array(capacity=32)
  for _ in 0..<32 {
    out.push(0)
  }
  for i in 0..<input.length() {
    let byte = input[i]
    let slot = i % 32
    out[slot] = (out[slot] + byte * (i + 3) + 19) % 256
    let other = (i * 5 + 7) % 32
    out[other] = out[other].lxor(byte)
  }
  out[31] = (out[31] + input.length()) % 256
  out
}

///|
fn sample_entries() -> Array[Array[Int32]] {
  let entries = Array(capacity=7)
  for i in 0..<7 {
    entries.push([i, i + 1, 9])
  }
  entries
}

///|
fn filled_hash(value : Int32) -> Array[Int32] {
  let out = Array(capacity=32)
  for _ in 0..<32 {
    out.push(value)
  }
  out
}

///|
fn[T] error_text(result : Result[T, CtError]) -> String {
  match result {
    Ok(_) => "ok"
    Err(err) => ct_error_text(err)
  }
}

///|
fn[T] expect_err(result : Result[T, CtError], want : CtError) -> Unit raise {
  assert_eq(error_text(result), ct_error_text(want))
}

///|
fn expect_path(path : Array[Hash], hexes : Array[String]) -> Unit raise {
  assert_eq(path.length(), hexes.length())
  if path.length() == hexes.length() {
    for i in 0..<path.length() {
      match hex_decode(hexes[i]) {
        Err(_) => assert_true(false)
        Ok(want) => assert_true(bytes_equal(path[i], want))
      }
    }
  }
}

///|
fn round_trans(item : TransItem, code : Int32) -> Unit raise {
  assert_eq(trans_type_code(item), code)
  match encode_trans_item(item) {
    Err(_) => assert_true(false)
    Ok(bytes) =>
      match decode_trans_item(bytes) {
        Err(_) => assert_true(false)
        Ok(decoded) => {
          assert_eq(trans_type_code(decoded), code)
          assert_true(bytes[0] * 256 + bytes[1] == code)
        }
      }
  }
}

///|
test "minimal inclusion path differs from legacy height" {
  let entries = sample_entries()
  assert_eq(proof_height(7U), Some(3U))
  match inclusion_path(mix_hash, entries, 6UL) {
    Err(_) => assert_true(false)
    Ok(proof) => {
      assert_eq(proof.path.length(), 2)
      assert_eq(proof.tree_size, 7UL)
      assert_eq(proof.leaf_index, 6UL)
      let legacy = new_inclusion_proof(6U, 7U, proof.path)
      assert_false(proof_shape_valid(legacy))
    }
  }
}

///|
test "rfc shapes match injected vectors" {
  let entries = sample_entries()
  match merkle_tree_hash(mix_hash, entries) {
    Err(_) => assert_true(false)
    Ok(root) =>
      match merkle_tree_hash_by_stack(mix_hash, entries) {
        Err(_) => assert_true(false)
        Ok(stacked) => {
          assert_true(bytes_equal(root, stacked))
          match
            hex_decode(
              "61d6912818506de5ac947928b13822917e0358e72b209e35d228cc94f71894b9",
            ) {
            Err(_) => assert_true(false)
            Ok(want) => assert_true(bytes_equal(root, want))
          }
          match inclusion_path(mix_hash, entries, 0UL) {
            Err(_) => assert_true(false)
            Ok(proof) =>
              expect_path(proof.path, [
                "13171d4900000000000000000100000000020000000009000000000000000004",
                "d41f28bc442626272726262648d62626264439262626251a2626282826262667",
                "9901d2dc4b28b70e9d743a1445f8f4f9d614b3acbf988ab00a749e912408328d",
              ])
          }
          match inclusion_path(mix_hash, entries, 3UL) {
            Err(_) => assert_true(false)
            Ok(proof) =>
              expect_path(proof.path, [
                "131b224900000000000000000200000000030000000009000000000000000004",
                "d41fd8044426262727262626485626262644a5262626491a2626282826262667",
                "9901d2dc4b28b70e9d743a1445f8f4f9d614b3acbf988ab00a749e912408328d",
              ])
          }
          match inclusion_path(mix_hash, entries, 4UL) {
            Err(_) => assert_true(false)
            Ok(proof) =>
              expect_path(proof.path, [
                "1327314900000000000000000500000000060000000009000000000000000004",
                "132b364900000000000000000600000000070000000009000000000000000004",
                "464e302ee6eecc2160aec2ce028ec2404e0012aac0ce12fa2e42b03e22aef243",
              ])
          }
          match inclusion_path(mix_hash, entries, 6UL) {
            Err(_) => assert_true(false)
            Ok(proof) => {
              expect_path(proof.path, [
                "d41f7874442626272f262626485626262624cd262626211a2626282826262667",
                "464e302ee6eecc2160aec2ce028ec2404e0012aac0ce12fa2e42b03e22aef243",
              ])
              match hash_leaf(mix_hash, entries[6]) {
                Err(_) => assert_true(false)
                Ok(leaf) =>
                  assert_true(
                    verify_merkle_inclusion(mix_hash, leaf, proof, root),
                  )
              }
            }
          }
          match consistency_proof(mix_hash, entries, 4UL) {
            Err(_) => assert_true(false)
            Ok(proof) => {
              expect_path(proof.proof, [
                "9901d2dc4b28b70e9d743a1445f8f4f9d614b3acbf988ab00a749e912408328d",
              ])
              match
                merkle_tree_hash(mix_hash, [
                  entries[0],
                  entries[1],
                  entries[2],
                  entries[3],
                ]) {
                Err(_) => assert_true(false)
                Ok(first) =>
                  assert_true(verify_consistency(mix_hash, first, root, proof))
              }
            }
          }
          match consistency_proof(mix_hash, entries, 3UL) {
            Err(_) => assert_true(false)
            Ok(proof) =>
              expect_path(proof.proof, [
                "131b224900000000000000000200000000030000000009000000000000000004",
                "131f274900000000000000000300000000040000000009000000000000000004",
                "d41fd8044426262727262626485626262644a5262626491a2626282826262667",
                "9901d2dc4b28b70e9d743a1445f8f4f9d614b3acbf988ab00a749e912408328d",
              ])
          }
          match consistency_proof(mix_hash, entries, 6UL) {
            Err(_) => assert_true(false)
            Ok(proof) =>
              expect_path(proof.proof, [
                "d41f7874442626272f262626485626262624cd262626211a2626282826262667",
                "132b364900000000000000000600000000070000000009000000000000000004",
                "464e302ee6eecc2160aec2ce028ec2404e0012aac0ce12fa2e42b03e22aef243",
              ])
          }
        }
      }
  }
}

///|
test "consistency boundaries reject empty and reversed trees" {
  let entries = sample_entries()
  expect_err(consistency_proof(mix_hash, entries, 0UL), CtError::BadIndex)
  expect_err(consistency_proof(mix_hash, entries, 8UL), CtError::BadIndex)
  match merkle_tree_hash(mix_hash, entries) {
    Err(_) => assert_true(false)
    Ok(root) => {
      match consistency_proof(mix_hash, entries, 7UL) {
        Err(_) => assert_true(false)
        Ok(proof) => {
          assert_eq(proof.proof.length(), 0)
          assert_true(verify_consistency(mix_hash, root, root, proof))
        }
      }
      let broken : MerkleConsistency = {
        first_size: 4UL,
        second_size: 7UL,
        proof: Array(capacity=0),
      }
      assert_false(verify_consistency(mix_hash, root, root, broken))
      match inclusion_path(mix_hash, entries, 6UL) {
        Err(_) => assert_true(false)
        Ok(proof) => {
          let extra = Array(capacity=proof.path.length() + 1)
          for i in 0..<proof.path.length() {
            extra.push(proof.path[i])
          }
          extra.push(filled_hash(1))
          let overlong : MerkleInclusion = {
            leaf_index: 6UL,
            tree_size: 7UL,
            path: extra,
          }
          match hash_leaf(mix_hash, entries[6]) {
            Err(_) => assert_true(false)
            Ok(leaf) =>
              assert_false(
                verify_merkle_inclusion(mix_hash, leaf, overlong, root),
              )
          }
        }
      }
    }
  }
  match empty_tree_hash(mix_hash) {
    Err(_) => assert_true(false)
    Ok(hash) => assert_true(bytes_equal(hash, filled_hash(0)))
  }
}

///|
test "v1 signed input matches merkle leaf but not tree head" {
  match v1_x509_body([1, 2, 3]) {
    Err(_) => assert_true(false)
    Ok(body) =>
      match new_v1_timestamped_entry(9UL, body, [4]) {
        Err(_) => assert_true(false)
        Ok(entry) =>
          match encode_v1_merkle_leaf(entry) {
            Err(_) => assert_true(false)
            Ok(leaf) =>
              match v1_sct_signed_input(entry) {
                Err(_) => assert_true(false)
                Ok(signed) => {
                  assert_true(bytes_equal(leaf, signed))
                  assert_eq(leaf[0], 0)
                  assert_eq(leaf[1], 0)
                  match v1_tree_head_signed_input(9UL, 1UL, filled_hash(2)) {
                    Err(_) => assert_true(false)
                    Ok(head) => {
                      assert_eq(head[1], 1)
                      assert_false(bytes_equal(head, leaf))
                    }
                  }
                }
              }
          }
      }
  }
  match v1_precert_body(filled_hash(3), [5, 6]) {
    Err(_) => assert_true(false)
    Ok(body) =>
      match new_v1_timestamped_entry(11UL, body, []) {
        Err(_) => assert_true(false)
        Ok(entry) =>
          match (encode_v1_merkle_leaf(entry), v1_sct_signed_input(entry)) {
            (Ok(leaf), Ok(signed)) => assert_true(bytes_equal(leaf, signed))
            _ => assert_true(false)
          }
      }
  }
}

///|
test "v1 algorithms and sct binding round trip" {
  let codes = [0, 1, 2, 3, 4, 5, 6]
  for i in 0..<codes.length() {
    match hash_algorithm_from_code(codes[i]) {
      Err(_) => assert_true(false)
      Ok(algorithm) => assert_eq(hash_algorithm_code(algorithm), codes[i])
    }
  }
  expect_err(hash_algorithm_from_code(7), CtError::BadEnum(7))
  let signatures = [0, 1, 2, 3]
  for i in 0..<signatures.length() {
    match signature_algorithm_from_code(signatures[i]) {
      Err(_) => assert_true(false)
      Ok(algorithm) =>
        assert_eq(signature_algorithm_code(algorithm), signatures[i])
    }
  }
  expect_err(signature_algorithm_from_code(4), CtError::BadEnum(4))
  match new_digitally_signed(Sha256Alg, Ecdsa, [9, 8]) {
    Err(_) => assert_true(false)
    Ok(signed) =>
      match encode_digitally_signed(signed) {
        Err(_) => assert_true(false)
        Ok(bytes) =>
          match decode_digitally_signed(bytes) {
            Err(_) => assert_true(false)
            Ok(decoded) => assert_true(bytes_equal(decoded.signature, [9, 8]))
          }
      }
  }
  match v1_x509_body([1]) {
    Err(_) => assert_true(false)
    Ok(body) =>
      match new_v1_timestamped_entry(4UL, body, [1]) {
        Err(_) => assert_true(false)
        Ok(entry) =>
          match new_digitally_signed(Sha256Alg, Ecdsa, [2]) {
            Err(_) => assert_true(false)
            Ok(signature) =>
              match new_v1_sct(filled_hash(1), 4UL, [1], signature) {
                Err(_) => assert_true(false)
                Ok(sct) => {
                  match v1_sct_binds_entry(sct, entry) {
                    Err(_) => assert_true(false)
                    Ok(_) => assert_true(true)
                  }
                  match new_v1_timestamped_entry(4UL, body, [2]) {
                    Err(_) => assert_true(false)
                    Ok(other) =>
                      expect_err(
                        v1_sct_binds_entry(sct, other),
                        CtError::BadProof,
                      )
                  }
                }
              }
          }
      }
  }
  expect_err(decode_v1_merkle_leaf([1, 0]), CtError::Unsupported)
  expect_err(decode_v1_merkle_leaf([0, 2]), CtError::BadEnum(2))
}

///|
test "v2 trans items round trip and reject reserved codes" {
  match new_ct_extension(1, [7]) {
    Err(_) => assert_true(false)
    Ok(extension) => {
      let extensions = [extension]
      match new_v2_certificate_entry(5UL, filled_hash(4), [6], extensions) {
        Err(_) => assert_true(false)
        Ok(entry) => {
          round_trans(TransItem::X509EntryV2(entry), 0x0100)
          round_trans(TransItem::PrecertEntryV2(entry), 0x0101)
        }
      }
      match new_v2_sct([1, 2], 5UL, extensions, [3]) {
        Err(_) => assert_true(false)
        Ok(sct) => {
          round_trans(TransItem::X509SctV2(sct), 0x0102)
          round_trans(TransItem::PrecertSctV2(sct), 0x0103)
        }
      }
      match new_v2_tree_head(5UL, 1UL, filled_hash(4), extensions) {
        Err(_) => assert_true(false)
        Ok(head) =>
          match new_v2_signed_tree_head([1, 2], head, [3]) {
            Err(_) => assert_true(false)
            Ok(signed) =>
              round_trans(TransItem::SignedTreeHeadV2(signed), 0x0104)
          }
      }
      match new_v2_consistency([1, 2], 1UL, 2UL, [filled_hash(4)]) {
        Err(_) => assert_true(false)
        Ok(proof) => round_trans(TransItem::ConsistencyProofV2(proof), 0x0105)
      }
      match new_v2_inclusion([1, 2], 2UL, 1UL, [filled_hash(4)]) {
        Err(_) => assert_true(false)
        Ok(proof) => round_trans(TransItem::InclusionProofV2(proof), 0x0106)
      }
    }
  }
  expect_err(decode_trans_item([0x00, 0x00]), CtError::Unsupported)
  expect_err(decode_trans_item([0x00, 0xFF]), CtError::Unsupported)
  expect_err(decode_trans_item([0xE0, 0x00]), CtError::Unsupported)
  expect_err(decode_trans_item([0xEF, 0xFF]), CtError::Unsupported)
  expect_err(decode_trans_item([0xF0, 0x00]), CtError::Unsupported)
  expect_err(decode_trans_item([0xFF, 0xFF]), CtError::Unsupported)
  expect_err(decode_trans_item([0x01, 0x07]), CtError::BadEnum(0x0107))
  expect_err(decode_trans_item([0x02, 0x00]), CtError::BadEnum(0x0200))
  expect_err(decode_trans_item([0xDF, 0xFF]), CtError::BadEnum(0xDFFF))
  match new_ct_extension(2, []) {
    Err(_) => assert_true(false)
    Ok(second) =>
      match new_ct_extension(1, []) {
        Err(_) => assert_true(false)
        Ok(first) =>
          expect_err(
            new_v2_certificate_entry(1UL, filled_hash(1), [1], [second, first]),
            CtError::OutOfOrder,
          )
      }
  }
  match new_ct_extension(4, []) {
    Err(_) => assert_true(false)
    Ok(item) =>
      expect_err(
        new_v2_certificate_entry(1UL, filled_hash(1), [1], [item, item]),
        CtError::Duplicate,
      )
  }
  expect_err(new_ct_extension(65535, []), CtError::Unsupported)
}

///|
test "json rejects malformed ct messages and keeps stable keys" {
  expect_err(parse_ct_json(""), CtError::EmptyInput)
  expect_err(parse_ct_json(" \n\t"), CtError::EmptyInput)
  expect_err(parse_ct_json("01"), CtError::BadJson("leading zero"))
  expect_err(parse_ct_json("-1"), CtError::BadJson("unexpected character"))
  expect_err(parse_ct_json("1.5"), CtError::BadJson("unsigned integer only"))
  expect_err(parse_ct_json("1e2"), CtError::BadJson("unsigned integer only"))
  expect_err(parse_ct_json("truex"), CtError::BadJson("literal"))
  expect_err(parse_ct_json("18446744073709551616"), CtError::Overflow)
  match parse_ct_json("18446744073709551615") {
    Ok(JsonNumber(text)) => assert_eq(text, "18446744073709551615")
    _ => assert_true(false)
  }
  match parse_ct_json("null") {
    Ok(JsonNull) =>
      match write_ct_json(JsonNull) {
        Ok(text) => assert_eq(text, "null")
        Err(_) => assert_true(false)
      }
    _ => assert_true(false)
  }
  expect_err(parse_ct_json("{\"a\":1,\"a\":2}"), CtError::Duplicate)
  expect_err(parse_ct_json("{\"a\":1,}"), CtError::BadJson("trailing comma"))
  expect_err(parse_ct_json("{a:1}"), CtError::BadJson("string"))
  expect_err(parse_ct_json("{\"a\":1} true"), CtError::BadJson("trailing data"))
  expect_err(parse_ct_json("\"\\uD800\""), CtError::BadJson("surrogate"))
  let message : SthMessage = {
    tree_size: 1UL,
    timestamp: 2UL,
    sha256_root_hash: filled_hash(0),
    tree_head_signature: [1],
  }
  match encode_sth_message(message) {
    Err(_) => assert_true(false)
    Ok(text) => {
      assert_eq(
        text, "{\"tree_size\":1,\"timestamp\":2,\"sha256_root_hash\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"tree_head_signature\":\"AQ==\"}",
      )
      match decode_sth_message(text) {
        Err(_) => assert_true(false)
        Ok(decoded) => {
          assert_eq(decoded.tree_size, 1UL)
          assert_true(bytes_equal(decoded.tree_head_signature, [1]))
        }
      }
    }
  }
  expect_err(decode_sth_message(""), CtError::EmptyInput)
  expect_err(
    decode_inclusion_message("{\"leaf_index\":01,\"audit_path\":[]}"),
    CtError::BadJson("leading zero"),
  )
  expect_err(
    decode_inclusion_message(
      "{\"leaf_index\":0,\"audit_path\":[],\"tree_size\":1}",
    ),
    CtError::BadJson("unknown key"),
  )
  match decode_inclusion_message("{\"audit_path\":[],\"leaf_index\":0}") {
    Err(_) => assert_true(false)
    Ok(decoded) => {
      assert_eq(decoded.leaf_index, 0UL)
      assert_eq(decoded.audit_path.length(), 0)
    }
  }
  match encode_consistency_message({ consistency: Array(capacity=0), }) {
    Err(_) => assert_true(false)
    Ok(text) => assert_eq(text, "{\"consistency\":[]}")
  }
  expect_err(
    encode_sth_message({
      tree_size: 1UL,
      timestamp: 1UL,
      sha256_root_hash: filled_hash(0),
      tree_head_signature: [],
    }),
    CtError::EmptyInput,
  )
}

///|
test "memory log checkpoints agree with both merkle roots" {
  let log = new_memory_log()
  expect_err(log.latest_time(), CtError::EmptyInput)
  match log.checkpoint(mix_hash, 5UL) {
    Err(_) => assert_true(false)
    Ok(checkpoint) => {
      assert_eq(checkpoint.tree_size, 0UL)
      assert_true(bytes_equal(checkpoint.root_hash, filled_hash(0)))
    }
  }
  let entries = sample_entries()
  for i in 0..<entries.length() {
    match log.append(mix_hash, (i + 1).to_uint64(), entries[i]) {
      Err(_) => assert_true(false)
      Ok(_) => ()
    }
  }
  let mutable = [9, 8, 7]
  match log.append(mix_hash, 8UL, mutable) {
    Err(_) => assert_true(false)
    Ok(_) => ()
  }
  mutable[0] = 1
  match log.entry_at(7UL) {
    Err(_) => assert_true(false)
    Ok(stored) => assert_eq(stored[0], 9)
  }
  expect_err(log.append(mix_hash, 8UL, [1]), CtError::OutOfOrder)
  expect_err(log.append(mix_hash, 9UL, [256]), CtError::BadByte)
  assert_eq(log.size(), 8UL)
  let seven = new_memory_log()
  for i in 0..<7 {
    match seven.append(mix_hash, (10 + i).to_uint64(), entries[i]) {
      Err(_) => assert_true(false)
      Ok(_) => ()
    }
  }
  match seven.audit(mix_hash) {
    Err(_) => assert_true(false)
    Ok(root) =>
      match
        hex_decode(
          "61d6912818506de5ac947928b13822917e0358e72b209e35d228cc94f71894b9",
        ) {
        Err(_) => assert_true(false)
        Ok(want) => assert_true(bytes_equal(root, want))
      }
  }
  match seven.root_through(mix_hash, 4UL) {
    Err(_) => assert_true(false)
    Ok(prefix) =>
      match
        hex_decode(
          "464e302ee6eecc2160aec2ce028ec2404e0012aac0ce12fa2e42b03e22aef243",
        ) {
        Err(_) => assert_true(false)
        Ok(want) => {
          assert_true(bytes_equal(prefix, want))
          match seven.verify_prefix(mix_hash, 4UL, prefix) {
            Err(_) => assert_true(false)
            Ok(_) => assert_true(true)
          }
        }
      }
  }
  match seven.inclusion(mix_hash, 6UL) {
    Err(_) => assert_true(false)
    Ok(proof) => {
      assert_eq(proof.path.length(), 2)
      match encode_log_inclusion(proof) {
        Err(_) => assert_true(false)
        Ok(text) =>
          match decode_inclusion_message(text) {
            Err(_) => assert_true(false)
            Ok(message) => assert_eq(message.audit_path.length(), 2)
          }
      }
      match
        new_v2_inclusion([9, 9], proof.tree_size, proof.leaf_index, proof.path) {
        Err(_) => assert_true(false)
        Ok(wire) =>
          match seven.root(mix_hash) {
            Err(_) => assert_true(false)
            Ok(root) =>
              match hash_leaf(mix_hash, entries[6]) {
                Err(_) => assert_true(false)
                Ok(leaf) =>
                  match
                    verify_trans_inclusion(
                      mix_hash,
                      leaf,
                      TransItem::InclusionProofV2(wire),
                      root,
                    ) {
                    Err(_) => assert_true(false)
                    Ok(_) =>
                      expect_err(
                        verify_trans_inclusion(
                          mix_hash,
                          leaf,
                          TransItem::X509SctV2({
                            log_id: [9, 9],
                            timestamp: 1UL,
                            extensions: Array(capacity=0),
                            signature: [1],
                          }),
                          root,
                        ),
                        CtError::Unsupported,
                      )
                  }
              }
          }
      }
    }
  }
  match seven.consistency(mix_hash, 6UL) {
    Err(_) => assert_true(false)
    Ok(proof) =>
      match encode_log_consistency(proof) {
        Err(_) => assert_true(false)
        Ok(text) =>
          match decode_consistency_message(text) {
            Err(_) => assert_true(false)
            Ok(message) => assert_eq(message.consistency.length(), 3)
          }
      }
  }
  expect_err(seven.checkpoint(mix_hash, 9UL), CtError::OutOfOrder)
  match seven.checkpoint(mix_hash, 16UL) {
    Err(_) => assert_true(false)
    Ok(checkpoint) =>
      match encode_checkpoint_sth(checkpoint, [4, 5]) {
        Err(_) => assert_true(false)
        Ok(text) => {
          assert_true(text.has_prefix("{\"tree_size\":7,"))
          match decode_sth_message(text) {
            Err(_) => assert_true(false)
            Ok(message) => assert_eq(message.timestamp, 16UL)
          }
        }
      }
  }
  match v1_x509_body([4, 5]) {
    Err(_) => assert_true(false)
    Ok(body) =>
      match new_v1_timestamped_entry(3UL, body, []) {
        Err(_) => assert_true(false)
        Ok(entry) => {
          let fresh = new_memory_log()
          match fresh.append_v1_leaf(mix_hash, entry) {
            Err(_) => assert_true(false)
            Ok(_) =>
              match fresh.entry_at(0UL) {
                Err(_) => assert_true(false)
                Ok(stored) => {
                  assert_eq(stored[0], 0)
                  assert_eq(stored[1], 0)
                }
              }
          }
          expect_err(fresh.append_v1_leaf(mix_hash, entry), CtError::OutOfOrder)
        }
      }
  }
  match log.append(mix_hash, 10UL, []) {
    Err(_) => assert_true(false)
    Ok(_) => assert_eq(log.size(), 9UL)
  }
}
