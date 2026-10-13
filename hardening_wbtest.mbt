///|
fn invalid_sha256(_input : Array[Int32]) -> Hash {
  Array::make(32, 256)
}

///|
test "hash boundaries enforce 32 unsigned bytes" {
  assert_true(is_valid_hash(filled_hash(255)))
  assert_false(is_valid_hash(filled_hash(256)))
  assert_false(is_valid_hash([0]))
  let negative = filled_hash(0)
  negative[0] = -1
  assert_false(is_valid_hash(negative))
  assert_eq(leaf_hash(mix_hash, [-1]), None)
  assert_eq(leaf_hash(mix_hash, [256]), None)
  assert_eq(leaf_hash(invalid_sha256, [1]), None)
  assert_eq(node_hash(invalid_sha256, filled_hash(0), filled_hash(1)), None)
  assert_eq(node_hash(mix_hash, negative, filled_hash(1)), None)
  let singleton = new_inclusion_proof(0U, 1U, [])
  let malformed_head = new_tree_head(0U, 0U, 1U, filled_hash(256))
  assert_false(
    verify_inclusion(mix_hash, filled_hash(0), singleton, malformed_head),
  )
}

///|
test "legacy proof height and shape are safe at UInt maximum" {
  let maximum = 4294967295U
  assert_eq(proof_height(maximum), Some(32U))
  let proof = new_inclusion_proof(0U, maximum, Array::make(32, filled_hash(0)))
  assert_true(proof_shape_valid(proof))
}

///|
test "byte reader owns input and opaque writes fail atomically" {
  let source = [1, 2]
  let reader = new_byte_reader(source)
  source[0] = 9
  match reader.read_u8() {
    Err(_) => assert_true(false)
    Ok(value) => assert_eq(value, 1)
  }
  let writer = new_byte_writer()
  match writer.write_u8(7) {
    Err(_) => assert_true(false)
    Ok(_) => ()
  }
  expect_err(writer.write_opaque(2, [8, 256], 1, 4), CtError::BadByte)
  assert_eq(writer.length(), 1)
  assert_true(bytes_equal(writer.bytes(), [7]))
  expect_err(writer.write_opaque(2, [8], 2, 4), CtError::BadLength)
  assert_eq(writer.length(), 1)
  match writer.write_opaque(2, [8, 9], 2, 4) {
    Err(_) => assert_true(false)
    Ok(_) => assert_true(bytes_equal(writer.bytes(), [7, 0, 2, 8, 9]))
  }
}
