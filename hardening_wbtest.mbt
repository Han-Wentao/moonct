///|
fn invalid_sha256(_input : Array[Int]) -> Hash {
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
