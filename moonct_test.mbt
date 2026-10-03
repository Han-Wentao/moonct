///|
fn test_hash(input : Array[Int]) -> Array[Int] {
  let out : Array[Int] = Array::make(32, 0)
  for i = 0; i < input.length(); i = i + 1 {
    let slot = i % 32
    out[slot] = (out[slot] + input[i] + i) % 256
  }
  out
}

///|
test "inclusion proof verifies" {
  let left = @moonct.leaf_hash(test_hash, [10, 20])
  let right = @moonct.leaf_hash(test_hash, [30, 40])
  match (left, right) {
    (Some(l), Some(r)) =>
      match @moonct.node_hash(test_hash, l, r) {
        Some(root) => {
          let proof = @moonct.new_inclusion_proof(0U, 2U, [r])
          let head = @moonct.new_tree_head(0U, 1U, 2U, root)
          assert_true(@moonct.verify_inclusion(test_hash, l, proof, head))
        }
        None => assert_true(false)
      }
    _ => assert_true(false)
  }
}

///|
test "proof height is bounded" {
  assert_eq(@moonct.proof_height(1U), Some(0U))
  assert_eq(@moonct.proof_height(7U), Some(3U))
  assert_eq(@moonct.proof_height(0U), None)
}

///|
test "tree head verifier delegates signature" {
  let head = @moonct.new_tree_head(0U, 1U, 1U, Array::make(32, 1))
  let accepted : (Array[Int], Array[Int], Array[Int]) -> Bool = fn(
    _key,
    _message,
    _signature,
  ) {
    true
  }
  assert_true(@moonct.verify_tree_head(head, [1], [2], [3], accepted))
}
