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

///|
test "raw leaf helper matches hash helper" {
  let leaf = [9, 8, 7]
  let hash = @moonct.leaf_hash(test_hash, leaf)
  match hash {
    Some(value) => {
      let proof = @moonct.new_inclusion_proof(0U, 1U, [])
      let head = @moonct.new_tree_head(0U, 1U, 1U, value)
      assert_true(@moonct.verify_leaf_inclusion(test_hash, leaf, proof, head))
    }
    None => assert_true(false)
  }
}

///|
test "invalid root is rejected" {
  let leaf = @moonct.leaf_hash(test_hash, [1])
  match leaf {
    Some(value) => {
      let proof = @moonct.new_inclusion_proof(0U, 1U, [])
      let head = @moonct.new_tree_head(0U, 1U, 1U, Array::make(32, 99))
      assert_false(@moonct.verify_inclusion(test_hash, value, proof, head))
    }
    None => assert_true(false)
  }
}

///|
test "malformed path is rejected" {
  let leaf = Array::make(32, 1)
  let proof = @moonct.new_inclusion_proof(0U, 2U, [])
  let head = @moonct.new_tree_head(0U, 1U, 2U, Array::make(32, 1))
  assert_false(@moonct.verify_inclusion(test_hash, leaf, proof, head))
}

///|
test "invalid index is rejected" {
  let leaf = Array::make(32, 1)
  let proof = @moonct.new_inclusion_proof(2U, 2U, [])
  let head = @moonct.new_tree_head(0U, 1U, 2U, Array::make(32, 1))
  assert_false(@moonct.verify_inclusion(test_hash, leaf, proof, head))
}

///|
test "signature rejection is propagated" {
  let head = @moonct.new_tree_head(0U, 1U, 1U, Array::make(32, 1))
  let rejected : (Array[Int], Array[Int], Array[Int]) -> Bool = fn(
    _key,
    _message,
    _signature,
  ) {
    false
  }
  assert_false(@moonct.verify_tree_head(head, [1], [2], [3], rejected))
}

///|
test "hash shape is explicit" {
  assert_true(@moonct.is_valid_hash(Array::make(32, 0)))
  assert_false(@moonct.is_valid_hash(Array::make(31, 0)))
}

///|
test "proof shape follows tree height" {
  assert_true(
    @moonct.proof_shape_valid(@moonct.new_inclusion_proof(0U, 1U, [])),
  )
  assert_true(
    @moonct.proof_shape_valid(
      @moonct.new_inclusion_proof(5U, 7U, [
        Array::make(32, 1),
        Array::make(32, 2),
        Array::make(32, 3),
      ]),
    ),
  )
  assert_false(
    @moonct.proof_shape_valid(@moonct.new_inclusion_proof(0U, 7U, [])),
  )
}

///|
test "leaf and node domains stay distinct" {
  let leaf = @moonct.leaf_hash(test_hash, [1, 2, 3])
  let left = Array::make(32, 1)
  let right = Array::make(32, 2)
  let node = @moonct.node_hash(test_hash, left, right)
  match (leaf, node) {
    (Some(a), Some(b)) => assert_false(a == b)
    _ => assert_true(false)
  }
}

///|
test "node hash rejects malformed children" {
  assert_eq(
    @moonct.node_hash(test_hash, Array::make(31, 0), Array::make(32, 0)),
    None,
  )
}
