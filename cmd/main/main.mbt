///|
fn demo_hash(input : Array[Int32]) -> @moonct.Hash {
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
fn main {
  match @moonct.proof_height(7U) {
    Some(height) =>
      println("legacy inclusion height for tree size 7: " + height.to_string())
    None => println("legacy inclusion height rejected tree size 7")
  }
  let entries = sample_entries()
  match @moonct.inclusion_path(demo_hash, entries, 6UL) {
    Ok(proof) =>
      println(
        "RFC 9162 inclusion path length for index 6: " +
        proof.path.length().to_string(),
      )
    Err(_) => println("RFC 9162 inclusion path was rejected")
  }
  match @moonct.consistency_proof(demo_hash, entries, 4UL) {
    Ok(proof) =>
      println(
        "RFC 9162 consistency proof length from 4 to 7: " +
        proof.proof.length().to_string(),
      )
    Err(_) => println("RFC 9162 consistency proof was rejected")
  }
}
