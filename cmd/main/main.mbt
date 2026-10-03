///|
fn main {
  let height = @moonct.proof_height(8U)
  match height {
    Some(value) =>
      println("MoonCT proof height for tree size 8: " + value.to_string())
    None => println("MoonCT rejected an empty tree")
  }
}
