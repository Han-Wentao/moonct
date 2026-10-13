///|
test "base64 matches RFC 4648 vectors and rejects non-canonical pad bits" {
  let cases : Array[(String, Array[Int])] = [
    ("", []),
    ("Zg==", [102]),
    ("Zm8=", [102, 111]),
    ("Zm9v", [102, 111, 111]),
    ("Zm9vYg==", [102, 111, 111, 98]),
    ("Zm9vYmE=", [102, 111, 111, 98, 97]),
    ("Zm9vYmFy", [102, 111, 111, 98, 97, 114]),
  ]
  for (encoded, decoded) in cases {
    match base64_decode(encoded) {
      Err(_) => assert_true(false)
      Ok(actual) => assert_true(bytes_equal(actual, decoded))
    }
    match base64_encode(decoded) {
      Err(_) => assert_true(false)
      Ok(actual) => assert_eq(actual, encoded)
    }
  }
  expect_err(base64_decode("A"), CtError::BadLength)
  expect_err(base64_decode("Zh=="), CtError::BadByte)
  expect_err(base64_decode("Zm9="), CtError::BadByte)
  expect_err(base64_decode("Z==="), CtError::BadByte)
  expect_err(base64_decode("=m9v"), CtError::BadByte)
  expect_err(base64_decode("Zm=v"), CtError::BadByte)
  expect_err(base64_decode("Zm9v="), CtError::BadLength)
  expect_err(base64_decode("Zm9?"), CtError::BadByte)
}
