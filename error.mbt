///|
/// Failure reported by MoonCT parsers, codecs, and proof checks.
pub enum CtError {
  Truncated
  BadLength
  BadByte
  BadEnum(Int32)
  BadHash
  BadIndex
  BadProof
  BadJson(String)
  EmptyInput
  Overflow
  OutOfOrder
  Duplicate
  Unsupported
}

///|
/// Render a stable diagnostic without allocating a stack trace.
pub fn ct_error_text(err : CtError) -> String {
  match err {
    Truncated => "truncated input"
    BadLength => "length is outside the allowed range"
    BadByte => "byte is outside 0..255"
    BadEnum(value) => "unknown enumeration value " + value.to_string()
    BadHash => "hash must contain 32 bytes"
    BadIndex => "index is outside the tree"
    BadProof => "proof does not match the tree head"
    BadJson(detail) => "json: " + detail
    EmptyInput => "input is empty"
    Overflow => "integer does not fit in the destination"
    OutOfOrder => "values are not in ascending order"
    Duplicate => "duplicate value"
    Unsupported => "unsupported value"
  }
}

///|
/// Classify whether retrying with a longer buffer could succeed.
pub fn ct_error_is_truncated(err : CtError) -> Bool {
  match err {
    Truncated => true
    _ => false
  }
}
