///|
/// Copy bytes so callers cannot alias a writer or log buffer.
pub fn bytes_copy(data : Array[Int]) -> Array[Int] {
  let out = Array(capacity=data.length())
  for i in 0..<data.length() {
    out.push(data[i])
  }
  out
}

///|
/// Report whether two byte arrays are the same length and contents.
pub fn bytes_equal(left : Array[Int], right : Array[Int]) -> Bool {
  if left.length() != right.length() {
    false
  } else {
    let mut same = true
    let mut i = 0
    while i < left.length() && same {
      if left[i] != right[i] {
        same = false
      }
      i = i + 1
    }
    same
  }
}

///|
/// Return true when every element is an unsigned byte.
pub fn bytes_in_range(data : Array[Int]) -> Bool {
  let mut valid = true
  let mut i = 0
  while i < data.length() && valid {
    if data[i] < 0 || data[i] > 255 {
      valid = false
    }
    i = i + 1
  }
  valid
}

///|
/// Copy an inclusive-exclusive slice.
pub fn bytes_slice(
  data : Array[Int],
  start : Int,
  end : Int,
) -> Result[Array[Int], CtError] {
  if start < 0 || end < start || end > data.length() {
    Err(CtError::BadLength)
  } else {
    let out = Array(capacity=end - start)
    for i in start..<end {
      out.push(data[i])
    }
    Ok(out)
  }
}

///|
/// Concatenate two byte arrays.
pub fn bytes_concat(left : Array[Int], right : Array[Int]) -> Array[Int] {
  let out = Array(capacity=left.length() + right.length())
  for i in 0..<left.length() {
    out.push(left[i])
  }
  for i in 0..<right.length() {
    out.push(right[i])
  }
  out
}

///|
/// Concatenate a list of byte arrays in order.
pub fn bytes_concat_all(parts : Array[Array[Int]]) -> Array[Int] {
  let mut total = 0
  for i in 0..<parts.length() {
    total = total + parts[i].length()
  }
  let out = Array(capacity=total)
  for i in 0..<parts.length() {
    let part = parts[i]
    for j in 0..<part.length() {
      out.push(part[j])
    }
  }
  out
}

///|
/// Report whether `data` begins with `prefix`.
pub fn bytes_has_prefix(data : Array[Int], prefix : Array[Int]) -> Bool {
  if prefix.length() > data.length() {
    false
  } else {
    let mut same = true
    let mut i = 0
    while i < prefix.length() && same {
      if data[i] != prefix[i] {
        same = false
      }
      i = i + 1
    }
    same
  }
}

///|
fn hex_nibble(value : Int) -> Char {
  if value < 10 {
    (48 + value).unsafe_to_char()
  } else {
    (87 + value).unsafe_to_char()
  }
}

///|
fn hex_value(ch : Char) -> Int? {
  let code = ch.to_int()
  if code >= 48 && code <= 57 {
    Some(code - 48)
  } else if code >= 97 && code <= 102 {
    Some(code - 87)
  } else if code >= 65 && code <= 70 {
    Some(code - 55)
  } else {
    None
  }
}

///|
/// Encode bytes as lowercase hexadecimal.
pub fn hex_encode(data : Array[Int]) -> Result[String, CtError] {
  if !bytes_in_range(data) {
    Err(CtError::BadByte)
  } else {
    let buf = StringBuilder()
    for i in 0..<data.length() {
      let value = data[i]
      buf.write_char(hex_nibble(value / 16))
      buf.write_char(hex_nibble(value % 16))
    }
    Ok(buf.to_string())
  }
}

///|
/// Decode lowercase or uppercase hexadecimal. Odd lengths are rejected.
pub fn hex_decode(text : String) -> Result[Array[Int], CtError] {
  if text.length() % 2 != 0 {
    Err(CtError::BadLength)
  } else {
    let out = Array(capacity=text.length() / 2)
    let mut valid = true
    let mut i = 0
    while i < text.length() && valid {
      match (text.get_char(i), text.get_char(i + 1)) {
        (Some(hi), Some(lo)) =>
          match (hex_value(hi), hex_value(lo)) {
            (Some(high), Some(low)) => out.push(high * 16 + low)
            _ => valid = false
          }
        _ => valid = false
      }
      i = i + 2
    }
    if valid {
      Ok(out)
    } else {
      Err(CtError::BadByte)
    }
  }
}

///|
fn base64_alphabet() -> String {
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
}

///|
fn base64_value(ch : Char) -> Int? {
  let alphabet = base64_alphabet()
  let mut found : Int? = None
  let mut i = 0
  while i < alphabet.length() && found is None {
    if alphabet.get_char(i).unwrap() == ch {
      found = Some(i)
    }
    i = i + 1
  }
  found
}

///|
/// Encode bytes with standard padded base64.
pub fn base64_encode(data : Array[Int]) -> Result[String, CtError] {
  if !bytes_in_range(data) {
    Err(CtError::BadByte)
  } else {
    let alphabet = base64_alphabet()
    let buf = StringBuilder()
    let mut i = 0
    while i + 3 <= data.length() {
      let block = data[i] * 65536 + data[i + 1] * 256 + data[i + 2]
      buf.write_char(alphabet.get_char(block / 262144 % 64).unwrap())
      buf.write_char(alphabet.get_char(block / 4096 % 64).unwrap())
      buf.write_char(alphabet.get_char(block / 64 % 64).unwrap())
      buf.write_char(alphabet.get_char(block % 64).unwrap())
      i = i + 3
    }
    let rest = data.length() - i
    if rest == 1 {
      let block = data[i] * 65536
      buf.write_char(alphabet.get_char(block / 262144 % 64).unwrap())
      buf.write_char(alphabet.get_char(block / 4096 % 64).unwrap())
      buf.write_char('=')
      buf.write_char('=')
    } else if rest == 2 {
      let block = data[i] * 65536 + data[i + 1] * 256
      buf.write_char(alphabet.get_char(block / 262144 % 64).unwrap())
      buf.write_char(alphabet.get_char(block / 4096 % 64).unwrap())
      buf.write_char(alphabet.get_char(block / 64 % 64).unwrap())
      buf.write_char('=')
    }
    Ok(buf.to_string())
  }
}

///|
fn base64_unused_bits_clear(block : Int, padding : Int) -> Bool {
  if padding == 1 {
    block / 64 % 4 == 0
  } else if padding == 2 {
    block / 4096 % 16 == 0
  } else {
    true
  }
}

///|
/// Decode standard padded base64 and reject non-canonical padding bits.
pub fn base64_decode(text : String) -> Result[Array[Int], CtError] {
  if text.length() == 0 {
    Ok([])
  } else if text.length() % 4 != 0 {
    Err(CtError::BadLength)
  } else {
    let mut padding = 0
    if text.get_char(text.length() - 1).unwrap() == '=' {
      padding = 1
      if text.get_char(text.length() - 2).unwrap() == '=' {
        padding = 2
      }
    }
    let mut early_pad = false
    let mut i = 0
    while i < text.length() - padding {
      if text.get_char(i).unwrap() == '=' {
        early_pad = true
      }
      i = i + 1
    }
    if early_pad {
      Err(CtError::BadByte)
    } else {
      let out = Array(capacity=text.length() / 4 * 3 - padding)
      let mut valid = true
      let mut pos = 0
      while pos < text.length() && valid {
        let c0 = text.get_char(pos).unwrap()
        let c1 = text.get_char(pos + 1).unwrap()
        let c2 = text.get_char(pos + 2).unwrap()
        let c3 = text.get_char(pos + 3).unwrap()
        let pad_here = if pos + 4 == text.length() { padding } else { 0 }
        match (base64_value(c0), base64_value(c1)) {
          (Some(v0), Some(v1)) => {
            let mut v2 = 0
            let mut v3 = 0
            if pad_here < 2 {
              match base64_value(c2) {
                Some(value) => v2 = value
                None => valid = false
              }
            } else if c2 != '=' {
              valid = false
            }
            if pad_here < 1 {
              match base64_value(c3) {
                Some(value) => v3 = value
                None => valid = false
              }
            } else if c3 != '=' {
              valid = false
            }
            if valid {
              let block = v0 * 262144 + v1 * 4096 + v2 * 64 + v3
              if !base64_unused_bits_clear(block, pad_here) {
                valid = false
              } else {
                out.push(block / 65536 % 256)
                if pad_here < 2 {
                  out.push(block / 256 % 256)
                }
                if pad_here < 1 {
                  out.push(block % 256)
                }
              }
            }
          }
          _ => valid = false
        }
        pos = pos + 4
      }
      if valid {
        Ok(out)
      } else {
        Err(CtError::BadByte)
      }
    }
  }
}
