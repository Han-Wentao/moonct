///|
/// Cursor over an immutable byte array.
pub struct ByteReader {
  data : Array[Int32]
  mut offset : Int32
}

///|
/// Growing big-endian byte sink.
pub struct ByteWriter {
  data : Array[Int32]
}

///|
/// Create a reader positioned at the first byte.
pub fn new_byte_reader(data : Array[Int32]) -> ByteReader {
  { data: bytes_copy(data), offset: 0, }
}

///|
/// Create an empty writer.
pub fn new_byte_writer() -> ByteWriter {
  { data: Array(capacity=32), }
}

///|
/// Bytes still available to the reader.
pub fn ByteReader::remaining(self : Self) -> Int32 {
  self.data.length() - self.offset
}

///|
/// Absolute position, useful for bounded extension vectors.
pub fn ByteReader::position(self : Self) -> Int32 {
  self.offset
}

///|
/// Move the cursor backward after a speculative parse.
pub fn ByteReader::rewind_to(
  self : Self,
  position : Int32,
) -> Result[Unit, CtError] {
  if position < 0 || position > self.data.length() || position > self.offset {
    Err(CtError::BadLength)
  } else {
    self.offset = position
    Ok(())
  }
}

///|
pub fn ByteReader::read_u8(self : Self) -> Result[Int32, CtError] {
  if self.offset >= self.data.length() {
    Err(CtError::Truncated)
  } else {
    let value = self.data[self.offset]
    self.offset = self.offset + 1
    if value < 0 || value > 255 {
      Err(CtError::BadByte)
    } else {
      Ok(value)
    }
  }
}

///|
pub fn ByteReader::read_u16(self : Self) -> Result[Int32, CtError] {
  match self.read_u8() {
    Err(err) => Err(err)
    Ok(hi) =>
      match self.read_u8() {
        Err(err) => Err(err)
        Ok(lo) => Ok(hi * 256 + lo)
      }
  }
}

///|
pub fn ByteReader::read_u24(self : Self) -> Result[Int32, CtError] {
  match self.read_u16() {
    Err(err) => Err(err)
    Ok(hi) =>
      match self.read_u8() {
        Err(err) => Err(err)
        Ok(lo) => Ok(hi * 256 + lo)
      }
  }
}

///|
fn shift_byte(value : UInt64, byte : Int32) -> UInt64 {
  (value << 8) + byte.to_uint64()
}

///|
pub fn ByteReader::read_u64(self : Self) -> Result[UInt64, CtError] {
  let mut value = 0UL
  let mut valid : Result[Unit, CtError] = Ok(())
  for _ in 0..<8 {
    match valid {
      Err(_) => ()
      Ok(_) =>
        match self.read_u8() {
          Err(err) => valid = Err(err)
          Ok(byte) => value = shift_byte(value, byte)
        }
    }
  }
  match valid {
    Err(err) => Err(err)
    Ok(_) => Ok(value)
  }
}

///|
pub fn ByteReader::read_uint(
  self : Self,
  width : Int32,
) -> Result[Int32, CtError] {
  if width == 1 {
    self.read_u8()
  } else if width == 2 {
    self.read_u16()
  } else if width == 3 {
    self.read_u24()
  } else {
    Err(CtError::Unsupported)
  }
}

///|
pub fn ByteReader::read_bytes(
  self : Self,
  count : Int32,
) -> Result[Array[Int32], CtError] {
  if count < 0 {
    Err(CtError::BadLength)
  } else if self.remaining() < count {
    Err(CtError::Truncated)
  } else {
    let out = Array(capacity=count)
    let mut valid = true
    for i in 0..<count {
      let value = self.data[self.offset + i]
      if value < 0 || value > 255 {
        valid = false
      }
      out.push(value)
    }
    self.offset = self.offset + count
    if valid {
      Ok(out)
    } else {
      Err(CtError::BadByte)
    }
  }
}

///|
/// Read a TLS opaque vector whose length prefix is `width` bytes.
pub fn ByteReader::read_opaque(
  self : Self,
  width : Int32,
  min_len : Int32,
  max_len : Int32,
) -> Result[Array[Int32], CtError] {
  match self.read_uint(width) {
    Err(err) => Err(err)
    Ok(length) =>
      if length < min_len || length > max_len {
        Err(CtError::BadLength)
      } else {
        self.read_bytes(length)
      }
  }
}

///|
pub fn ByteReader::is_exhausted(self : Self) -> Bool {
  self.offset == self.data.length()
}

///|
pub fn ByteReader::expect_exhausted(self : Self) -> Result[Unit, CtError] {
  if self.is_exhausted() {
    Ok(())
  } else {
    Err(CtError::BadLength)
  }
}

///|
pub fn ByteWriter::write_u8(
  self : Self,
  value : Int32,
) -> Result[Unit, CtError] {
  if value < 0 || value > 255 {
    Err(CtError::BadByte)
  } else {
    self.data.push(value)
    Ok(())
  }
}

///|
pub fn ByteWriter::write_u16(
  self : Self,
  value : Int32,
) -> Result[Unit, CtError] {
  if value < 0 || value > 65535 {
    Err(CtError::Overflow)
  } else {
    match self.write_u8(value / 256) {
      Err(err) => Err(err)
      Ok(_) => self.write_u8(value % 256)
    }
  }
}

///|
pub fn ByteWriter::write_u24(
  self : Self,
  value : Int32,
) -> Result[Unit, CtError] {
  if value < 0 || value > 16777215 {
    Err(CtError::Overflow)
  } else {
    match self.write_u16(value / 256) {
      Err(err) => Err(err)
      Ok(_) => self.write_u8(value % 256)
    }
  }
}

///|
pub fn ByteWriter::write_u64(
  self : Self,
  value : UInt64,
) -> Result[Unit, CtError] {
  let mut valid : Result[Unit, CtError] = Ok(())
  for i in 0..<8 {
    match valid {
      Err(_) => ()
      Ok(_) => {
        let shift = (7 - i) * 8
        let byte = ((value >> shift) & 0xFFUL).to_int()
        valid = self.write_u8(byte)
      }
    }
  }
  valid
}

///|
pub fn ByteWriter::write_uint(
  self : Self,
  width : Int32,
  value : Int32,
) -> Result[Unit, CtError] {
  if width == 1 {
    self.write_u8(value)
  } else if width == 2 {
    self.write_u16(value)
  } else if width == 3 {
    self.write_u24(value)
  } else {
    Err(CtError::Unsupported)
  }
}

///|
pub fn ByteWriter::write_bytes(
  self : Self,
  data : Array[Int32],
) -> Result[Unit, CtError] {
  if !bytes_in_range(data) {
    Err(CtError::BadByte)
  } else {
    for i in 0..<data.length() {
      self.data.push(data[i])
    }
    Ok(())
  }
}

///|
pub fn ByteWriter::write_opaque(
  self : Self,
  width : Int32,
  data : Array[Int32],
  min_len : Int32,
  max_len : Int32,
) -> Result[Unit, CtError] {
  if min_len < 0 ||
    max_len < min_len ||
    data.length() < min_len ||
    data.length() > max_len {
    Err(CtError::BadLength)
  } else if !bytes_in_range(data) {
    Err(CtError::BadByte)
  } else {
    match self.write_uint(width, data.length()) {
      Err(err) => Err(err)
      Ok(_) => self.write_bytes(data)
    }
  }
}

///|
/// Copy the bytes written so far.
pub fn ByteWriter::bytes(self : Self) -> Array[Int32] {
  bytes_copy(self.data)
}

///|
pub fn ByteWriter::length(self : Self) -> Int32 {
  self.data.length()
}

///|
fn ct_u16_max() -> Int32 {
  65535
}

///|
fn ct_u24_max() -> Int32 {
  16777215
}

///|
/// A writer that keeps the first framing error instead of threading Result
/// through every field. Later puts become no-ops.
pub struct WriteGate {
  writer : ByteWriter
  mut failed : CtError?
}

///|
pub fn new_write_gate() -> WriteGate {
  { writer: new_byte_writer(), failed: None, }
}

///|
fn WriteGate::note(self : Self, result : Result[Unit, CtError]) -> Unit {
  match self.failed {
    Some(_) => ()
    None =>
      match result {
        Ok(_) => ()
        Err(err) => self.failed = Some(err)
      }
  }
}

///|
pub fn WriteGate::put_u8(self : Self, value : Int32) -> Unit {
  match self.failed {
    Some(_) => ()
    None => self.note(self.writer.write_u8(value))
  }
}

///|
pub fn WriteGate::put_u16(self : Self, value : Int32) -> Unit {
  match self.failed {
    Some(_) => ()
    None => self.note(self.writer.write_u16(value))
  }
}

///|
pub fn WriteGate::put_u24(self : Self, value : Int32) -> Unit {
  match self.failed {
    Some(_) => ()
    None => self.note(self.writer.write_u24(value))
  }
}

///|
pub fn WriteGate::put_u64(self : Self, value : UInt64) -> Unit {
  match self.failed {
    Some(_) => ()
    None => self.note(self.writer.write_u64(value))
  }
}

///|
pub fn WriteGate::put_bytes(self : Self, data : Array[Int32]) -> Unit {
  match self.failed {
    Some(_) => ()
    None => self.note(self.writer.write_bytes(data))
  }
}

///|
pub fn WriteGate::put_opaque(
  self : Self,
  width : Int32,
  data : Array[Int32],
  min_len : Int32,
  max_len : Int32,
) -> Unit {
  match self.failed {
    Some(_) => ()
    None => self.note(self.writer.write_opaque(width, data, min_len, max_len))
  }
}

///|
/// Return the framed bytes, or the first error recorded by a put.
pub fn WriteGate::finish(self : Self) -> Result[Array[Int32], CtError] {
  match self.failed {
    Some(err) => Err(err)
    None => Ok(self.writer.bytes())
  }
}
