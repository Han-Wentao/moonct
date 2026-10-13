///|
/// One field of a CT JSON object. Duplicate keys are rejected.
pub struct JsonField {
  key : String
  value : CtJson
}

///|
/// Restricted JSON value used by RFC 6962 CT messages.
pub enum CtJson {
  JsonNull
  JsonBool(Bool)
  JsonNumber(String)
  JsonString(String)
  JsonArray(Array[CtJson])
  JsonObject(Array[JsonField])
}

///|
priv struct JsonCursor {
  text : String
  mut at : Int32
}

///|
fn JsonCursor::ended(self : Self) -> Bool {
  self.at >= self.text.length()
}

///|
fn JsonCursor::peek(self : Self) -> Char? {
  if self.ended() {
    None
  } else {
    self.text.get_char(self.at)
  }
}

///|
fn JsonCursor::bump(self : Self) -> Unit {
  self.at = self.at + 1
}

///|
fn json_space(ch : Char) -> Bool {
  ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r'
}

///|
fn json_digit(ch : Char) -> Bool {
  let code = ch.to_int()
  code >= 48 && code <= 57
}

///|
fn json_word_char(ch : Char) -> Bool {
  let code = ch.to_int()
  json_digit(ch) ||
  (code >= 65 && code <= 90) ||
  (code >= 97 && code <= 122) ||
  ch == '_'
}

///|
fn JsonCursor::skip_ws(self : Self) -> Unit {
  let mut moving = true
  while moving {
    match self.peek() {
      Some(ch) => if json_space(ch) { self.bump() } else { moving = false }
      None => moving = false
    }
  }
}

///|
fn u64_push_digit(acc : UInt64, digit : Int32) -> Result[UInt64, CtError] {
  let limit = 0x1999999999999999UL
  let max = 0xFFFFFFFFFFFFFFFFUL
  if digit < 0 || digit > 9 {
    Err(CtError::BadJson("digit"))
  } else if acc > limit {
    Err(CtError::Overflow)
  } else {
    let scaled = acc * 10UL
    let part = digit.to_uint64()
    if part > max - scaled {
      Err(CtError::Overflow)
    } else {
      Ok(scaled + part)
    }
  }
}

///|
fn parse_u64_text(text : String) -> Result[UInt64, CtError] {
  if text.length() == 0 {
    Err(CtError::BadJson("number"))
  } else if text.length() > 1 && text.get_char(0).unwrap() == '0' {
    Err(CtError::BadJson("leading zero"))
  } else {
    let mut acc = 0UL
    let mut failed : CtError? = None
    let mut i = 0
    while i < text.length() && failed is None {
      match text.get_char(i) {
        None => failed = Some(CtError::BadJson("number"))
        Some(ch) =>
          if !json_digit(ch) {
            failed = Some(CtError::BadJson("number"))
          } else {
            match u64_push_digit(acc, ch.to_int() - 48) {
              Err(err) => failed = Some(err)
              Ok(next) => acc = next
            }
          }
      }
      i = i + 1
    }
    match failed {
      Some(err) => Err(err)
      None => Ok(acc)
    }
  }
}

///|
fn JsonCursor::consume_word(
  self : Self,
  word : String,
) -> Result[Unit, CtError] {
  let mut i = 0
  let mut failed = false
  while i < word.length() && !failed {
    match (self.peek(), word.get_char(i)) {
      (Some(got), Some(want)) =>
        if got == want {
          self.bump()
        } else {
          failed = true
        }
      _ => failed = true
    }
    i = i + 1
  }
  if failed {
    Err(CtError::BadJson("literal"))
  } else {
    match self.peek() {
      Some(ch) =>
        if json_word_char(ch) {
          Err(CtError::BadJson("literal"))
        } else {
          Ok(())
        }
      None => Ok(())
    }
  }
}

///|
fn JsonCursor::parse_hex4(self : Self) -> Result[Char, CtError] {
  let mut code = 0
  let mut i = 0
  let mut failed = false
  while i < 4 && !failed {
    match self.peek() {
      None => failed = true
      Some(ch) =>
        match hex_value(ch) {
          None => failed = true
          Some(nibble) => {
            code = code * 16 + nibble
            self.bump()
          }
        }
    }
    i = i + 1
  }
  if failed {
    Err(CtError::BadJson("unicode"))
  } else if code >= 0xD800 && code <= 0xDFFF {
    Err(CtError::BadJson("surrogate"))
  } else {
    match code.to_char() {
      Some(ch) => Ok(ch)
      None => Err(CtError::BadJson("unicode"))
    }
  }
}

///|
fn JsonCursor::parse_escape(self : Self) -> Result[Char, CtError] {
  match self.peek() {
    None => Err(CtError::BadJson("escape"))
    Some(ch) => {
      self.bump()
      if ch == '"' || ch == '\\' || ch == '/' {
        Ok(ch)
      } else if ch == 'b' {
        Ok('\u{0008}')
      } else if ch == 'f' {
        Ok('\u{000c}')
      } else if ch == 'n' {
        Ok('\n')
      } else if ch == 'r' {
        Ok('\r')
      } else if ch == 't' {
        Ok('\t')
      } else if ch == 'u' {
        self.parse_hex4()
      } else {
        Err(CtError::BadJson("escape"))
      }
    }
  }
}

///|
fn JsonCursor::parse_string(self : Self) -> Result[String, CtError] {
  match self.peek() {
    Some('"') => self.bump()
    _ => return Err(CtError::BadJson("string"))
  }
  let buf = StringBuilder()
  let mut failed : CtError? = None
  let mut closed = false
  while !closed && failed is None {
    match self.peek() {
      None => failed = Some(CtError::BadJson("unterminated string"))
      Some('"') => {
        self.bump()
        closed = true
      }
      Some('\\') => {
        self.bump()
        match self.parse_escape() {
          Err(err) => failed = Some(err)
          Ok(ch) => buf.write_char(ch)
        }
      }
      Some(ch) =>
        if ch.to_int() < 32 {
          failed = Some(CtError::BadJson("control character"))
        } else {
          self.bump()
          buf.write_char(ch)
        }
    }
  }
  match failed {
    Some(err) => Err(err)
    None => Ok(buf.to_string())
  }
}

///|
fn JsonCursor::parse_number(self : Self) -> Result[CtJson, CtError] {
  match self.peek() {
    Some('0') => {
      self.bump()
      match self.peek() {
        Some(ch) =>
          if json_digit(ch) {
            Err(CtError::BadJson("leading zero"))
          } else if ch == '.' || ch == 'e' || ch == 'E' {
            Err(CtError::BadJson("unsigned integer only"))
          } else {
            Ok(CtJson::JsonNumber("0"))
          }
        None => Ok(CtJson::JsonNumber("0"))
      }
    }
    Some(ch) =>
      if !json_digit(ch) {
        Err(CtError::BadJson("number"))
      } else {
        let buf = StringBuilder()
        let mut acc = 0UL
        let mut failed : CtError? = None
        let mut reading = true
        while reading && failed is None {
          match self.peek() {
            Some(digit) =>
              if json_digit(digit) {
                buf.write_char(digit)
                self.bump()
                match u64_push_digit(acc, digit.to_int() - 48) {
                  Err(err) => failed = Some(err)
                  Ok(next) => acc = next
                }
              } else {
                reading = false
              }
            None => reading = false
          }
        }
        if failed is None {
          match self.peek() {
            Some(next) =>
              if next == '.' ||
                next == 'e' ||
                next == 'E' ||
                next == '+' ||
                next == '-' {
                failed = Some(CtError::BadJson("unsigned integer only"))
              }
            None => ()
          }
        }
        match failed {
          Some(err) => Err(err)
          None => Ok(CtJson::JsonNumber(buf.to_string()))
        }
      }
    None => Err(CtError::BadJson("number"))
  }
}

///|
fn JsonCursor::parse_array(self : Self) -> Result[CtJson, CtError] {
  self.bump()
  let items : Array[CtJson] = Array(capacity=4)
  self.skip_ws()
  match self.peek() {
    Some(']') => {
      self.bump()
      Ok(CtJson::JsonArray(items))
    }
    _ => {
      let mut failed : CtError? = None
      let mut closed = false
      while !closed && failed is None {
        match self.parse_value() {
          Err(err) => failed = Some(err)
          Ok(value) => {
            items.push(value)
            self.skip_ws()
            match self.peek() {
              Some(',') => {
                self.bump()
                self.skip_ws()
                match self.peek() {
                  Some(']') => failed = Some(CtError::BadJson("trailing comma"))
                  _ => ()
                }
              }
              Some(']') => {
                self.bump()
                closed = true
              }
              _ => failed = Some(CtError::BadJson("array"))
            }
          }
        }
      }
      match failed {
        Some(err) => Err(err)
        None => Ok(CtJson::JsonArray(items))
      }
    }
  }
}

///|
fn json_key_seen(keys : Array[String], key : String) -> Bool {
  let mut seen = false
  let mut i = 0
  while i < keys.length() && !seen {
    if keys[i] == key {
      seen = true
    }
    i = i + 1
  }
  seen
}

///|
fn JsonCursor::parse_object(self : Self) -> Result[CtJson, CtError] {
  self.bump()
  let fields : Array[JsonField] = Array(capacity=4)
  let keys : Array[String] = Array(capacity=4)
  self.skip_ws()
  match self.peek() {
    Some('}') => {
      self.bump()
      Ok(CtJson::JsonObject(fields))
    }
    _ => {
      let mut failed : CtError? = None
      let mut closed = false
      while !closed && failed is None {
        match self.parse_string() {
          Err(err) => failed = Some(err)
          Ok(key) =>
            if json_key_seen(keys, key) {
              failed = Some(CtError::Duplicate)
            } else {
              keys.push(key)
              self.skip_ws()
              match self.peek() {
                Some(':') => {
                  self.bump()
                  self.skip_ws()
                  match self.parse_value() {
                    Err(err) => failed = Some(err)
                    Ok(value) => {
                      fields.push({ key, value, })
                      self.skip_ws()
                      match self.peek() {
                        Some(',') => {
                          self.bump()
                          self.skip_ws()
                          match self.peek() {
                            Some('}') =>
                              failed = Some(CtError::BadJson("trailing comma"))
                            _ => ()
                          }
                        }
                        Some('}') => {
                          self.bump()
                          closed = true
                        }
                        _ => failed = Some(CtError::BadJson("object"))
                      }
                    }
                  }
                }
                _ => failed = Some(CtError::BadJson("object"))
              }
            }
        }
      }
      match failed {
        Some(err) => Err(err)
        None => Ok(CtJson::JsonObject(fields))
      }
    }
  }
}

///|
fn JsonCursor::parse_value(self : Self) -> Result[CtJson, CtError] {
  match self.peek() {
    None => Err(CtError::BadJson("unexpected end"))
    Some('n') =>
      match self.consume_word("null") {
        Err(err) => Err(err)
        Ok(_) => Ok(CtJson::JsonNull)
      }
    Some('t') =>
      match self.consume_word("true") {
        Err(err) => Err(err)
        Ok(_) => Ok(CtJson::JsonBool(true))
      }
    Some('f') =>
      match self.consume_word("false") {
        Err(err) => Err(err)
        Ok(_) => Ok(CtJson::JsonBool(false))
      }
    Some('"') =>
      match self.parse_string() {
        Err(err) => Err(err)
        Ok(text) => Ok(CtJson::JsonString(text))
      }
    Some('[') => self.parse_array()
    Some('{') => self.parse_object()
    Some(ch) =>
      if json_digit(ch) {
        self.parse_number()
      } else {
        Err(CtError::BadJson("unexpected character"))
      }
  }
}

///|
/// Parse one JSON value. Empty and whitespace-only input is `EmptyInput`.
pub fn parse_ct_json(text : String) -> Result[CtJson, CtError] {
  if text.length() == 0 {
    Err(CtError::EmptyInput)
  } else {
    let cursor = { text, at: 0, }
    cursor.skip_ws()
    if cursor.ended() {
      Err(CtError::EmptyInput)
    } else {
      match cursor.parse_value() {
        Err(err) => Err(err)
        Ok(value) => {
          cursor.skip_ws()
          if cursor.ended() {
            Ok(value)
          } else {
            Err(CtError::BadJson("trailing data"))
          }
        }
      }
    }
  }
}

///|
fn append_u_escape(buf : StringBuilder, code : Int32) -> Unit {
  buf.write_string("\\u00")
  buf.write_char(hex_nibble(code / 16 % 16))
  buf.write_char(hex_nibble(code % 16))
}

///|
fn append_json_string(buf : StringBuilder, text : String) -> Unit {
  buf.write_char('"')
  for i in 0..<text.length() {
    let ch = text.get_char(i).unwrap()
    let code = ch.to_int()
    if ch == '"' || ch == '\\' {
      buf.write_char('\\')
      buf.write_char(ch)
    } else if ch == '\u{0008}' {
      buf.write_string("\\b")
    } else if ch == '\u{000c}' {
      buf.write_string("\\f")
    } else if ch == '\n' {
      buf.write_string("\\n")
    } else if ch == '\r' {
      buf.write_string("\\r")
    } else if ch == '\t' {
      buf.write_string("\\t")
    } else if code < 32 {
      append_u_escape(buf, code)
    } else {
      buf.write_char(ch)
    }
  }
  buf.write_char('"')
}

///|
fn write_json_into(
  buf : StringBuilder,
  value : CtJson,
) -> Result[Unit, CtError] {
  match value {
    JsonNull => {
      buf.write_string("null")
      Ok(())
    }
    JsonBool(flag) => {
      if flag {
        buf.write_string("true")
      } else {
        buf.write_string("false")
      }
      Ok(())
    }
    JsonNumber(text) =>
      match parse_u64_text(text) {
        Err(err) => Err(err)
        Ok(number) =>
          if number.to_string() != text {
            Err(CtError::BadJson("number"))
          } else {
            buf.write_string(text)
            Ok(())
          }
      }
    JsonString(text) => {
      append_json_string(buf, text)
      Ok(())
    }
    JsonArray(items) => {
      buf.write_char('[')
      let mut failed : CtError? = None
      for i in 0..<items.length() {
        if failed is None {
          if i > 0 {
            buf.write_char(',')
          }
          match write_json_into(buf, items[i]) {
            Err(err) => failed = Some(err)
            Ok(_) => ()
          }
        }
      }
      buf.write_char(']')
      match failed {
        Some(err) => Err(err)
        None => Ok(())
      }
    }
    JsonObject(fields) => {
      buf.write_char('{')
      let keys = Array(capacity=fields.length())
      let mut failed : CtError? = None
      for i in 0..<fields.length() {
        if failed is None {
          let field = fields[i]
          if json_key_seen(keys, field.key) {
            failed = Some(CtError::Duplicate)
          } else {
            keys.push(field.key)
            if i > 0 {
              buf.write_char(',')
            }
            append_json_string(buf, field.key)
            buf.write_char(':')
            match write_json_into(buf, field.value) {
              Err(err) => failed = Some(err)
              Ok(_) => ()
            }
          }
        }
      }
      buf.write_char('}')
      match failed {
        Some(err) => Err(err)
        None => Ok(())
      }
    }
  }
}

///|
/// Write compact JSON. Object keys stay in the given order.
pub fn write_ct_json(value : CtJson) -> Result[String, CtError] {
  let buf = StringBuilder()
  match write_json_into(buf, value) {
    Err(err) => Err(err)
    Ok(_) => Ok(buf.to_string())
  }
}

///|
pub struct SthMessage {
  tree_size : UInt64
  timestamp : UInt64
  sha256_root_hash : Hash
  tree_head_signature : Array[Int32]
}

///|
pub struct InclusionMessage {
  leaf_index : UInt64
  audit_path : Array[Hash]
}

///|
pub struct ConsistencyMessage {
  consistency : Array[Hash]
}

///|
fn require_object(value : CtJson) -> Result[Array[JsonField], CtError] {
  match value {
    JsonObject(fields) => Ok(fields)
    _ => Err(CtError::BadJson("object required"))
  }
}

///|
fn object_field(
  fields : Array[JsonField],
  key : String,
) -> Result[CtJson, CtError] {
  let mut found : CtJson? = None
  let mut duplicate = false
  for i in 0..<fields.length() {
    if fields[i].key == key {
      match found {
        Some(_) => duplicate = true
        None => found = Some(fields[i].value)
      }
    }
  }
  if duplicate {
    Err(CtError::Duplicate)
  } else {
    match found {
      Some(value) => Ok(value)
      None => Err(CtError::BadJson("missing " + key))
    }
  }
}

///|
fn reject_unknown_keys(
  fields : Array[JsonField],
  allowed : Array[String],
) -> Result[Unit, CtError] {
  let mut failed : CtError? = None
  for i in 0..<fields.length() {
    if failed is None {
      let mut known = false
      for j in 0..<allowed.length() {
        if allowed[j] == fields[i].key {
          known = true
        }
      }
      if !known {
        failed = Some(CtError::BadJson("unknown key"))
      }
    }
  }
  match failed {
    Some(err) => Err(err)
    None => Ok(())
  }
}

///|
fn json_u64(value : CtJson) -> Result[UInt64, CtError] {
  match value {
    JsonNumber(text) => parse_u64_text(text)
    _ => Err(CtError::BadJson("unsigned integer required"))
  }
}

///|
fn json_required_bytes(value : CtJson) -> Result[Array[Int32], CtError] {
  match value {
    JsonString(text) =>
      if text.length() == 0 {
        Err(CtError::EmptyInput)
      } else {
        match base64_decode(text) {
          Err(_) => Err(CtError::BadJson("base64"))
          Ok(bytes) =>
            if bytes.length() == 0 {
              Err(CtError::EmptyInput)
            } else {
              Ok(bytes)
            }
        }
      }
    _ => Err(CtError::BadJson("string required"))
  }
}

///|
fn json_hash(value : CtJson) -> Result[Hash, CtError] {
  match json_required_bytes(value) {
    Err(err) => Err(err)
    Ok(bytes) =>
      if !bytes_in_range(bytes) {
        Err(CtError::BadByte)
      } else if !is_valid_hash(bytes) {
        Err(CtError::BadHash)
      } else {
        Ok(bytes)
      }
  }
}

///|
fn json_hash_array(value : CtJson) -> Result[Array[Hash], CtError] {
  match value {
    JsonArray(items) => {
      let out = Array(capacity=items.length())
      let mut failed : CtError? = None
      for i in 0..<items.length() {
        if failed is None {
          match json_hash(items[i]) {
            Err(err) => failed = Some(err)
            Ok(hash) => out.push(hash)
          }
        }
      }
      match failed {
        Some(err) => Err(err)
        None => Ok(out)
      }
    }
    _ => Err(CtError::BadJson("array required"))
  }
}

///|
fn sth_from_json(value : CtJson) -> Result[SthMessage, CtError] {
  match require_object(value) {
    Err(err) => Err(err)
    Ok(fields) =>
      match
        reject_unknown_keys(fields, [
          "tree_size", "timestamp", "sha256_root_hash", "tree_head_signature",
        ]) {
        Err(err) => Err(err)
        Ok(_) =>
          match object_field(fields, "tree_size") {
            Err(err) => Err(err)
            Ok(tree_size) =>
              match json_u64(tree_size) {
                Err(err) => Err(err)
                Ok(size) =>
                  match object_field(fields, "timestamp") {
                    Err(err) => Err(err)
                    Ok(stamp) =>
                      match json_u64(stamp) {
                        Err(err) => Err(err)
                        Ok(timestamp) =>
                          match object_field(fields, "sha256_root_hash") {
                            Err(err) => Err(err)
                            Ok(root) =>
                              match json_hash(root) {
                                Err(err) => Err(err)
                                Ok(sha256_root_hash) =>
                                  match
                                    object_field(fields, "tree_head_signature") {
                                    Err(err) => Err(err)
                                    Ok(signature) =>
                                      match json_required_bytes(signature) {
                                        Err(err) => Err(err)
                                        Ok(tree_head_signature) =>
                                          Ok({
                                            tree_size: size,
                                            timestamp,
                                            sha256_root_hash,
                                            tree_head_signature,
                                          })
                                      }
                                  }
                              }
                          }
                      }
                  }
              }
          }
      }
  }
}

///|
pub fn decode_sth_message(text : String) -> Result[SthMessage, CtError] {
  match parse_ct_json(text) {
    Err(err) => Err(err)
    Ok(value) => sth_from_json(value)
  }
}

///|
fn hash_b64(hash : Hash) -> Result[String, CtError] {
  if !bytes_in_range(hash) {
    Err(CtError::BadByte)
  } else if !is_valid_hash(hash) {
    Err(CtError::BadHash)
  } else {
    base64_encode(hash)
  }
}

///|
fn bytes_b64(data : Array[Int32]) -> Result[String, CtError] {
  if !bytes_in_range(data) {
    Err(CtError::BadByte)
  } else if data.length() == 0 {
    Err(CtError::EmptyInput)
  } else {
    base64_encode(data)
  }
}

///|
pub fn encode_sth_message(message : SthMessage) -> Result[String, CtError] {
  match hash_b64(message.sha256_root_hash) {
    Err(err) => Err(err)
    Ok(root) =>
      match bytes_b64(message.tree_head_signature) {
        Err(err) => Err(err)
        Ok(signature) =>
          write_ct_json(
            CtJson::JsonObject([
              {
                key: "tree_size",
                value: CtJson::JsonNumber(message.tree_size.to_string()),
              },
              {
                key: "timestamp",
                value: CtJson::JsonNumber(message.timestamp.to_string()),
              },
              { key: "sha256_root_hash", value: CtJson::JsonString(root), },
              {
                key: "tree_head_signature",
                value: CtJson::JsonString(signature),
              },
            ]),
          )
      }
  }
}

///|
fn inclusion_from_json(value : CtJson) -> Result[InclusionMessage, CtError] {
  match require_object(value) {
    Err(err) => Err(err)
    Ok(fields) =>
      match reject_unknown_keys(fields, ["leaf_index", "audit_path"]) {
        Err(err) => Err(err)
        Ok(_) =>
          match object_field(fields, "leaf_index") {
            Err(err) => Err(err)
            Ok(index) =>
              match json_u64(index) {
                Err(err) => Err(err)
                Ok(leaf_index) =>
                  match object_field(fields, "audit_path") {
                    Err(err) => Err(err)
                    Ok(path) =>
                      match json_hash_array(path) {
                        Err(err) => Err(err)
                        Ok(audit_path) => Ok({ leaf_index, audit_path, })
                      }
                  }
              }
          }
      }
  }
}

///|
pub fn decode_inclusion_message(
  text : String,
) -> Result[InclusionMessage, CtError] {
  match parse_ct_json(text) {
    Err(err) => Err(err)
    Ok(value) => inclusion_from_json(value)
  }
}

///|
fn hash_array_json(hashes : Array[Hash]) -> Result[CtJson, CtError] {
  let items : Array[CtJson] = Array(capacity=hashes.length())
  let mut failed : CtError? = None
  for i in 0..<hashes.length() {
    if failed is None {
      match hash_b64(hashes[i]) {
        Err(err) => failed = Some(err)
        Ok(text) => items.push(CtJson::JsonString(text))
      }
    }
  }
  match failed {
    Some(err) => Err(err)
    None => Ok(CtJson::JsonArray(items))
  }
}

///|
pub fn encode_inclusion_message(
  message : InclusionMessage,
) -> Result[String, CtError] {
  match hash_array_json(message.audit_path) {
    Err(err) => Err(err)
    Ok(path) =>
      write_ct_json(
        CtJson::JsonObject([
          {
            key: "leaf_index",
            value: CtJson::JsonNumber(message.leaf_index.to_string()),
          },
          { key: "audit_path", value: path, },
        ]),
      )
  }
}

///|
fn consistency_from_json(value : CtJson) -> Result[ConsistencyMessage, CtError] {
  match require_object(value) {
    Err(err) => Err(err)
    Ok(fields) =>
      match reject_unknown_keys(fields, ["consistency"]) {
        Err(err) => Err(err)
        Ok(_) =>
          match object_field(fields, "consistency") {
            Err(err) => Err(err)
            Ok(path) =>
              match json_hash_array(path) {
                Err(err) => Err(err)
                Ok(consistency) => Ok({ consistency, })
              }
          }
      }
  }
}

///|
pub fn decode_consistency_message(
  text : String,
) -> Result[ConsistencyMessage, CtError] {
  match parse_ct_json(text) {
    Err(err) => Err(err)
    Ok(value) => consistency_from_json(value)
  }
}

///|
pub fn encode_consistency_message(
  message : ConsistencyMessage,
) -> Result[String, CtError] {
  match hash_array_json(message.consistency) {
    Err(err) => Err(err)
    Ok(path) =>
      write_ct_json(CtJson::JsonObject([{ key: "consistency", value: path, }]))
  }
}
