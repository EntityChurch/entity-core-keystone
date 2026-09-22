//! A minimal JSON reader for the keystone seed-policy file format
//! (`protocol-generator/shared/seed-policy/`).
//!
//! Hand-rolled for the same reason the codec, base58 and base64 are: dep-minimization
//! (the crate closure is `ed25519-dalek` + `sha2`, and a `serde_json` closure would be
//! larger than the peer). It reads RFC 8259 JSON with two deliberate restrictions,
//! both of which fail loudly rather than approximate:
//!
//! - **numbers must be integers** that fit `u64` or `i64`. A seed policy has no use for
//!   a float, and silently rounding one into a grant would be a policy nobody wrote;
//! - **duplicate object keys are refused.** RFC 8259 leaves them undefined, and "last
//!   one wins" in a policy file is an authorization decision made by accident.

/// A parsed JSON value. Objects keep document order.
#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    UInt(u64),
    Int(i64),
    Str(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(kvs) => kvs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
}

const MAX_DEPTH: usize = 64;

/// Parse a complete JSON document. The error carries the byte offset.
pub fn parse(text: &str) -> Result<Json, String> {
    let mut p = Parser {
        b: text.as_bytes(),
        i: 0,
    };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i != p.b.len() {
        return Err(p.err("trailing characters after the JSON value"));
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn err(&self, msg: &str) -> String {
        format!("JSON: {msg} at byte {}", self.i)
    }

    fn ws(&mut self) {
        while let Some(&c) = self.b.get(self.i) {
            if matches!(c, b' ' | b'\t' | b'\n' | b'\r') {
                self.i += 1;
            } else {
                break;
            }
        }
    }

    fn eat(&mut self, lit: &str) -> bool {
        if self.b[self.i..].starts_with(lit.as_bytes()) {
            self.i += lit.len();
            true
        } else {
            false
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, String> {
        if depth > MAX_DEPTH {
            return Err(self.err("nesting too deep"));
        }
        match self.b.get(self.i) {
            None => Err(self.err("unexpected end of input")),
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b't') if self.eat("true") => Ok(Json::Bool(true)),
            Some(b'f') if self.eat("false") => Ok(Json::Bool(false)),
            Some(b'n') if self.eat("null") => Ok(Json::Null),
            Some(c) if *c == b'-' || c.is_ascii_digit() => self.number(),
            Some(_) => Err(self.err("unexpected character")),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, String> {
        self.i += 1; // {
        let mut kvs: Vec<(String, Json)> = vec![];
        self.ws();
        if self.b.get(self.i) == Some(&b'}') {
            self.i += 1;
            return Ok(Json::Object(kvs));
        }
        loop {
            self.ws();
            if self.b.get(self.i) != Some(&b'"') {
                return Err(self.err("expected an object key"));
            }
            let k = self.string()?;
            if kvs.iter().any(|(e, _)| *e == k) {
                return Err(self.err(&format!("duplicate object key \"{k}\"")));
            }
            self.ws();
            if self.b.get(self.i) != Some(&b':') {
                return Err(self.err("expected ':'"));
            }
            self.i += 1;
            self.ws();
            let v = self.value(depth + 1)?;
            kvs.push((k, v));
            self.ws();
            match self.b.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Json::Object(kvs));
                }
                _ => return Err(self.err("expected ',' or '}'")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json, String> {
        self.i += 1; // [
        let mut items = vec![];
        self.ws();
        if self.b.get(self.i) == Some(&b']') {
            self.i += 1;
            return Ok(Json::Array(items));
        }
        loop {
            self.ws();
            items.push(self.value(depth + 1)?);
            self.ws();
            match self.b.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(Json::Array(items));
                }
                _ => return Err(self.err("expected ',' or ']'")),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let s = self
            .b
            .get(self.i..self.i + 4)
            .ok_or_else(|| self.err("truncated \\u escape"))?;
        let s = std::str::from_utf8(s).map_err(|_| self.err("bad \\u escape"))?;
        let v = u32::from_str_radix(s, 16).map_err(|_| self.err("bad \\u escape"))?;
        self.i += 4;
        Ok(v)
    }

    fn string(&mut self) -> Result<String, String> {
        self.i += 1; // opening quote
        let mut out: Vec<u8> = vec![];
        loop {
            let c = *self
                .b
                .get(self.i)
                .ok_or_else(|| self.err("unterminated string"))?;
            self.i += 1;
            match c {
                b'"' => {
                    return String::from_utf8(out).map_err(|_| self.err("string is not UTF-8"))
                }
                b'\\' => {
                    let e = *self
                        .b
                        .get(self.i)
                        .ok_or_else(|| self.err("unterminated escape"))?;
                    self.i += 1;
                    let ch = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                if !self.eat("\\u") {
                                    return Err(self.err("unpaired surrogate"));
                                }
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(self.err("unpaired surrogate"));
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else {
                                hi
                            };
                            char::from_u32(cp).ok_or_else(|| self.err("invalid code point"))?
                        }
                        _ => return Err(self.err("invalid escape")),
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                c if c < 0x20 => return Err(self.err("control character in string")),
                c => out.push(c),
            }
        }
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.i;
        if self.b.get(self.i) == Some(&b'-') {
            self.i += 1;
        }
        while matches!(self.b.get(self.i), Some(c) if c.is_ascii_digit()) {
            self.i += 1;
        }
        if matches!(self.b.get(self.i), Some(b'.' | b'e' | b'E')) {
            return Err(self.err("only integer numbers are accepted"));
        }
        let s = std::str::from_utf8(&self.b[start..self.i]).unwrap_or("");
        if s == "-" || s.is_empty() {
            return Err(self.err("malformed number"));
        }
        if s.starts_with('-') {
            s.parse::<i64>()
                .map(Json::Int)
                .map_err(|_| self.err("integer out of range"))
        } else {
            s.parse::<u64>()
                .map(Json::UInt)
                .map_err(|_| self.err("integer out of range"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_document_in_order() {
        let v = parse(r#"{"b": [1, -2, "xé😀"], "a": {"t": true, "n": null}}"#)
            .unwrap();
        match &v {
            Json::Object(kvs) => assert_eq!(kvs[0].0, "b"),
            _ => panic!("not an object"),
        }
        assert_eq!(
            v.get("b"),
            Some(&Json::Array(vec![
                Json::UInt(1),
                Json::Int(-2),
                Json::Str("xé😀".into())
            ]))
        );
    }

    #[test]
    fn refuses_what_it_does_not_approximate() {
        assert!(parse(r#"{"a": 1.5}"#).is_err(), "float");
        assert!(parse(r#"{"a": 1, "a": 2}"#).is_err(), "duplicate key");
        assert!(parse(r#"{"a": 1} x"#).is_err(), "trailing");
        assert!(parse(r#"{"a": "\ud800"}"#).is_err(), "unpaired surrogate");
        assert!(parse("[1,]").is_err(), "trailing comma");
    }
}
