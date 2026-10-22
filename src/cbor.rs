//! A decoder for the part of CBOR (RFC 8949) that passkeys use: integers, byte and text strings,
//! arrays, maps and the simple values false, true and null, all of definite length.
//!
//! Tags, floating-point numbers and indefinite lengths are refused, since authenticators don't
//! send them. So are maps with a repeated key, which two readers could take differently.

/// Arrays and maps nest no deeper than this, so input can't exhaust the stack.
const MAX_DEPTH: usize = 8;
/// Arrays and maps hold no more than this many entries. The largest we read, a certificate
/// chain in an attestation statement, has a handful.
const MAX_ENTRIES: u64 = 64;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Value<'a> {
    Integer(i64),
    Bytes(&'a [u8]),
    Text(&'a str),
    Array(Vec<Value<'a>>),
    Map(Vec<(Value<'a>, Value<'a>)>),
    Bool(bool),
    Null,
}

impl Value<'_> {
    /// The value under `key` in a map; `None` for a missing key or a value that isn't a map.
    pub(crate) fn get(&self, key: &Value<'_>) -> Option<&Self> {
        let Self::Map(entries) = self else {
            return None;
        };
        entries
            .iter()
            .find_map(|(entry, value)| (entry == key).then_some(value))
    }
}

/// Decodes one value that must take up all of `bytes`.
pub(crate) fn decode(bytes: &[u8]) -> Option<Value<'_>> {
    match decode_prefix(bytes)? {
        (value, []) => Some(value),
        _ => None,
    }
}

/// Decodes the value at the start of `bytes` and returns it with what follows it.
pub(crate) fn decode_prefix(bytes: &[u8]) -> Option<(Value<'_>, &[u8])> {
    let mut reader = Reader { rest: bytes };
    let value = reader.value(0)?;
    Some((value, reader.rest))
}

struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let (taken, rest) = self.rest.split_at_checked(len)?;
        self.rest = rest;
        Some(taken)
    }

    /// The argument of a head: the number in its low five bits, or in the bytes after it.
    fn argument(&mut self, info: u8) -> Option<u64> {
        let len = match info {
            0..=23 => return Some(u64::from(info)),
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            // 28 to 30 are reserved, and 31 marks an indefinite length.
            _ => return None,
        };
        let mut bytes = [0; 8];
        bytes
            .get_mut(8_usize.saturating_sub(len)..)?
            .copy_from_slice(self.take(len)?);
        Some(u64::from_be_bytes(bytes))
    }

    fn value(&mut self, depth: usize) -> Option<Value<'a>> {
        let (&head, rest) = self.rest.split_first()?;
        self.rest = rest;
        let (major, info) = (head >> 5, head & 0x1f);
        if major == 7 {
            return match info {
                20 => Some(Value::Bool(false)),
                21 => Some(Value::Bool(true)),
                22 => Some(Value::Null),
                _ => None,
            };
        }
        let argument = self.argument(info)?;
        match major {
            0 => i64::try_from(argument).ok().map(Value::Integer),
            // -1 - n, which fits whenever n does.
            1 => i64::try_from(argument)
                .ok()
                .map(|n| Value::Integer((-1_i64).saturating_sub(n))),
            2 => self.take(usize::try_from(argument).ok()?).map(Value::Bytes),
            3 => {
                let bytes = self.take(usize::try_from(argument).ok()?)?;
                std::str::from_utf8(bytes).ok().map(Value::Text)
            }
            4 | 5 if depth < MAX_DEPTH && argument <= MAX_ENTRIES => {
                let depth = depth.saturating_add(1);
                if major == 4 {
                    (0..argument)
                        .map(|_| self.value(depth))
                        .collect::<Option<_>>()
                        .map(Value::Array)
                } else {
                    let mut entries: Vec<(Value<'a>, Value<'a>)> = Vec::new();
                    for _ in 0..argument {
                        let key = self.value(depth)?;
                        if entries.iter().any(|(seen, _)| *seen == key) {
                            return None;
                        }
                        let value = self.value(depth)?;
                        entries.push((key, value));
                    }
                    Some(Value::Map(entries))
                }
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_what_authenticators_send_and_nothing_else() {
        // {1: 2, 3: -7, -1: h'0102', "fmt": "none", "ok": [true, null]}
        let bytes = [
            0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x42, 0x01, 0x02, 0x63, b'f', b'm', b't', 0x64,
            b'n', b'o', b'n', b'e', 0x62, b'o', b'k', 0x82, 0xf5, 0xf6,
        ];
        let value = decode(&bytes).unwrap();
        assert_eq!(value.get(&Value::Integer(3)), Some(&Value::Integer(-7)));
        assert_eq!(value.get(&Value::Integer(-1)), Some(&Value::Bytes(&[1, 2])));
        assert_eq!(value.get(&Value::Text("fmt")), Some(&Value::Text("none")));
        assert_eq!(
            value.get(&Value::Text("ok")),
            Some(&Value::Array(vec![Value::Bool(true), Value::Null]))
        );

        // A value followed by more bytes reads only as a prefix.
        assert_eq!(decode(&[0x01, 0x02]), None);
        assert_eq!(
            decode_prefix(&[0x01, 0x02]),
            Some((Value::Integer(1), &[2][..]))
        );

        // Eight arrays, one inside the other, are as deep as it goes.
        let nested = |depth| [vec![0x81; depth], vec![0x00]].concat();
        assert!(decode(&nested(8)).is_some());
        assert_eq!(decode(&nested(9)), None);

        for bad in [
            &[0xa2, 0x01, 0x02, 0x01, 0x03][..], // repeated key
            &[0x5f, 0x41, 0x00, 0xff],           // indefinite length
            &[0xc2, 0x41, 0x00],                 // tag
            &[0xfa, 0, 0, 0, 0],                 // float
            &[0x62, 0xc3, 0x28],                 // invalid UTF-8
            &[0x5a, 0xff, 0xff, 0xff, 0xff],     // longer than the input
            &[0x1b, 0xff, 0, 0, 0, 0, 0, 0, 0],  // beyond i64
            &[0x9b, 0, 0, 0, 0, 0, 0, 0, 65],    // too many entries
        ] {
            assert_eq!(decode(bad), None, "{bad:02x?}");
        }
    }
}
