//! `application/x-www-form-urlencoded` data: request bodies and query strings.

use std::fmt;

/// More fields than any page or endpoint of ours sends.
const MAX_FIELDS: usize = 256;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FormError {
    Malformed,
    TooManyFields,
    /// A field that must appear once appeared more than once.
    Repeated(String),
}

impl fmt::Display for FormError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => f.write_str("malformed form data"),
            Self::TooManyFields => f.write_str("too many form fields"),
            Self::Repeated(name) => write!(f, "parameter {name} is repeated"),
        }
    }
}

/// Decoded fields in the order they were sent.
#[derive(Debug, Default)]
pub(crate) struct Form(Vec<(String, String)>);

impl Form {
    pub(crate) fn parse(input: &str) -> Result<Self, FormError> {
        let mut fields = Vec::new();
        for pair in input.split('&').filter(|pair| !pair.is_empty()) {
            if fields.len() == MAX_FIELDS {
                return Err(FormError::TooManyFields);
            }
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            fields.push((decode_component(name)?, decode_component(value)?));
        }
        Ok(Self(fields))
    }

    /// The value of a field that may appear at most once. Repeating it is an error rather than
    /// a choice of the first or last value, because OAuth forbids repeated parameters and two
    /// parsers that pick differently can be played against each other.
    pub(crate) fn single(&self, name: &str) -> Result<Option<&str>, FormError> {
        let mut values = self.all(name);
        let first = values.next();
        if values.next().is_some() {
            return Err(FormError::Repeated(name.to_owned()));
        }
        Ok(first)
    }

    /// Every value of a field that may repeat, such as a group of checkboxes.
    pub(crate) fn all<'a, 'n>(
        &'a self,
        name: &'n str,
    ) -> impl Iterator<Item = &'a str> + use<'a, 'n> {
        self.0
            .iter()
            .filter(move |(field, _)| field == name)
            .map(|(_, value)| value.as_str())
    }
}

/// Decodes one name or value.
pub(crate) fn decode_component(text: &str) -> Result<String, FormError> {
    let mut bytes = Vec::with_capacity(text.len());
    let mut input = text.bytes();
    while let Some(byte) = input.next() {
        match byte {
            b'+' => bytes.push(b' '),
            b'%' => {
                let high = input.next().and_then(hex_digit);
                let low = input.next().and_then(hex_digit);
                match (high, low) {
                    (Some(high), Some(low)) => bytes.push((high << 4) | low),
                    _ => return Err(FormError::Malformed),
                }
            }
            _ => bytes.push(byte),
        }
    }
    String::from_utf8(bytes).map_err(|_| FormError::Malformed)
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(c.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

/// Percent-encodes everything except the unreserved characters of RFC 3986, which is safe in
/// both query strings and form bodies.
pub(crate) fn encode(text: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            for nibble in [byte >> 4, byte & 0xf] {
                out.push(char::from(
                    HEX.get(usize::from(nibble)).copied().unwrap_or(b'0'),
                ));
            }
        }
    }
    out
}

/// Encodes name-value pairs as a query string or form body.
pub(crate) fn encode_pairs<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    let mut out = String::new();
    for (name, value) in pairs {
        if !out.is_empty() {
            out.push('&');
        }
        out.push_str(&encode(name));
        out.push('=');
        out.push_str(&encode(value));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_and_rejects_repeats_where_it_matters() {
        let form = Form::parse("a=1+2&b=%E2%9C%93&c=x&c=y&d").unwrap();
        assert_eq!(form.single("a"), Ok(Some("1 2")));
        assert_eq!(form.single("b"), Ok(Some("✓")));
        assert_eq!(form.single("d"), Ok(Some("")));
        assert_eq!(form.single("missing"), Ok(None));
        assert_eq!(form.single("c"), Err(FormError::Repeated("c".into())));
        assert_eq!(form.all("c").collect::<Vec<_>>(), ["x", "y"]);

        for bad in ["a=%", "a=%G1", "a=%FF"] {
            assert_eq!(Form::parse(bad).unwrap_err(), FormError::Malformed, "{bad}");
        }
    }

    #[test]
    fn encoding_round_trips() {
        let text = "a b&c=d/é~";
        let encoded = encode(text);
        assert_eq!(encoded, "a%20b%26c%3Dd%2F%C3%A9~");
        assert_eq!(decode_component(&encoded).unwrap(), text);
    }
}
