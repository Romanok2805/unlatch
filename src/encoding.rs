//! Base64 and base32 without padding, as used by JOSE, PHC strings and authenticator apps.
//!
//! Decoding is strict: input that a canonical encoder would not produce is rejected, so every
//! value has exactly one encoding and encoded strings can be compared directly.

const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Base64url without padding (RFC 4648, section 5).
pub(crate) fn base64url(data: &[u8]) -> String {
    encode_base64(data, URL_SAFE)
}

/// Standard base64 without padding, the "B64" of PHC strings.
pub(crate) fn base64(data: &[u8]) -> String {
    encode_base64(data, STANDARD)
}

pub(crate) fn decode_base64url(text: &str) -> Option<Vec<u8>> {
    decode_base64(text, b'-', b'_')
}

pub(crate) fn decode_base64_standard(text: &str) -> Option<Vec<u8>> {
    decode_base64(text, b'+', b'/')
}

/// Base32 without padding (RFC 4648, section 6), the format authenticator apps expect.
pub(crate) fn base32(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().saturating_mul(8).div_ceil(5));
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits = bits.wrapping_add(8);
        while bits >= 5 {
            bits = bits.wrapping_sub(5);
            out.push(symbol(BASE32, buffer >> bits));
        }
        buffer &= (1_u32 << bits).wrapping_sub(1);
    }
    if bits > 0 {
        out.push(symbol(BASE32, buffer << 5_u32.wrapping_sub(bits)));
    }
    out
}

fn encode_base64(data: &[u8], alphabet: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3).saturating_mul(4));
    for chunk in data.chunks(3) {
        let byte = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
        let group = (byte(0) << 16) | (byte(1) << 8) | byte(2);
        // One byte needs two symbols, two bytes three, three bytes four.
        let symbols = chunk.len().saturating_add(1);
        for shift in [18, 12, 6, 0].into_iter().take(symbols) {
            out.push(symbol(alphabet, group >> shift));
        }
    }
    out
}

/// The symbol for the low bits of `value`; the mask keeps the index inside the alphabet.
fn symbol(alphabet: &[u8], value: u32) -> char {
    let mask = u32::try_from(alphabet.len()).map_or(0, |len| len.wrapping_sub(1));
    let index = usize::try_from(value & mask).unwrap_or(0);
    char::from(alphabet.get(index).copied().unwrap_or(b'A'))
}

fn decode_base64(text: &str, symbol_62: u8, symbol_63: u8) -> Option<Vec<u8>> {
    let value = |c: u8| -> Option<u32> {
        let v = match c {
            b'A'..=b'Z' => c.wrapping_sub(b'A'),
            b'a'..=b'z' => c.wrapping_sub(b'a').wrapping_add(26),
            b'0'..=b'9' => c.wrapping_sub(b'0').wrapping_add(52),
            _ if c == symbol_62 => 62,
            _ if c == symbol_63 => 63,
            _ => return None,
        };
        Some(u32::from(v))
    };

    let mut out = Vec::with_capacity(text.len().saturating_mul(3).div_ceil(4));
    for chunk in text.as_bytes().chunks(4) {
        let mut group: u32 = 0;
        for &c in chunk {
            group = (group << 6) | value(c)?;
        }
        // A partial group carries 2 or 4 unused bits, which a canonical encoder leaves zero.
        match chunk.len() {
            4 => {
                let [_, a, b, c] = group.to_be_bytes();
                out.extend_from_slice(&[a, b, c]);
            }
            3 if group.trailing_zeros() >= 2 => {
                let [_, _, a, b] = (group >> 2).to_be_bytes();
                out.extend_from_slice(&[a, b]);
            }
            2 if group.trailing_zeros() >= 4 => {
                let [_, _, _, a] = (group >> 4).to_be_bytes();
                out.push(a);
            }
            _ => return None,
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips_and_rejects_non_canonical_input() {
        for (data, encoded) in [
            (&b""[..], ""),
            (b"f", "Zg"),
            (b"fo", "Zm8"),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg"),
            (&[0xfb, 0xff], "-_8"),
        ] {
            assert_eq!(base64url(data), encoded);
            assert_eq!(decode_base64url(encoded).as_deref(), Some(data));
        }
        assert_eq!(base64(&[0xfb, 0xff]), "+/8");
        // Padding, a lone trailing symbol and non-zero unused bits are all rejected.
        for bad in ["Zg==", "Zm9vY", "Zh", "Zm9", "Zm 9v", "+/8"] {
            assert_eq!(decode_base64url(bad), None, "{bad}");
        }
    }

    #[test]
    fn base32_matches_rfc_4648() {
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32(b"fooba"), "MZXW6YTB");
        assert_eq!(base32(b"f"), "MY");
    }
}
