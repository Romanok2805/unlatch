//! Time-based one-time passwords (RFC 6238) as authenticator apps implement them: HMAC-SHA1, six
//! digits, 30-second steps. Apps that offer other settings rarely honour them.

use aws_lc_rs::hmac;

use super::{CryptoError, constant_time_eq, random_bytes};
use crate::encoding::base32;
use crate::form::encode;
use crate::secret::Secret;

const SECRET_LEN: usize = 20;
const STEP_SECONDS: u64 = 30;

pub(crate) fn generate_secret() -> Result<Secret<Vec<u8>>, CryptoError> {
    Ok(Secret::new(random_bytes::<SECRET_LEN>()?.to_vec()))
}

/// The time step a code was accepted for, or `None`. Codes from one step before and after now are
/// accepted to allow for clock drift. A step at or before `last_used_step` is refused, so each
/// code works once even within its window.
pub(crate) fn verify(
    secret: &[u8],
    input: &str,
    now: u64,
    last_used_step: Option<u64>,
) -> Option<u64> {
    let digits: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if digits.len() != 6 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let current = now / STEP_SECONDS;
    let mut accepted = None;
    // Every candidate is computed and compared, so timing doesn't reveal which one matched.
    for step in [
        current.checked_sub(1),
        Some(current),
        current.checked_add(1),
    ]
    .into_iter()
    .flatten()
    {
        let expected = format!("{:06}", code(secret, step));
        let fresh = last_used_step.is_none_or(|last| step > last);
        if constant_time_eq(expected.as_bytes(), digits.as_bytes()) && fresh {
            accepted = Some(step);
        }
    }
    accepted
}

/// The `otpauth://` URI that authenticator apps scan from a QR code.
pub(crate) fn uri(secret: &[u8], issuer: &str, account: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        encode(issuer),
        encode(account),
        base32(secret),
        encode(issuer)
    )
}

/// The six-digit code for a time step (RFC 4226, section 5.3).
fn code(secret: &[u8], step: u64) -> u32 {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let tag = hmac::sign(&key, &step.to_be_bytes());
    let tag = tag.as_ref();
    let offset = usize::from(tag.last().copied().unwrap_or(0) & 0xf);
    let window: [u8; 4] = tag
        .get(offset..offset.saturating_add(4))
        .and_then(|bytes| bytes.try_into().ok())
        .unwrap_or_default();
    (u32::from_be_bytes(window) & 0x7fff_ffff) % 1_000_000
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn matches_rfc_6238_test_vectors() {
        // The RFC lists eight digits; authenticator apps show the last six.
        for (time, expected) in [
            (59, 287_082),
            (1_111_111_109, 81_804),
            (1_234_567_890, 5_924),
        ] {
            assert_eq!(code(RFC_SECRET, time / STEP_SECONDS), expected);
        }
    }

    #[test]
    fn accepts_neighbouring_steps_once() {
        let now = 1_234_567_890;
        let step = now / STEP_SECONDS;
        let next = format!("{:06}", code(RFC_SECRET, step + 1));

        assert_eq!(verify(RFC_SECRET, "005 924", now, None), Some(step));
        assert_eq!(verify(RFC_SECRET, &next, now, None), Some(step + 1));
        assert_eq!(verify(RFC_SECRET, "005924", now, Some(step)), None);
        assert_eq!(verify(RFC_SECRET, "005925", now, None), None);
        assert_eq!(verify(RFC_SECRET, "5924", now, None), None);
    }
}
