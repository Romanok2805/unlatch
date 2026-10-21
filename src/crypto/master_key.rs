//! The master key and the keys derived from it.
//!
//! One master key is configured. Each use gets its own key derived with HKDF, so a value sealed
//! or signed for one purpose is meaningless for another.

use aws_lc_rs::{aead, hkdf, hmac};

use super::{CryptoError, random_bytes};
use crate::encoding::{base64url, decode_base64url};
use crate::secret::Secret;

const NONCE_LEN: usize = 12;

pub(crate) struct MasterKey(Secret<[u8; 32]>);

impl MasterKey {
    /// Reads a key written by [`MasterKey::generate`]. Surrounding whitespace is ignored, so the
    /// key file may end with a newline.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        let bytes = Secret::new(decode_base64url(text.trim())?);
        let key: [u8; 32] = bytes.expose().as_slice().try_into().ok()?;
        Some(Self(Secret::new(key)))
    }

    /// A new random key in the form [`MasterKey::parse`] reads.
    pub(crate) fn generate() -> Result<String, CryptoError> {
        let key = Secret::new(random_bytes::<32>()?);
        Ok(base64url(key.expose()))
    }

    fn derive(&self, purpose: &str) -> Result<Secret<[u8; 32]>, CryptoError> {
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, b"unlatch").extract(self.0.expose());
        let info = [purpose.as_bytes()];
        let mut out = Secret::new([0; 32]);
        let okm = prk.expand(&info, hkdf::HKDF_SHA256)?;
        okm.fill(out.expose_mut())?;
        Ok(out)
    }

    pub(crate) fn sealing_key(&self, purpose: &str) -> Result<SealingKey, CryptoError> {
        let key = self.derive(purpose)?;
        let unbound = aead::UnboundKey::new(&aead::AES_256_GCM, key.expose())?;
        Ok(SealingKey(aead::LessSafeKey::new(unbound)))
    }

    pub(crate) fn mac_key(&self, purpose: &str) -> Result<MacKey, CryptoError> {
        let key = self.derive(purpose)?;
        Ok(MacKey(hmac::Key::new(hmac::HMAC_SHA256, key.expose())))
    }
}

/// Encrypts and authenticates with AES-256-GCM. Every message gets a random nonce, which is safe
/// far beyond the number of values Unlatch will ever seal under one key.
pub(crate) struct SealingKey(aead::LessSafeKey);

impl SealingKey {
    /// Returns the nonce followed by the ciphertext and tag. `context` is authenticated but not
    /// stored: opening needs the same context, which ties a value to where it belongs.
    pub(crate) fn seal(&self, plaintext: &[u8], context: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = random_bytes::<NONCE_LEN>()?;
        let mut out = Vec::with_capacity(
            NONCE_LEN
                .saturating_add(plaintext.len())
                .saturating_add(aead::AES_256_GCM.tag_len()),
        );
        out.extend_from_slice(&nonce);
        out.extend_from_slice(plaintext);
        let mut in_out = out.split_off(NONCE_LEN);
        self.0.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(context),
            &mut in_out,
        )?;
        out.append(&mut in_out);
        Ok(out)
    }

    /// The plaintext, or `None` if the value was altered or sealed with another key or context.
    pub(crate) fn open(&self, sealed: &[u8], context: &[u8]) -> Option<Secret<Vec<u8>>> {
        let (nonce, ciphertext) = sealed.split_at_checked(NONCE_LEN)?;
        let nonce = aead::Nonce::try_assume_unique_for_key(nonce).ok()?;
        let mut in_out = Secret::new(ciphertext.to_vec());
        let plaintext_len = self
            .0
            .open_in_place(nonce, aead::Aad::from(context), in_out.expose_mut())
            .ok()?
            .len();
        in_out.expose_mut().truncate(plaintext_len);
        Some(in_out)
    }
}

/// HMAC-SHA256 for values that need integrity but not secrecy, such as CSRF tokens.
pub(crate) struct MacKey(hmac::Key);

impl MacKey {
    pub(crate) fn sign(&self, data: &[u8]) -> [u8; 32] {
        let mut out = [0; 32];
        out.copy_from_slice(hmac::sign(&self.0, data).as_ref());
        out
    }

    pub(crate) fn verify(&self, data: &[u8], tag: &[u8]) -> bool {
        hmac::verify(&self.0, data, tag).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_values_open_only_with_the_same_key_and_context() {
        let master = MasterKey::parse(&MasterKey::generate().unwrap()).unwrap();
        let key = master.sealing_key("test").unwrap();
        let sealed = key.seal(b"secret", b"row 1").unwrap();

        assert_eq!(key.open(&sealed, b"row 1").unwrap().expose(), b"secret");
        assert!(key.open(&sealed, b"row 2").is_none());
        assert!(
            master
                .sealing_key("other")
                .unwrap()
                .open(&sealed, b"row 1")
                .is_none()
        );

        let mut tampered = sealed.clone();
        if let Some(last) = tampered.last_mut() {
            *last ^= 1;
        }
        assert!(key.open(&tampered, b"row 1").is_none());
    }

    #[test]
    fn rejects_keys_of_the_wrong_length() {
        assert!(MasterKey::parse("c2hvcnQ").is_none());
        assert!(MasterKey::parse("not base64!").is_none());
    }
}
