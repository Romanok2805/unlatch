//! Cryptography. The primitives come from aws-lc-rs; this module only combines them.

mod jws;
mod master_key;
pub(crate) mod passkey;
pub(crate) mod password;
pub(crate) mod totp;

use std::fmt;

use aws_lc_rs::{constant_time, digest, rand};

use crate::encoding::base64url;

pub(crate) use jws::{
    Algorithm, Jwk, JwtError, SigningKey, VerifyingKey, verify_jwt, verify_self_signed,
};
pub(crate) use master_key::{MacKey, MasterKey, SealingKey};

/// A cryptographic operation failed. The library doesn't say why, and nothing we could do with a
/// reason would differ: the operation is refused.
#[derive(Debug)]
pub(crate) struct CryptoError;

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a cryptographic operation failed")
    }
}

impl From<aws_lc_rs::error::Unspecified> for CryptoError {
    fn from(_: aws_lc_rs::error::Unspecified) -> Self {
        Self
    }
}

impl From<aws_lc_rs::error::KeyRejected> for CryptoError {
    fn from(_: aws_lc_rs::error::KeyRejected) -> Self {
        Self
    }
}

pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut bytes = [0; N];
    rand::fill(&mut bytes)?;
    Ok(bytes)
}

/// A random token with 256 bits of entropy, for sessions, codes and refresh tokens.
pub(crate) fn random_token() -> Result<String, CryptoError> {
    Ok(base64url(&random_bytes::<32>()?))
}

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let mut out = [0; 32];
    out.copy_from_slice(digest::digest(&digest::SHA256, data).as_ref());
    out
}

pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    constant_time::verify_slices_are_equal(a, b).is_ok()
}

/// The SHA-256 hash of a bearer token. The database stores only these, so a copy of it holds no
/// usable sessions, codes or refresh tokens. A plain hash is enough because the tokens are random
/// with 256 bits of entropy and can't be guessed from their hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TokenHash(pub(crate) [u8; 32]);

impl TokenHash {
    pub(crate) fn of(token: &str) -> Self {
        Self(sha256(token.as_bytes()))
    }
}
