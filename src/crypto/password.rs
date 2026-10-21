//! Password hashing with Argon2id, stored as PHC strings.

use std::sync::OnceLock;

use argon2::{Algorithm, Argon2, Params, Version};

use super::{CryptoError, constant_time_eq, random_bytes};
use crate::encoding::{base64, decode_base64_standard};
use crate::secret::Secret;

/// OWASP's recommended minimum for Argon2id: 19 MiB, two passes, one lane. Memory is what makes
/// guessing on GPUs expensive, and it is also what limits how many sign-ins run at once.
const MEMORY_KIB: u32 = 19 * 1024;
const PASSES: u32 = 2;
const LANES: u32 = 1;
const SALT_LEN: usize = 16;
const HASH_LEN: usize = 32;
/// Stored hashes that ask for more memory or passes than this are refused, not computed.
const MAX_MEMORY_KIB: u32 = 256 * 1024;
const MAX_PASSES: u32 = 16;

/// A hash in PHC format: `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PasswordHash(String);

impl PasswordHash {
    pub(crate) fn from_stored(text: String) -> Self {
        Self(text)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

pub(crate) fn hash(password: &str) -> Result<PasswordHash, CryptoError> {
    let salt = random_bytes::<SALT_LEN>()?;
    let hash = compute(password, &salt, MEMORY_KIB, PASSES, LANES)?;
    Ok(PasswordHash(format!(
        "$argon2id$v=19$m={MEMORY_KIB},t={PASSES},p={LANES}${}${}",
        base64(&salt),
        base64(hash.expose())
    )))
}

/// Whether `password` matches. A stored hash that can't be read never matches.
pub(crate) fn verify(password: &str, stored: &PasswordHash) -> bool {
    let Some(parsed) = parse(&stored.0) else {
        return false;
    };
    compute(
        password,
        &parsed.salt,
        parsed.memory,
        parsed.passes,
        parsed.lanes,
    )
    .is_ok_and(|hash| constant_time_eq(hash.expose(), &parsed.hash))
}

/// Does the work of a verification for an account that doesn't exist, so the response time
/// doesn't tell an attacker which user names are taken.
pub(crate) fn verify_nonexistent(password: &str) {
    static DUMMY: OnceLock<Option<PasswordHash>> = OnceLock::new();
    if let Some(dummy) = DUMMY.get_or_init(|| hash("unlatch dummy password").ok()) {
        let _ = verify(password, dummy);
    }
}

/// Whether a hash was made with weaker settings than today's and should be replaced at the next
/// successful sign-in.
pub(crate) fn needs_rehash(stored: &PasswordHash) -> bool {
    parse(&stored.0).is_none_or(|p| p.memory < MEMORY_KIB || p.passes < PASSES)
}

fn compute(
    password: &str,
    salt: &[u8],
    memory: u32,
    passes: u32,
    lanes: u32,
) -> Result<Secret<Vec<u8>>, CryptoError> {
    let params = Params::new(memory, passes, lanes, Some(HASH_LEN)).map_err(|_| CryptoError)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Secret::new(vec![0; HASH_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), salt, out.expose_mut())
        .map_err(|_| CryptoError)?;
    Ok(out)
}

struct Parsed {
    memory: u32,
    passes: u32,
    lanes: u32,
    salt: Vec<u8>,
    hash: Vec<u8>,
}

fn parse(text: &str) -> Option<Parsed> {
    let mut fields = text.split('$');
    let ("", "argon2id", "v=19", Some(params), Some(salt), Some(hash), None) = (
        fields.next()?,
        fields.next()?,
        fields.next()?,
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    ) else {
        return None;
    };
    let (mut memory, mut passes, mut lanes) = (None, None, None);
    for param in params.split(',') {
        let (name, value) = param.split_once('=')?;
        let value = value.parse::<u32>().ok()?;
        match name {
            "m" => memory = Some(value),
            "t" => passes = Some(value),
            "p" => lanes = Some(value),
            _ => return None,
        }
    }
    let parsed = Parsed {
        memory: memory?,
        passes: passes?,
        lanes: lanes?,
        salt: decode_base64_standard(salt)?,
        hash: decode_base64_standard(hash)?,
    };
    (parsed.memory <= MAX_MEMORY_KIB
        && parsed.passes <= MAX_PASSES
        && parsed.hash.len() == HASH_LEN)
        .then_some(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_verify_and_tampering_is_rejected() {
        let stored = hash("correct horse battery staple").unwrap();
        assert!(
            stored
                .as_str()
                .starts_with("$argon2id$v=19$m=19456,t=2,p=1$")
        );
        assert!(verify("correct horse battery staple", &stored));
        assert!(!verify("correct horse battery stapl", &stored));
        assert!(!needs_rehash(&stored));

        let greedy = stored.as_str().replace("m=19456", "m=4194304");
        assert!(!verify(
            "correct horse battery staple",
            &PasswordHash::from_stored(greedy)
        ));
        assert!(!verify(
            "x",
            &PasswordHash::from_stored("$argon2i$v=19$m=8,t=1,p=1$AA$AA".into())
        ));
    }
}
