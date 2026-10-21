//! Signing keys and JSON Web Tokens (RFC 7515, RFC 7519) for the three algorithms we accept.

use std::fmt;

use aws_lc_rs::encoding::AsDer as _;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{
    self, ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, ED25519, EcdsaKeyPair,
    Ed25519KeyPair, KeyPair as _, RSA_PKCS1_2048_8192_SHA256, RsaKeyPair, RsaPublicKeyComponents,
    UnparsedPublicKey,
};
use serde::{Deserialize, Serialize};

use super::{CryptoError, sha256};
use crate::encoding::{base64url, decode_base64url};
use crate::secret::Secret;

/// Tokens larger than this are rejected before any parsing.
const MAX_TOKEN_LEN: usize = 16 * 1024;
/// RSA keys shorter than 2048 bits are refused.
const MIN_RSA_MODULUS_LEN: usize = 256;

/// Signature algorithms. `none` and HMAC are absent on purpose: a token must be signed, and
/// signing with a secret shared with a client would let the client forge tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Algorithm {
    Rs256,
    Es256,
    EdDsa,
}

impl Algorithm {
    pub(crate) const ALL: [Self; 3] = [Self::Rs256, Self::Es256, Self::EdDsa];

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Es256 => "ES256",
            Self::EdDsa => "EdDSA",
        }
    }

    pub(crate) fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|alg| alg.name() == name)
    }
}

enum Pair {
    Rsa(RsaKeyPair),
    Ec(EcdsaKeyPair),
    Ed(Ed25519KeyPair),
}

/// A private key that signs tokens. Its `kid` is the RFC 7638 thumbprint of the public key, so
/// the same key always has the same identifier.
pub(crate) struct SigningKey {
    pair: Pair,
    public: VerifyingKey,
}

impl SigningKey {
    /// A new key, and its PKCS #8 encoding for storage.
    pub(crate) fn generate(algorithm: Algorithm) -> Result<(Self, Secret<Vec<u8>>), CryptoError> {
        let der = match algorithm {
            Algorithm::Rs256 => RsaKeyPair::generate(KeySize::Rsa2048)?
                .as_der()?
                .as_ref()
                .to_vec(),
            Algorithm::Es256 => EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING)?
                .to_pkcs8v1()?
                .as_ref()
                .to_vec(),
            Algorithm::EdDsa => Ed25519KeyPair::generate()?.to_pkcs8v1()?.as_ref().to_vec(),
        };
        let der = Secret::new(der);
        Ok((Self::from_pkcs8(algorithm, der.expose())?, der))
    }

    pub(crate) fn from_pkcs8(algorithm: Algorithm, der: &[u8]) -> Result<Self, CryptoError> {
        let (pair, material) = match algorithm {
            Algorithm::Rs256 => {
                let pair = RsaKeyPair::from_pkcs8(der)?;
                if pair.public_modulus_len() < MIN_RSA_MODULUS_LEN {
                    return Err(CryptoError);
                }
                let public = pair.public_key();
                let material = Material::Rsa {
                    n: public.modulus().big_endian_without_leading_zero().to_vec(),
                    e: public.exponent().big_endian_without_leading_zero().to_vec(),
                };
                (Pair::Rsa(pair), material)
            }
            Algorithm::Es256 => {
                let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der)?;
                let material = Material::from_ec_point(pair.public_key().as_ref())?;
                (Pair::Ec(pair), material)
            }
            Algorithm::EdDsa => {
                let pair = Ed25519KeyPair::from_pkcs8(der)?;
                let material = Material::Ed {
                    x: pair.public_key().as_ref().to_vec(),
                };
                (Pair::Ed(pair), material)
            }
        };
        Ok(Self {
            pair,
            public: VerifyingKey::new(material),
        })
    }

    pub(crate) fn algorithm(&self) -> Algorithm {
        self.public.algorithm()
    }

    pub(crate) fn kid(&self) -> &str {
        &self.public.kid
    }

    pub(crate) fn verifying_key(&self) -> &VerifyingKey {
        &self.public
    }

    /// Signs `claims` as a compact JWT with the given `typ` header.
    pub(crate) fn sign_jwt(
        &self,
        typ: &str,
        claims: &impl Serialize,
    ) -> Result<String, CryptoError> {
        #[derive(Serialize)]
        struct Header<'a> {
            alg: &'a str,
            typ: &'a str,
            kid: &'a str,
        }
        let header = Header {
            alg: self.algorithm().name(),
            typ,
            kid: self.kid(),
        };
        let header = serde_json::to_vec(&header).map_err(|_| CryptoError)?;
        let claims = serde_json::to_vec(claims).map_err(|_| CryptoError)?;
        let mut token = format!("{}.{}", base64url(&header), base64url(&claims));
        let signature = self.sign(token.as_bytes())?;
        token.push('.');
        token.push_str(&base64url(&signature));
        Ok(token)
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(match &self.pair {
            Pair::Rsa(pair) => {
                let mut signature = vec![0; pair.public_modulus_len()];
                pair.sign(
                    &signature::RSA_PKCS1_SHA256,
                    &SystemRandom::new(),
                    message,
                    &mut signature,
                )?;
                signature
            }
            Pair::Ec(pair) => pair.sign(&SystemRandom::new(), message)?.as_ref().to_vec(),
            Pair::Ed(pair) => pair.sign(message).as_ref().to_vec(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Material {
    Rsa {
        n: Vec<u8>,
        e: Vec<u8>,
    },
    /// P-256 coordinates, 32 bytes each.
    Ec {
        x: Vec<u8>,
        y: Vec<u8>,
    },
    Ed {
        x: Vec<u8>,
    },
}

impl Material {
    /// Splits an uncompressed P-256 point, `04 || x || y`.
    fn from_ec_point(point: &[u8]) -> Result<Self, CryptoError> {
        match point.split_first() {
            Some((4, coordinates)) if coordinates.len() == 64 => {
                let (x, y) = coordinates.split_at_checked(32).ok_or(CryptoError)?;
                Ok(Self::Ec {
                    x: x.to_vec(),
                    y: y.to_vec(),
                })
            }
            _ => Err(CryptoError),
        }
    }

    /// The members RFC 7638 hashes for a thumbprint, in the order it requires.
    fn thumbprint_input(&self) -> String {
        match self {
            Self::Rsa { n, e } => format!(
                r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#,
                base64url(e),
                base64url(n)
            ),
            Self::Ec { x, y } => format!(
                r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
                base64url(x),
                base64url(y)
            ),
            Self::Ed { x } => format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#, base64url(x)),
        }
    }
}

/// A public key that checks signatures: one of ours, or one published by another provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifyingKey {
    kid: String,
    material: Material,
}

impl VerifyingKey {
    fn new(material: Material) -> Self {
        let mut key = Self {
            kid: String::new(),
            material,
        };
        key.kid = key.thumbprint();
        key
    }

    /// The RFC 7638 thumbprint, which names the key whatever `kid` it was published with.
    pub(crate) fn thumbprint(&self) -> String {
        base64url(&sha256(self.material.thumbprint_input().as_bytes()))
    }

    /// Reads a key from a JWK set. Keys for other uses or algorithms, and RSA keys under 2048
    /// bits, are skipped. The `kid` stays as published, because tokens refer to it.
    pub(crate) fn from_jwk(jwk: &Jwk) -> Option<Self> {
        if jwk.use_.as_deref().is_some_and(|use_| use_ != "sig") {
            return None;
        }
        let decode = |value: &Option<String>| decode_base64url(value.as_deref()?);
        let material = match (jwk.kty.as_str(), jwk.crv.as_deref()) {
            ("RSA", None) => {
                let n = decode(&jwk.n)?;
                if n.len() < MIN_RSA_MODULUS_LEN || n.first() == Some(&0) {
                    return None;
                }
                Material::Rsa {
                    n,
                    e: decode(&jwk.e)?,
                }
            }
            ("EC", Some("P-256")) => {
                let (x, y) = (decode(&jwk.x)?, decode(&jwk.y)?);
                (x.len() == 32 && y.len() == 32).then_some(Material::Ec { x, y })?
            }
            ("OKP", Some("Ed25519")) => {
                let x = decode(&jwk.x)?;
                (x.len() == 32).then_some(Material::Ed { x })?
            }
            _ => return None,
        };
        let key = Self {
            kid: jwk.kid.clone().unwrap_or_default(),
            material,
        };
        match jwk.alg.as_deref() {
            Some(alg) if alg != key.algorithm().name() => None,
            _ => Some(key),
        }
    }

    pub(crate) fn algorithm(&self) -> Algorithm {
        match self.material {
            Material::Rsa { .. } => Algorithm::Rs256,
            Material::Ec { .. } => Algorithm::Es256,
            Material::Ed { .. } => Algorithm::EdDsa,
        }
    }

    pub(crate) fn jwk(&self) -> Jwk {
        let encode = |bytes: &[u8]| Some(base64url(bytes));
        let common = Jwk {
            kid: Some(self.kid.clone()),
            use_: Some("sig".to_owned()),
            alg: Some(self.algorithm().name().to_owned()),
            ..Jwk::default()
        };
        match &self.material {
            Material::Rsa { n, e } => Jwk {
                kty: "RSA".to_owned(),
                n: encode(n),
                e: encode(e),
                ..common
            },
            Material::Ec { x, y } => Jwk {
                kty: "EC".to_owned(),
                crv: Some("P-256".to_owned()),
                x: encode(x),
                y: encode(y),
                ..common
            },
            Material::Ed { x } => Jwk {
                kty: "OKP".to_owned(),
                crv: Some("Ed25519".to_owned()),
                x: encode(x),
                ..common
            },
        }
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        match &self.material {
            Material::Rsa { n, e } => RsaPublicKeyComponents { n, e }
                .verify(&RSA_PKCS1_2048_8192_SHA256, message, signature)
                .is_ok(),
            Material::Ec { x, y } => {
                let mut point = Vec::with_capacity(65);
                point.push(4);
                point.extend_from_slice(x);
                point.extend_from_slice(y);
                UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
                    .verify(message, signature)
                    .is_ok()
            }
            Material::Ed { x } => UnparsedPublicKey::new(&ED25519, x)
                .verify(message, signature)
                .is_ok(),
        }
    }
}

/// A JSON Web Key (RFC 7517) with the members we read or publish. Others are ignored.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct Jwk {
    pub(crate) kty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) kid: Option<String>,
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub(crate) use_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) crv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) n: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) e: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) y: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum JwtError {
    Malformed,
    UnsupportedAlgorithm,
    UnknownKey,
    BadSignature,
    WrongType,
}

impl fmt::Display for JwtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "the token is malformed",
            Self::UnsupportedAlgorithm => "the token uses an algorithm we don't accept",
            Self::UnknownKey => "the token was signed with an unknown key",
            Self::BadSignature => "the token signature is invalid",
            Self::WrongType => "the token has the wrong type",
        })
    }
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: Option<String>,
    typ: Option<String>,
    crit: Option<serde_json::Value>,
    jwk: Option<serde_json::Value>,
}

/// A compact JWS taken apart. Only its shape, algorithm and `typ` have been checked.
struct Parts<'a> {
    header: Header,
    algorithm: Algorithm,
    /// The part the signature covers: `header.payload`, as sent.
    signed: &'a str,
    payload: &'a str,
    signature: Vec<u8>,
}

impl Parts<'_> {
    fn verify(self, key: &VerifyingKey) -> Result<Vec<u8>, JwtError> {
        if !key.verify(self.signed.as_bytes(), &self.signature) {
            return Err(JwtError::BadSignature);
        }
        decode_base64url(self.payload).ok_or(JwtError::Malformed)
    }
}

fn parse<'a>(token: &'a str, typ: Option<&str>) -> Result<Parts<'a>, JwtError> {
    if token.len() > MAX_TOKEN_LEN {
        return Err(JwtError::Malformed);
    }
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(JwtError::Malformed);
    };
    let header_json = decode_base64url(header).ok_or(JwtError::Malformed)?;
    let fields: Header = serde_json::from_slice(&header_json).map_err(|_| JwtError::Malformed)?;
    // We understand no extensions, and RFC 7515 says to reject tokens that require one.
    if fields.crit.is_some() {
        return Err(JwtError::Malformed);
    }
    let algorithm = Algorithm::from_name(&fields.alg).ok_or(JwtError::UnsupportedAlgorithm)?;
    if let Some(expected) = typ {
        let actual = fields.typ.as_deref().unwrap_or_default();
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(JwtError::WrongType);
        }
    }
    let signed_len = header.len().saturating_add(1).saturating_add(payload.len());
    Ok(Parts {
        header: fields,
        algorithm,
        signed: token.get(..signed_len).ok_or(JwtError::Malformed)?,
        payload,
        signature: decode_base64url(signature).ok_or(JwtError::Malformed)?,
    })
}

/// Checks a compact JWT against `keys` and returns its payload. Only the signature, algorithm and
/// `typ` are checked here; the caller checks the claims.
pub(crate) fn verify_jwt(
    token: &str,
    keys: &[VerifyingKey],
    typ: Option<&str>,
) -> Result<Vec<u8>, JwtError> {
    let parts = parse(token, typ)?;
    let kid = parts.header.kid.as_deref();
    let mut candidates = keys
        .iter()
        .filter(|key| key.algorithm() == parts.algorithm && kid.is_none_or(|kid| kid == key.kid));
    let key = match (candidates.next(), candidates.next()) {
        (Some(key), None) => key,
        // Without a kid, several keys of one algorithm would be guesswork.
        (Some(key), Some(_)) if kid.is_some() => key,
        _ => return Err(JwtError::UnknownKey),
    };
    parts.verify(key)
}

/// Checks a JWT signed with the key in its own `jwk` header, such as a DPoP proof (RFC 9449):
/// the signature proves that the sender holds the private key. Returns the payload and the
/// key's thumbprint (RFC 7638).
pub(crate) fn verify_self_signed(token: &str, typ: &str) -> Result<(Vec<u8>, String), JwtError> {
    let mut parts = parse(token, Some(typ))?;
    let jwk = parts.header.jwk.take().ok_or(JwtError::UnknownKey)?;
    // A private key in the header would be a client giving its key away; refuse to use it.
    if jwk.get("d").is_some() {
        return Err(JwtError::UnknownKey);
    }
    let jwk: Jwk = serde_json::from_value(jwk).map_err(|_| JwtError::Malformed)?;
    let key = VerifyingKey::from_jwk(&jwk).ok_or(JwtError::UnknownKey)?;
    if key.algorithm() != parts.algorithm {
        return Err(JwtError::UnsupportedAlgorithm);
    }
    let thumbprint = key.thumbprint();
    Ok((parts.verify(&key)?, thumbprint))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_verify_only_with_the_right_key_algorithm_and_type() {
        for algorithm in Algorithm::ALL {
            let (key, der) = SigningKey::generate(algorithm).unwrap();
            let reloaded = SigningKey::from_pkcs8(algorithm, der.expose()).unwrap();
            assert_eq!(reloaded.kid(), key.kid());

            let token = key
                .sign_jwt("at+jwt", &serde_json::json!({ "sub": "anna" }))
                .unwrap();
            let keys = [key.verifying_key().clone()];
            let payload = verify_jwt(&token, &keys, Some("at+jwt")).unwrap();
            assert_eq!(payload, br#"{"sub":"anna"}"#);

            assert_eq!(
                verify_jwt(&token, &keys, Some("logout+jwt")),
                Err(JwtError::WrongType)
            );
            let (other, _) = SigningKey::generate(algorithm).unwrap();
            assert_eq!(
                verify_jwt(&token, &[other.verifying_key().clone()], None),
                Err(JwtError::UnknownKey)
            );

            // A published JWK reads back as the same key.
            let from_jwk = VerifyingKey::from_jwk(&key.verifying_key().jwk()).unwrap();
            assert_eq!(&from_jwk, key.verifying_key());

            let mut tampered = token.clone();
            tampered.insert(token.find('.').unwrap() + 2, 'A');
            assert!(verify_jwt(&tampered, &keys, None).is_err());
        }
    }

    #[test]
    fn self_signed_tokens_prove_the_key_in_their_header() {
        let (key, _) = SigningKey::generate(Algorithm::Es256).unwrap();
        let token = |jwk: serde_json::Value| {
            let header = serde_json::json!({ "alg": "ES256", "typ": "dpop+jwt", "jwk": jwk });
            let signed = format!(
                "{}.{}",
                base64url(header.to_string().as_bytes()),
                base64url(b"{}")
            );
            let signature = key.sign(signed.as_bytes()).unwrap();
            format!("{signed}.{}", base64url(&signature))
        };
        let public = serde_json::to_value(key.verifying_key().jwk()).unwrap();
        let (payload, thumbprint) = verify_self_signed(&token(public.clone()), "dpop+jwt").unwrap();
        assert_eq!(
            (payload.as_slice(), thumbprint.as_str()),
            (&b"{}"[..], key.kid())
        );
        assert_eq!(
            verify_self_signed(&token(public.clone()), "at+jwt"),
            Err(JwtError::WrongType)
        );

        let mut private = public;
        private["d"] = "AAAA".into();
        assert_eq!(
            verify_self_signed(&token(private), "dpop+jwt"),
            Err(JwtError::UnknownKey)
        );
        let (other, _) = SigningKey::generate(Algorithm::Es256).unwrap();
        let other = serde_json::to_value(other.verifying_key().jwk()).unwrap();
        assert_eq!(
            verify_self_signed(&token(other), "dpop+jwt"),
            Err(JwtError::BadSignature)
        );
    }

    #[test]
    fn unsigned_and_hmac_tokens_are_rejected() {
        let (key, _) = SigningKey::generate(Algorithm::Es256).unwrap();
        let keys = [key.verifying_key().clone()];
        for alg in ["none", "HS256"] {
            let header = base64url(format!(r#"{{"alg":"{alg}"}}"#).as_bytes());
            let token = format!("{header}.{}.", base64url(b"{}"));
            assert_eq!(
                verify_jwt(&token, &keys, None),
                Err(JwtError::UnsupportedAlgorithm)
            );
        }
    }
}
