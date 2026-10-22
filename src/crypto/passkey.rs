//! Passkeys: checking what a browser returns from `navigator.credentials.create()` and `get()`,
//! as WebAuthn Level 3 describes in sections 7.1 and 7.2.
//!
//! Unlatch asks for no attestation, so it neither learns nor checks which make of authenticator
//! holds a key, and ignores any attestation statement the browser sends anyway. Every passkey
//! must verify the user with a PIN or biometrics, so it stands for two factors on its own.

use std::fmt;

use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1, ED25519, ParsedPublicKey, RSA_PKCS1_2048_8192_SHA256,
    RsaPublicKeyComponents, VerificationAlgorithm,
};
use serde::Deserialize;

use super::jws::{MIN_RSA_MODULUS_LEN, valid_exponent};
use super::sha256;
use crate::cbor::{self, Value};
use crate::encoding::decode_base64url;

/// The COSE algorithms (RFC 9053) we accept, in order of preference: EdDSA, ES256 and RS256,
/// which older Windows Hello authenticators need.
pub(crate) const ALGORITHMS: [i64; 3] = [-8, -7, -257];
/// The ways a browser may reach an authenticator, as `getTransports()` names them. Others are
/// dropped.
const TRANSPORTS: [&str; 6] = ["ble", "hybrid", "internal", "nfc", "smart-card", "usb"];
/// WebAuthn section 5.1 limits credential IDs to this length.
const MAX_CREDENTIAL_ID_LEN: usize = 1023;
/// The longest RSA modulus aws-lc-rs checks signatures with, 8192 bits.
const MAX_RSA_MODULUS_LEN: usize = 1024;

// Flags in authenticator data (WebAuthn section 6.1).
const USER_PRESENT: u8 = 0x01;
const USER_VERIFIED: u8 = 0x04;
const BACKUP_ELIGIBLE: u8 = 0x08;
const BACKED_UP: u8 = 0x10;
const ATTESTED_CREDENTIAL: u8 = 0x40;
const EXTENSIONS: u8 = 0x80;

/// Where a ceremony must have taken place: the domain that authenticators tie passkeys to, and
/// the origin our pages are served from.
pub(crate) struct RelyingParty<'a> {
    pub(crate) id: &'a str,
    pub(crate) origin: &'a str,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PasskeyError {
    Malformed,
    /// The answer is to another challenge or ceremony, or comes from another site.
    WrongContext,
    /// The authenticator didn't verify the user.
    NotVerified,
    UnsupportedKey,
    BadSignature,
    /// The signature counter didn't move forward, so the authenticator may have been copied.
    CounterWentBack,
}

impl fmt::Display for PasskeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "the passkey answer is malformed",
            Self::WrongContext => "the passkey answer is for another challenge or site",
            Self::NotVerified => "the authenticator didn't verify the user",
            Self::UnsupportedKey => "the passkey uses a key we don't accept",
            Self::BadSignature => "the passkey signature is invalid",
            Self::CounterWentBack => "the passkey counter went back; it may have been copied",
        })
    }
}

/// A passkey the browser has just created, checked and ready to store.
pub(crate) struct CreatedPasskey {
    pub(crate) credential_id: Vec<u8>,
    /// The `COSE_Key` (RFC 9052) as the authenticator sent it.
    pub(crate) public_key: Vec<u8>,
    pub(crate) sign_count: u32,
    pub(crate) transports: Vec<&'static str>,
}

/// A `PublicKeyCredential` as the script posts it: the shape WebAuthn's `toJSON()` gives, with
/// binary values in base64url.
#[derive(Deserialize)]
struct Credential<R> {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    response: R,
}

#[derive(Deserialize)]
struct AttestationResponse {
    #[serde(rename = "clientDataJSON")]
    client_data: String,
    #[serde(rename = "attestationObject")]
    attestation_object: String,
    #[serde(default)]
    transports: Vec<String>,
}

#[derive(Deserialize)]
struct AssertionResponse {
    #[serde(rename = "clientDataJSON")]
    client_data: String,
    #[serde(rename = "authenticatorData")]
    authenticator_data: String,
    signature: String,
    #[serde(rename = "userHandle")]
    user_handle: Option<String>,
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: bool,
}

/// Checks a new passkey, posted as JSON, against the challenge we issued for it.
pub(crate) fn register(
    rp: &RelyingParty<'_>,
    challenge: &[u8],
    json: &str,
) -> Result<CreatedPasskey, PasskeyError> {
    let credential: Credential<AttestationResponse> =
        serde_json::from_str(json).map_err(|_| PasskeyError::Malformed)?;
    let id = credential_id(&credential.kind, &credential.id)?;
    let response = credential.response;
    check_client_data(
        rp,
        "webauthn.create",
        challenge,
        &decode(&response.client_data)?,
    )?;

    let object = decode(&response.attestation_object)?;
    let object = cbor::decode(&object).ok_or(PasskeyError::Malformed)?;
    let (Some(Value::Text(_)), Some(Value::Map(_)), Some(Value::Bytes(data))) = (
        object.get(&Value::Text("fmt")),
        object.get(&Value::Text("attStmt")),
        object.get(&Value::Text("authData")),
    ) else {
        return Err(PasskeyError::Malformed);
    };
    let data = AuthenticatorData::parse(data)?;
    data.check(rp)?;
    let attested = data.attested.ok_or(PasskeyError::Malformed)?;
    if attested.credential_id != id {
        return Err(PasskeyError::Malformed);
    }
    PublicKey::from_cose(attested.public_key)?;

    let mut transports = Vec::new();
    for name in &response.transports {
        if let Some(known) = TRANSPORTS.into_iter().find(|known| known == name)
            && !transports.contains(&known)
        {
            transports.push(known);
        }
    }
    Ok(CreatedPasskey {
        credential_id: id,
        public_key: attested.public_key.to_vec(),
        sign_count: data.sign_count,
        transports,
    })
}

/// An answer from `navigator.credentials.get()`, taken apart but not yet checked: first the
/// caller finds the passkey it names.
pub(crate) struct Assertion {
    pub(crate) credential_id: Vec<u8>,
    /// The user handle the passkey was created with, if the authenticator sent it.
    pub(crate) user_handle: Option<Vec<u8>>,
    client_data: Vec<u8>,
    authenticator_data: Vec<u8>,
    signature: Vec<u8>,
}

impl Assertion {
    pub(crate) fn parse(json: &str) -> Result<Self, PasskeyError> {
        let credential: Credential<AssertionResponse> =
            serde_json::from_str(json).map_err(|_| PasskeyError::Malformed)?;
        let response = credential.response;
        Ok(Self {
            credential_id: credential_id(&credential.kind, &credential.id)?,
            user_handle: response.user_handle.as_deref().map(decode).transpose()?,
            client_data: decode(&response.client_data)?,
            authenticator_data: decode(&response.authenticator_data)?,
            signature: decode(&response.signature)?,
        })
    }

    /// Checks the answer against the challenge and the passkey's stored key and counter, and
    /// returns the counter to store.
    pub(crate) fn verify(
        &self,
        rp: &RelyingParty<'_>,
        challenge: &[u8],
        public_key: &[u8],
        sign_count: u32,
    ) -> Result<u32, PasskeyError> {
        check_client_data(rp, "webauthn.get", challenge, &self.client_data)?;
        let data = AuthenticatorData::parse(&self.authenticator_data)?;
        data.check(rp)?;
        if data.attested.is_some() {
            return Err(PasskeyError::Malformed);
        }
        let mut signed = self.authenticator_data.clone();
        signed.extend_from_slice(&sha256(&self.client_data));
        if !PublicKey::from_cose(public_key)?.verify(&signed, &self.signature) {
            return Err(PasskeyError::BadSignature);
        }
        // Synced passkeys keep no counter and always send 0.
        if (data.sign_count != 0 || sign_count != 0) && data.sign_count <= sign_count {
            return Err(PasskeyError::CounterWentBack);
        }
        Ok(data.sign_count)
    }
}

fn decode(text: &str) -> Result<Vec<u8>, PasskeyError> {
    decode_base64url(text).ok_or(PasskeyError::Malformed)
}

fn credential_id(kind: &str, id: &str) -> Result<Vec<u8>, PasskeyError> {
    let id = decode(id)?;
    if kind != "public-key" || id.is_empty() || id.len() > MAX_CREDENTIAL_ID_LEN {
        return Err(PasskeyError::Malformed);
    }
    Ok(id)
}

/// What the browser says about the ceremony (WebAuthn section 5.8.1). It writes this itself, so
/// a page on another site can't claim to be ours.
fn check_client_data(
    rp: &RelyingParty<'_>,
    ceremony: &str,
    challenge: &[u8],
    json: &[u8],
) -> Result<(), PasskeyError> {
    let data: ClientData = serde_json::from_slice(json).map_err(|_| PasskeyError::Malformed)?;
    let answered = decode(&data.challenge)?;
    if data.kind != ceremony
        || answered != challenge
        || data.origin != rp.origin
        || data.cross_origin
    {
        return Err(PasskeyError::WrongContext);
    }
    Ok(())
}

/// What the authenticator says (WebAuthn section 6.1). It is covered by the signature of an
/// assertion, but not of a new passkey, since we ask for no attestation.
struct AuthenticatorData<'a> {
    rp_id_hash: &'a [u8],
    flags: u8,
    sign_count: u32,
    attested: Option<AttestedCredential<'a>>,
}

struct AttestedCredential<'a> {
    credential_id: &'a [u8],
    public_key: &'a [u8],
}

impl<'a> AuthenticatorData<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, PasskeyError> {
        Self::parse_parts(bytes).ok_or(PasskeyError::Malformed)
    }

    fn parse_parts(bytes: &'a [u8]) -> Option<Self> {
        let (rp_id_hash, rest) = bytes.split_at_checked(32)?;
        let (&flags, rest) = rest.split_first()?;
        let (count, mut rest) = rest.split_first_chunk::<4>()?;
        let mut attested = None;
        if flags & ATTESTED_CREDENTIAL != 0 {
            // The authenticator's model (AAGUID), which we don't use, then the credential.
            let (_, after) = rest.split_at_checked(16)?;
            let (len, after) = after.split_first_chunk::<2>()?;
            let len = usize::from(u16::from_be_bytes(*len));
            let (credential_id, after) = after.split_at_checked(len)?;
            let (_, after_key) = cbor::decode_prefix(after)?;
            let key_len = after.len().checked_sub(after_key.len())?;
            attested = Some(AttestedCredential {
                credential_id,
                public_key: after.get(..key_len)?,
            });
            rest = after_key;
        }
        if flags & EXTENSIONS != 0 {
            let (Value::Map(_), after) = cbor::decode_prefix(rest)? else {
                return None;
            };
            rest = after;
        }
        rest.is_empty().then_some(Self {
            rp_id_hash,
            flags,
            sign_count: u32::from_be_bytes(*count),
            attested,
        })
    }

    fn check(&self, rp: &RelyingParty<'_>) -> Result<(), PasskeyError> {
        if self.rp_id_hash != sha256(rp.id.as_bytes()) {
            return Err(PasskeyError::WrongContext);
        }
        let verified = USER_PRESENT | USER_VERIFIED;
        if self.flags & verified != verified {
            return Err(PasskeyError::NotVerified);
        }
        if self.flags & BACKED_UP != 0 && self.flags & BACKUP_ELIGIBLE == 0 {
            return Err(PasskeyError::Malformed);
        }
        Ok(())
    }
}

/// A public key from a `COSE_Key`, for one of [`ALGORITHMS`].
enum PublicKey {
    Parsed(ParsedPublicKey),
    Rsa { n: Vec<u8>, e: Vec<u8> },
}

impl PublicKey {
    fn from_cose(bytes: &[u8]) -> Result<Self, PasskeyError> {
        let key = cbor::decode(bytes).ok_or(PasskeyError::Malformed)?;
        let field = |label| key.get(&Value::Integer(label));
        let bytes = |label| match field(label) {
            Some(Value::Bytes(bytes)) => Ok(*bytes),
            _ => Err(PasskeyError::UnsupportedKey),
        };
        let parsed = |algorithm: &'static dyn VerificationAlgorithm, bytes: &[u8]| {
            ParsedPublicKey::new(algorithm, bytes)
                .map(Self::Parsed)
                .map_err(|_| PasskeyError::UnsupportedKey)
        };
        // Key type (1), algorithm (3) and curve (-1) of RFC 9053.
        let (Some(Value::Integer(kty)), Some(Value::Integer(alg))) = (field(1), field(3)) else {
            return Err(PasskeyError::UnsupportedKey);
        };
        let curve = field(-1);
        match (kty, alg) {
            // EC2 on P-256 with ES256: x (-2) and y (-3), joined into an uncompressed point.
            (2, -7) if curve == Some(&Value::Integer(1)) => {
                let (x, y) = (bytes(-2)?, bytes(-3)?);
                if x.len() != 32 || y.len() != 32 {
                    return Err(PasskeyError::UnsupportedKey);
                }
                parsed(&ECDSA_P256_SHA256_ASN1, &[&[4], x, y].concat())
            }
            // OKP on Ed25519 with EdDSA: x (-2).
            (1, -8) if curve == Some(&Value::Integer(6)) => parsed(&ED25519, bytes(-2)?),
            // RSA with RS256: n (-1) and e (-2).
            (3, -257) => {
                let (n, e) = (bytes(-1)?, bytes(-2)?);
                let n_fits = (MIN_RSA_MODULUS_LEN..=MAX_RSA_MODULUS_LEN).contains(&n.len());
                if !n_fits || n.first() == Some(&0) || !valid_exponent(e) {
                    return Err(PasskeyError::UnsupportedKey);
                }
                Ok(Self::Rsa {
                    n: n.to_vec(),
                    e: e.to_vec(),
                })
            }
            _ => Err(PasskeyError::UnsupportedKey),
        }
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        match self {
            Self::Parsed(key) => key.verify_sig(message, signature).is_ok(),
            Self::Rsa { n, e } => RsaPublicKeyComponents { n, e }
                .verify(&RSA_PKCS1_2048_8192_SHA256, message, signature)
                .is_ok(),
        }
    }
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::rsa::KeySize;
    use aws_lc_rs::signature::{
        ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair as _,
        RSA_PKCS1_SHA256, RsaKeyPair,
    };

    use super::*;
    use crate::encoding::base64url;

    const RP: RelyingParty<'static> = RelyingParty {
        id: "login.example.com",
        origin: "https://login.example.com",
    };

    /// A CBOR byte string.
    fn bytes(data: &[u8]) -> Vec<u8> {
        let [high, low] = u16::try_from(data.len()).unwrap().to_be_bytes();
        [&[0x59, high, low][..], data].concat()
    }

    /// The key of a software authenticator.
    enum Key {
        Ec(EcdsaKeyPair),
        Ed(Ed25519KeyPair),
        Rsa(RsaKeyPair),
    }

    impl Key {
        fn cose(&self) -> Vec<u8> {
            match self {
                // {1: 2, 3: -7, -1: 1, -2: x, -3: y}
                Self::Ec(pair) => {
                    let point = pair.public_key().as_ref();
                    let start = [0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21];
                    [
                        &start[..],
                        &bytes(&point[1..33]),
                        &[0x22],
                        &bytes(&point[33..]),
                    ]
                    .concat()
                }
                // {1: 1, 3: -8, -1: 6, -2: x}
                Self::Ed(pair) => {
                    let start = [0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21];
                    [&start[..], &bytes(pair.public_key().as_ref())].concat()
                }
                // {1: 3, 3: -257, -1: n, -2: e}
                Self::Rsa(pair) => {
                    let public = pair.public_key();
                    let start = [0xa4, 0x01, 0x03, 0x03, 0x39, 0x01, 0x00, 0x20];
                    let n = bytes(public.modulus().big_endian_without_leading_zero());
                    let e = bytes(public.exponent().big_endian_without_leading_zero());
                    [&start[..], &n, &[0x21], &e].concat()
                }
            }
        }

        fn sign(&self, message: &[u8]) -> Vec<u8> {
            let rng = SystemRandom::new();
            match self {
                Self::Ec(pair) => pair.sign(&rng, message).unwrap().as_ref().to_vec(),
                Self::Ed(pair) => pair.sign(message).as_ref().to_vec(),
                Self::Rsa(pair) => {
                    let mut signature = vec![0; pair.public_modulus_len()];
                    pair.sign(&RSA_PKCS1_SHA256, &rng, message, &mut signature)
                        .unwrap();
                    signature
                }
            }
        }
    }

    fn client_data(kind: &str, challenge: &[u8], origin: &str) -> String {
        let json = format!(
            r#"{{"type":"{kind}","challenge":"{}","origin":"{origin}","crossOrigin":false}}"#,
            base64url(challenge)
        );
        base64url(json.as_bytes())
    }

    /// What `navigator.credentials.create()` gives for `key`, with "none" attestation.
    fn created(key: &Key, id: &[u8], challenge: &[u8]) -> String {
        let mut data = sha256(RP.id.as_bytes()).to_vec();
        data.push(USER_PRESENT | USER_VERIFIED | ATTESTED_CREDENTIAL);
        // The counter and the AAGUID.
        data.extend_from_slice(&[0; 20]);
        data.extend_from_slice(&u16::try_from(id.len()).unwrap().to_be_bytes());
        data.extend_from_slice(id);
        data.extend_from_slice(&key.cose());
        // {"fmt": "none", "attStmt": {}, "authData": data}
        let start = b"\xa3\x63fmt\x64none\x67attStmt\xa0\x68authData";
        let object = [&start[..], &bytes(&data)].concat();
        format!(
            r#"{{"id":"{}","type":"public-key","response":{{"clientDataJSON":"{}",
            "attestationObject":"{}","transports":["internal","carrier pigeon"]}}}}"#,
            base64url(id),
            client_data("webauthn.create", challenge, RP.origin),
            base64url(&object)
        )
    }

    /// What `navigator.credentials.get()` gives for `key`.
    fn signed(key: &Key, challenge: &[u8], flags: u8, count: u32, origin: &str) -> String {
        let mut data = sha256(RP.id.as_bytes()).to_vec();
        data.push(flags);
        data.extend_from_slice(&count.to_be_bytes());
        let client = client_data("webauthn.get", challenge, origin);
        let signed = [&data[..], &sha256(&decode_base64url(&client).unwrap())].concat();
        format!(
            r#"{{"id":"AQID","type":"public-key","response":{{"clientDataJSON":"{client}",
            "authenticatorData":"{}","signature":"{}","userHandle":"YW5uYQ"}}}}"#,
            base64url(&data),
            base64url(&key.sign(&signed))
        )
    }

    #[test]
    fn passkeys_sign_in_only_with_their_key_here_once_per_count() {
        let keys = [
            Key::Ec(EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap()),
            Key::Ed(Ed25519KeyPair::generate().unwrap()),
            Key::Rsa(RsaKeyPair::generate(KeySize::Rsa2048).unwrap()),
        ];
        let other = Key::Ed(Ed25519KeyPair::generate().unwrap());
        let verified = USER_PRESENT | USER_VERIFIED;
        for key in &keys {
            let new = register(&RP, b"create", &created(key, &[1, 2, 3], b"create")).unwrap();
            assert_eq!(new.credential_id, [1, 2, 3]);
            assert_eq!(new.transports, ["internal"]);

            let check = |json: String, stored| {
                let assertion = Assertion::parse(&json)?;
                assert_eq!(assertion.user_handle.as_deref(), Some(&b"anna"[..]));
                assertion.verify(&RP, b"get", &new.public_key, stored)
            };
            assert_eq!(check(signed(key, b"get", verified, 1, RP.origin), 0), Ok(1));
            assert_eq!(
                check(signed(key, b"get", verified, 1, RP.origin), 1),
                Err(PasskeyError::CounterWentBack)
            );
            // Synced passkeys keep no counter.
            assert_eq!(check(signed(key, b"get", verified, 0, RP.origin), 0), Ok(0));
            assert_eq!(
                check(signed(key, b"get", USER_PRESENT, 2, RP.origin), 1),
                Err(PasskeyError::NotVerified)
            );
            for (challenge, origin) in [(&b"old"[..], RP.origin), (b"get", "https://evil.example")]
            {
                assert_eq!(
                    check(signed(key, challenge, verified, 2, origin), 1),
                    Err(PasskeyError::WrongContext)
                );
            }
            assert_eq!(
                check(signed(&other, b"get", verified, 2, RP.origin), 1),
                Err(PasskeyError::BadSignature)
            );
        }
        let stale = created(&keys[0], &[1, 2, 3], b"old");
        assert_eq!(
            register(&RP, b"create", &stale).err(),
            Some(PasskeyError::WrongContext)
        );
    }
}
