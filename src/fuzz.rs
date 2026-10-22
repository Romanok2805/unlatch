//! Entry points for the fuzz targets in `fuzz/`, compiled only with `--cfg fuzzing`. Each one
//! feeds arbitrary bytes to code that reads untrusted input and checks what must always hold. A
//! failed check panics, and the fuzzer reports the input.

#![expect(
    clippy::missing_panics_doc,
    reason = "a fuzz target reports a broken invariant by panicking"
)]

use std::sync::OnceLock;

use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair as _};

use crate::cbor;
use crate::crypto::passkey::{self, Assertion, RelyingParty};
use crate::crypto::{Algorithm, SigningKey, VerifyingKey, verify_jwt, verify_self_signed};
use crate::encoding::{base64url, decode_base64_standard, decode_base64url};
use crate::form::{Form, decode_component, encode};
use crate::html::Html;
use crate::uri::RedirectUri;

/// Query strings and form bodies. A decoded value encodes back to itself.
pub fn form(data: &[u8]) {
    let Ok(text) = str::from_utf8(data) else {
        return;
    };
    if let Ok(form) = Form::parse(text) {
        drop(form.single(text));
    }
    if let Ok(decoded) = decode_component(text) {
        assert_eq!(decode_component(&encode(&decoded)).ok(), Some(decoded));
    }
}

/// Signed tokens from clients and providers, and DPoP proofs. A fuzzer can't forge a signature,
/// so nothing may verify against our key.
pub fn jws(data: &[u8]) {
    static KEY: OnceLock<Option<VerifyingKey>> = OnceLock::new();
    let Ok(text) = str::from_utf8(data) else {
        return;
    };
    let key = KEY.get_or_init(|| {
        SigningKey::generate(Algorithm::EdDsa)
            .ok()
            .map(|(key, _)| key.verifying_key().clone())
    });
    if let Some(key) = key {
        assert!(verify_jwt(text, std::slice::from_ref(key), None).is_err());
    }
    drop(verify_self_signed(text, "dpop+jwt"));
}

/// Answers from browsers to passkey challenges, and the CBOR inside them. A fuzzer can't forge a
/// signature, so no assertion may verify against our key.
pub fn passkey(data: &[u8]) {
    const RP: RelyingParty<'static> = RelyingParty {
        id: "login.example.com",
        origin: "https://login.example.com",
    };
    static KEY: OnceLock<Option<Vec<u8>>> = OnceLock::new();
    drop(cbor::decode(data));
    let Ok(text) = str::from_utf8(data) else {
        return;
    };
    drop(passkey::register(&RP, b"challenge", text));
    // Our key as an Ed25519 COSE_Key: {1: 1, 3: -8, -1: 6, -2: x}.
    let key = KEY.get_or_init(|| {
        let pair = Ed25519KeyPair::generate().ok()?;
        let start = [0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20];
        Some([&start[..], pair.public_key().as_ref()].concat())
    });
    if let (Some(key), Ok(assertion)) = (key, Assertion::parse(text)) {
        assert!(assertion.verify(&RP, b"challenge", key, 0).is_err());
    }
}

/// Base64 decoding inverts encoding, and is strict: whatever it accepts, it would produce.
pub fn base64(data: &[u8]) {
    assert_eq!(decode_base64url(&base64url(data)).as_deref(), Some(data));
    if let Ok(text) = str::from_utf8(data) {
        if let Some(bytes) = decode_base64url(text) {
            assert_eq!(base64url(&bytes), text);
        }
        drop(decode_base64_standard(text));
    }
}

/// Text in pages: escaped, it can't open a tag, leave a quoted attribute or start an entity of
/// its own.
pub fn html(data: &[u8]) {
    const ENTITIES: [&str; 5] = ["&amp;", "&lt;", "&gt;", "&quot;", "&#39;"];
    let Ok(text) = str::from_utf8(data) else {
        return;
    };
    let mut html = Html::new();
    html.push_text(text);
    let out = html.into_string();
    assert!(!out.contains(['<', '>', '"', '\'']));
    for (at, _) in out.match_indices('&') {
        let rest = out.get(at..).unwrap_or_default();
        assert!(ENTITIES.iter().any(|entity| rest.starts_with(entity)));
    }
}

/// Whether `requested` is accepted for a client that registered `registered`, if that is a valid
/// redirect URI. The target checks the answer against an independent URL parser.
#[must_use]
pub fn redirect_uri_matches(registered: &str, requested: &str) -> Option<bool> {
    RedirectUri::parse(registered)
        .ok()
        .map(|uri| uri.matches(requested))
}

/// Whether a `next` address is accepted as a path on this server. The target checks that a
/// browser would resolve it to our host.
#[must_use]
pub fn is_local_path(path: &str) -> bool {
    crate::web::is_local_path(path)
}
