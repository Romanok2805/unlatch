//! Entry points for the fuzz targets in `fuzz/`, compiled only with `--cfg fuzzing`. Each one
//! feeds arbitrary bytes to code that reads untrusted input and checks what must always hold. A
//! failed check panics, and the fuzzer reports the input.

#![expect(
    clippy::missing_panics_doc,
    reason = "a fuzz target reports a broken invariant by panicking"
)]

use std::sync::OnceLock;

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
