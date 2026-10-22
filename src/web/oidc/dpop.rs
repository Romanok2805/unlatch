//! DPoP (RFC 9449): tokens bound to a key that the client keeps. Each request with such a token
//! carries a fresh proof signed with the key, so a token that leaks is useless on its own.

use serde::Deserialize;

use super::super::App;
use crate::crypto::{Algorithm, sha256, verify_self_signed};
use crate::encoding::base64url;
use crate::http::Request;
use crate::time;

/// How far the time in a proof may be from ours, either way.
const WINDOW: u64 = 60;
const MAX_JTI_LEN: usize = 256;

/// The algorithms a proof may be signed with, for discovery and `WWW-Authenticate`.
pub(crate) fn algorithms() -> Vec<&'static str> {
    Algorithm::ALL.into_iter().map(Algorithm::name).collect()
}

#[derive(Deserialize)]
struct Claims {
    jti: String,
    htm: String,
    htu: String,
    iat: i64,
    ath: Option<String>,
}

/// Checks the DPoP proof of a request to `path` (RFC 9449 section 4.3), if it has one, and
/// returns the thumbprint of its key. At a resource, `access_token` is the token the proof must
/// name. The error says what is wrong, for the client.
pub(crate) fn check(
    app: &App,
    request: &Request,
    path: &str,
    access_token: Option<&str>,
) -> Result<Option<String>, &'static str> {
    let proof = match request.only_header("dpop") {
        Ok(Some(proof)) => proof,
        Ok(None) => return Ok(None),
        Err(()) => return Err("send exactly one DPoP proof"),
    };
    let (payload, thumbprint) =
        verify_self_signed(proof, "dpop+jwt").map_err(|_| "the DPoP proof isn't validly signed")?;
    let claims: Claims =
        serde_json::from_slice(&payload).map_err(|_| "the DPoP proof lacks claims")?;
    if claims.htm != request.method.as_str() {
        return Err("the DPoP proof is for another method");
    }
    // The address without query and fragment, which the proof doesn't cover.
    let htu = claims.htu.split(['?', '#']).next().unwrap_or_default();
    if htu != app.config.issuer.url(path) {
        return Err("the DPoP proof is for another address");
    }
    let now = time::now();
    if now.abs_diff(claims.iat) > WINDOW {
        return Err("the DPoP proof is too old or from the future");
    }
    if let Some(token) = access_token
        && claims.ath != Some(base64url(&sha256(token.as_bytes())))
    {
        return Err("the DPoP proof is for another access token");
    }
    if claims.jti.is_empty() || claims.jti.len() > MAX_JTI_LEN {
        return Err("the DPoP proof needs a jti");
    }
    // A proof is accepted once (RFC 9449 section 11.1), identified by its key and `jti`.
    let id = sha256(format!("{thumbprint} {}", claims.jti).as_bytes());
    let until = claims.iat.saturating_add_unsigned(WINDOW);
    if !app.dpop_proofs.first_use(id, until, now) {
        return Err("the DPoP proof was used before");
    }
    Ok(Some(thumbprint))
}
