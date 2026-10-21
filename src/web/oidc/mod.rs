//! OpenID Connect and the OAuth 2.0 endpoints it builds on.

mod authorize;
pub(crate) mod backchannel;
pub(crate) mod cors;
mod discovery;
pub(crate) mod dpop;
pub(crate) mod keys;
mod logout;
mod par;
mod request;
mod token;
mod tokens;
mod userinfo;

pub(crate) use self::authorize::{authorize, client_name_for, decide, resume};
pub(crate) use self::discovery::{discovery, jwks};
pub(crate) use self::logout::end_session;
pub(crate) use self::par::push;
pub(crate) use self::token::token;
pub(crate) use self::userinfo::{introspect, revoke, userinfo};
use crate::form::encode_pairs;

/// The scopes we understand, in the order they appear in a granted scope.
pub(crate) const SCOPES: [&str; 5] = ["openid", "profile", "email", "groups", "offline_access"];

/// A code must be redeemed within a minute.
const CODE_LIFETIME: i64 = 60;
/// Signing in for an authorization request may take this long.
const REQUEST_LIFETIME: i64 = 30 * 60;
/// A pushed request must reach `/authorize` within a minute.
const PUSHED_REQUEST_LIFETIME: i64 = 60;
const ACCESS_TOKEN_LIFETIME: i64 = 5 * 60;
const ID_TOKEN_LIFETIME: i64 = 5 * 60;

/// `uri` with parameters added to its query string.
fn append_query(uri: &str, pairs: &[(&str, &str)]) -> String {
    if pairs.is_empty() {
        return uri.to_owned();
    }
    let separator = if uri.contains('?') { '&' } else { '?' };
    format!("{uri}{separator}{}", encode_pairs(pairs.iter().copied()))
}
