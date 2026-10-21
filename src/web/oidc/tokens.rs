//! Minting tokens, and the claims they carry about users.

use serde::{Deserialize, Serialize};

use super::super::App;
use super::keys::KeyRing;
use super::{ACCESS_TOKEN_LIFETIME, ID_TOKEN_LIFETIME};
use crate::crypto::{Algorithm, CryptoError, random_bytes};
use crate::encoding::{base64url, decode_base64url};
use crate::store::grants::GrantId;
use crate::store::sessions::ActiveSession;
use crate::store::users::{User, UserId};

/// The `sub` of a user: stable and opaque. It is derived from the user's row with a key, so it
/// reveals neither the order of accounts nor how many there are.
pub(crate) fn subject(app: &App, user: UserId) -> String {
    base64url(&app.keys.subject.sign(&user.0.to_be_bytes()))
        .chars()
        .take(22)
        .collect()
}

/// What we tell applications about a user, limited to the granted scopes.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct UserClaims {
    pub(crate) sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    groups: Option<Vec<String>>,
}

impl UserClaims {
    pub(crate) fn new(app: &App, user: &User, groups: Vec<String>, scope: &str) -> Self {
        let has = |name| scope.split(' ').any(|scope| scope == name);
        let email = user.email.clone().filter(|_| has("email"));
        Self {
            sub: subject(app, user.id),
            name: has("profile").then(|| user.display_name.clone()),
            preferred_username: has("profile").then(|| user.username.clone()),
            email_verified: email.as_ref().map(|_| user.email_verified),
            email,
            groups: has("groups").then_some(groups),
        }
    }
}

/// The claims of an access token (RFC 9068), plus `sid`, which lets us refuse tokens of a
/// session that has ended.
#[derive(Serialize, Deserialize)]
pub(crate) struct AccessClaims {
    pub(crate) iss: String,
    pub(crate) sub: String,
    pub(crate) aud: String,
    pub(crate) client_id: String,
    pub(crate) iat: i64,
    pub(crate) exp: i64,
    pub(crate) jti: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) auth_time: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) sid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cnf: Option<Confirmation>,
}

/// The key a token is bound to (RFC 7800), named by its thumbprint (RFC 9449 section 6).
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Confirmation {
    pub(crate) jkt: String,
}

/// Who an access token is for.
pub(crate) enum Holder<'a> {
    User {
        subject: String,
        session: &'a ActiveSession,
    },
    /// A service acting for itself with the client credentials grant.
    Client,
}

/// What an access token is issued for.
pub(crate) struct Access<'a> {
    pub(crate) client_id: &'a str,
    pub(crate) holder: Holder<'a>,
    pub(crate) scope: &'a str,
    pub(crate) resource: Option<&'a str>,
    /// The thumbprint of the DPoP key the token is bound to.
    pub(crate) dpop: Option<&'a str>,
}

/// An access token. Its audience is the API named with `resource`, or the client itself, so a
/// token issued to one application is refused by every other.
pub(crate) fn access_token(
    app: &App,
    ring: &KeyRing,
    now: i64,
    access: &Access<'_>,
) -> Result<String, CryptoError> {
    let client_id = access.client_id;
    let (sub, auth_time, sid) = match &access.holder {
        Holder::User { subject, session } => (
            subject.clone(),
            Some(session.auth_time),
            Some(session.public_id.clone()),
        ),
        Holder::Client => (client_id.to_owned(), None, None),
    };
    let claims = AccessClaims {
        iss: app.config.issuer.as_str().to_owned(),
        sub,
        aud: access.resource.unwrap_or(client_id).to_owned(),
        client_id: client_id.to_owned(),
        iat: now,
        exp: now.saturating_add(ACCESS_TOKEN_LIFETIME),
        jti: base64url(&random_bytes::<16>()?),
        scope: access.scope.to_owned(),
        auth_time,
        sid,
        cnf: access.dpop.map(|jkt| Confirmation {
            jkt: jkt.to_owned(),
        }),
    };
    // Access tokens are always RS256, which every resource server library understands.
    let key = ring.current(Algorithm::Rs256, now).ok_or(CryptoError)?;
    key.sign_jwt("at+jwt", &claims)
}

#[derive(Serialize)]
struct IdClaims<'a> {
    iss: &'a str,
    aud: &'a str,
    iat: i64,
    exp: i64,
    auth_time: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<&'a str>,
    amr: Vec<&'a str>,
    sid: &'a str,
    #[serde(flatten)]
    user: &'a UserClaims,
}

#[expect(
    clippy::too_many_arguments,
    reason = "each is a separate input to the token"
)]
pub(crate) fn id_token(
    app: &App,
    ring: &KeyRing,
    now: i64,
    client_id: &str,
    algorithm: Algorithm,
    session: &ActiveSession,
    user: &UserClaims,
    nonce: Option<&str>,
) -> Result<String, CryptoError> {
    let claims = IdClaims {
        iss: app.config.issuer.as_str(),
        aud: client_id,
        iat: now,
        exp: now.saturating_add(ID_TOKEN_LIFETIME),
        auth_time: session.auth_time,
        nonce,
        amr: session.amr.split(' ').collect(),
        sid: &session.public_id,
        user,
    };
    let key = ring.current(algorithm, now).ok_or(CryptoError)?;
    key.sign_jwt("JWT", &claims)
}

const REFRESH_CONTEXT: &[u8] = b"refresh token";

/// A refresh token: the grant and its generation, sealed. Nothing about it is stored.
pub(crate) fn refresh_token(
    app: &App,
    grant: GrantId,
    generation: i64,
) -> Result<String, CryptoError> {
    let mut payload = [0; 16];
    let (first, second) = payload.split_at_mut(8);
    first.copy_from_slice(&grant.0.to_be_bytes());
    second.copy_from_slice(&generation.to_be_bytes());
    Ok(base64url(
        &app.keys.refresh.seal(&payload, REFRESH_CONTEXT)?,
    ))
}

pub(crate) fn open_refresh_token(app: &App, token: &str) -> Option<(GrantId, i64)> {
    let payload = app
        .keys
        .refresh
        .open(&decode_base64url(token)?, REFRESH_CONTEXT)?;
    let (grant, generation) = payload.expose().split_at_checked(8)?;
    Some((
        GrantId(i64::from_be_bytes(grant.try_into().ok()?)),
        i64::from_be_bytes(generation.try_into().ok()?),
    ))
}

/// The body of a successful token response (RFC 6749 section 5.1).
#[derive(Serialize)]
pub(crate) struct TokenResponse {
    pub(crate) access_token: String,
    pub(crate) token_type: &'static str,
    pub(crate) expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) refresh_token: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) scope: String,
}
