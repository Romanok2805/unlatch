//! Authorization requests: checking them, and carrying them sealed through sign-in.

use serde::{Deserialize, Serialize};

use super::super::{App, Failure};
use super::{PUSHED_REQUEST_LIFETIME, REQUEST_LIFETIME, SCOPES};
use crate::crypto::{CryptoError, SealingKey};
use crate::encoding::{base64url, decode_base64url};
use crate::form::Form;
use crate::store::apps::{self, AppRecord, Kind};
use crate::time;

/// State and nonce travel inside sealed cookies, which browsers cap at 4 KB.
const MAX_STATE_LEN: usize = 512;
const MAX_NONCE_LEN: usize = 256;
const MAX_LOGIN_HINT_LEN: usize = 100;
/// The parameters of an authorization request. OAuth forbids repeating any of them.
const PARAMETERS: [&str; 16] = [
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "state",
    "nonce",
    "code_challenge",
    "code_challenge_method",
    "prompt",
    "max_age",
    "resource",
    "login_hint",
    "response_mode",
    "request",
    "request_uri",
    "dpop_jkt",
];
/// Ten years; larger values mean "don't care" and only risk overflow.
const MAX_MAX_AGE: i64 = 10 * 365 * 24 * 60 * 60;

/// A checked authorization request. It travels sealed in the `req` parameter while the user
/// signs in, so nothing is stored for requests that are never finished.
#[derive(Serialize, Deserialize)]
pub(crate) struct AuthRequest {
    pub(crate) client_id: String,
    pub(crate) client_name: String,
    pub(crate) redirect_uri: String,
    /// The granted scopes: the requested ones we support, in a fixed order.
    pub(crate) scope: String,
    pub(crate) state: Option<String>,
    pub(crate) nonce: Option<String>,
    pub(crate) code_challenge: String,
    pub(crate) resource: Option<String>,
    pub(crate) prompt: Prompt,
    pub(crate) max_age: Option<i64>,
    pub(crate) login_hint: Option<String>,
    /// Answer with a posted form instead of query parameters (OAuth 2.0 Form Post Response
    /// Mode).
    pub(crate) form_post: bool,
    /// The thumbprint of the DPoP key the code may only be redeemed with (RFC 9449 section 10).
    pub(crate) dpop_jkt: Option<String>,
    pub(crate) issued_at: i64,
}

const CONTEXT: &[u8] = b"authorization request";
const PUSHED_CONTEXT: &[u8] = b"pushed authorization request";
/// What a `request_uri` from `/par` starts with (RFC 9126 section 2.2).
const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

impl AuthRequest {
    pub(crate) fn seal(&self, key: &SealingKey) -> Result<String, CryptoError> {
        self.seal_as(key, CONTEXT)
    }

    /// The request in a `req` value, unless it was altered or is older than half an hour.
    pub(crate) fn open(text: &str, key: &SealingKey) -> Option<Self> {
        Self::open_as(text, key, CONTEXT, REQUEST_LIFETIME)
    }

    /// The `request_uri` of a pushed request: the request itself, sealed. Nothing is stored, so
    /// pushing requests that are never used costs nothing. Within its minute it can be used more
    /// than once, as when a page is reloaded; each use only repeats the same request of the
    /// same client, and PKCE keeps the codes useless to anyone else.
    pub(crate) fn request_uri(&self, key: &SealingKey) -> Result<String, CryptoError> {
        Ok(format!(
            "{REQUEST_URI_PREFIX}{}",
            self.seal_as(key, PUSHED_CONTEXT)?
        ))
    }

    fn open_pushed(text: &str, key: &SealingKey) -> Option<Self> {
        Self::open_as(text, key, PUSHED_CONTEXT, PUSHED_REQUEST_LIFETIME)
    }

    fn seal_as(&self, key: &SealingKey, context: &[u8]) -> Result<String, CryptoError> {
        let json = serde_json::to_vec(self).map_err(|_| CryptoError)?;
        Ok(base64url(&key.seal(&json, context)?))
    }

    fn open_as(text: &str, key: &SealingKey, context: &[u8], lifetime: i64) -> Option<Self> {
        let json = key.open(&decode_base64url(text)?, context)?;
        let request: Self = serde_json::from_slice(json.expose()).ok()?;
        let age = time::now().saturating_sub(request.issued_at);
        (0..lifetime).contains(&age).then_some(request)
    }

    pub(crate) fn scopes(&self) -> impl Iterator<Item = &str> {
        self.scope.split(' ').filter(|scope| !scope.is_empty())
    }

    /// Whether the client still accepts this request as it is registered now: an administrator
    /// may have removed the redirect URI or resource since the request was checked.
    pub(crate) fn fits(&self, client: &AppRecord) -> bool {
        accepts(client, &self.redirect_uri)
            && self
                .resource
                .as_ref()
                .is_none_or(|resource| client.resources.contains(resource))
    }
}

/// Whether `redirect_uri` is registered for the client.
fn accepts(client: &AppRecord, redirect_uri: &str) -> bool {
    client.kind == Kind::Oidc
        && client
            .redirect_uris
            .iter()
            .any(|uri| uri.matches(redirect_uri))
}

/// Why a request was refused.
pub(crate) enum Rejection {
    /// The client or redirect URI is unknown, so the error can't be sent back: it would let
    /// anyone use us to redirect users wherever they like. It is shown as a page instead.
    Page,
    /// Sent back to the client, as RFC 6749 section 4.1.2.1 describes.
    Redirect {
        redirect_uri: String,
        state: Option<String>,
        form_post: bool,
        error: &'static str,
        description: &'static str,
    },
}

/// How an authorization request arrived.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Arrival {
    /// Through the browser, at `/authorize`.
    Browser,
    /// From the client directly, at `/par` (RFC 9126).
    Pushed,
}

/// Checks an authorization request: the query or form of `/authorize`, or the body of `/par`.
pub(crate) async fn check(
    app: &App,
    form: &Form,
    arrival: Arrival,
) -> Result<Result<(AuthRequest, AppRecord), Rejection>, Failure> {
    if arrival == Arrival::Browser
        && let Ok(Some(request_uri)) = form.single("request_uri")
    {
        return pushed(app, form, request_uri).await;
    }
    // A repeated parameter is ambiguous, so the request is refused rather than guessed at.
    let (Ok(Some(client_id)), Ok(Some(redirect_uri))) =
        (form.single("client_id"), form.single("redirect_uri"))
    else {
        return Ok(Err(Rejection::Page));
    };
    let lookup = client_id.to_owned();
    let client = app
        .db
        .run(move |conn| apps::by_client_id(conn, &lookup))
        .await?;
    let Some(client) = client.filter(|client| accepts(client, redirect_uri)) else {
        return Ok(Err(Rejection::Page));
    };

    let value = |name| form.single(name).ok().flatten();
    let state = value("state").map(str::to_owned);
    let form_post = value("response_mode") == Some("form_post");
    let reject = |error, description| Rejection::Redirect {
        redirect_uri: redirect_uri.to_owned(),
        state: state.clone().filter(|state| state.len() <= MAX_STATE_LEN),
        form_post,
        error,
        description,
    };
    if PARAMETERS.iter().any(|name| form.single(name).is_err()) {
        return Ok(Err(reject("invalid_request", "a parameter is repeated")));
    }
    if !client.enabled {
        return Ok(Err(reject(
            "unauthorized_client",
            "the application is disabled",
        )));
    }
    if arrival == Arrival::Browser && client.require_par {
        return Ok(Err(reject(
            "invalid_request",
            "this application must push its authorization requests",
        )));
    }
    let checked = match validate(form, &client) {
        Ok(checked) => checked,
        Err((error, description)) => return Ok(Err(reject(error, description))),
    };
    let request = AuthRequest {
        client_id: client_id.to_owned(),
        client_name: client.name.clone(),
        redirect_uri: redirect_uri.to_owned(),
        scope: checked.scope,
        state,
        nonce: value("nonce").map(str::to_owned),
        code_challenge: checked.challenge,
        resource: value("resource").map(str::to_owned),
        prompt: checked.prompt,
        max_age: checked.max_age,
        login_hint: value("login_hint")
            .filter(|hint| hint.len() <= MAX_LOGIN_HINT_LEN)
            .map(str::to_owned),
        form_post,
        dpop_jkt: value("dpop_jkt").map(str::to_owned),
        issued_at: time::now(),
    };
    Ok(Ok((request, client)))
}

/// A request pushed earlier, which `/authorize` gets as the `request_uri` that `/par` returned.
/// Nothing else in the query counts, except that `client_id` must name the same client.
async fn pushed(
    app: &App,
    form: &Form,
    request_uri: &str,
) -> Result<Result<(AuthRequest, AppRecord), Rejection>, Failure> {
    let client_id = form.single("client_id").ok().flatten();
    let Some(auth) = request_uri
        .strip_prefix(REQUEST_URI_PREFIX)
        .and_then(|sealed| AuthRequest::open_pushed(sealed, &app.keys.requests))
        .filter(|auth| client_id == Some(auth.client_id.as_str()))
    else {
        return Ok(Err(Rejection::Page));
    };
    let lookup = auth.client_id.clone();
    let client = app
        .db
        .run(move |conn| apps::by_client_id(conn, &lookup))
        .await?;
    Ok(client.map(|client| (auth, client)).ok_or(Rejection::Page))
}

/// The parts of a request that needed parsing.
struct Checked {
    scope: String,
    challenge: String,
    prompt: Prompt,
    max_age: Option<i64>,
}

/// What the client asked for with `prompt`.
#[derive(Default, Serialize, Deserialize)]
pub(crate) struct Prompt {
    /// Don't show anything; fail if the user would have to act.
    pub(crate) none: bool,
    /// Sign in again, even if signed in already.
    pub(crate) login: bool,
    /// Ask for consent again.
    pub(crate) consent: bool,
}

/// Checks everything but the client and redirect URI. Errors are `(error, description)` for
/// the redirect back to the client.
fn validate(form: &Form, client: &AppRecord) -> Result<Checked, (&'static str, &'static str)> {
    let value = |name: &str| form.single(name).ok().flatten();
    if value("request").is_some() {
        return Err(("request_not_supported", "request objects are not supported"));
    }
    // Only a pushed request gets here with one, and it can't refer to another (RFC 9126).
    if value("request_uri").is_some() {
        return Err((
            "invalid_request",
            "a pushed request can't have a request_uri",
        ));
    }
    if value("response_type") != Some("code") {
        return Err((
            "unsupported_response_type",
            "only the code flow is supported",
        ));
    }
    if value("response_mode").is_some_and(|mode| mode != "query" && mode != "form_post") {
        return Err((
            "invalid_request",
            "use the query or form_post response mode",
        ));
    }
    if value("state").is_some_and(|state| state.len() > MAX_STATE_LEN) {
        return Err(("invalid_request", "state is too long"));
    }
    if value("nonce").is_some_and(|nonce| nonce.len() > MAX_NONCE_LEN) {
        return Err(("invalid_request", "nonce is too long"));
    }
    // PKCE with S256 is required of every client (OAuth 2.0 Security BCP, RFC 9700).
    let challenge =
        value("code_challenge").ok_or(("invalid_request", "code_challenge is required"))?;
    if value("code_challenge_method") != Some("S256") {
        return Err(("invalid_request", "code_challenge_method must be S256"));
    }
    if decode_base64url(challenge).is_none_or(|digest| digest.len() != 32) {
        return Err((
            "invalid_request",
            "code_challenge must be a base64url SHA-256 hash",
        ));
    }
    let max_age = match value("max_age").map(str::parse::<i64>) {
        None => None,
        Some(Ok(seconds)) if (0..=MAX_MAX_AGE).contains(&seconds) => Some(seconds),
        Some(_) => return Err(("invalid_request", "max_age must be a number of seconds")),
    };
    let prompt = parse_prompt(value("prompt").unwrap_or_default())?;
    if value("dpop_jkt")
        .is_some_and(|jkt| decode_base64url(jkt).is_none_or(|hash| hash.len() != 32))
    {
        return Err((
            "invalid_request",
            "dpop_jkt must be a base64url SHA-256 thumbprint",
        ));
    }
    if value("resource")
        .is_some_and(|resource| !client.resources.iter().any(|known| known == resource))
    {
        return Err((
            "invalid_target",
            "the resource isn't registered for this application",
        ));
    }
    // Unknown scopes are ignored, as OpenID Connect asks; the granted scope lists only ours.
    let requested: Vec<&str> = value("scope").unwrap_or_default().split(' ').collect();
    let granted: Vec<&str> = SCOPES
        .into_iter()
        .filter(|known| requested.contains(known))
        .collect();
    Ok(Checked {
        scope: granted.join(" "),
        challenge: challenge.to_owned(),
        prompt,
        max_age,
    })
}

fn parse_prompt(text: &str) -> Result<Prompt, (&'static str, &'static str)> {
    let mut prompt = Prompt::default();
    let mut count = 0_usize;
    for value in text.split(' ').filter(|value| !value.is_empty()) {
        count = count.saturating_add(1);
        match value {
            "none" => prompt.none = true,
            // We have one account per browser, so choosing one means signing in again.
            "login" | "select_account" => prompt.login = true,
            "consent" => prompt.consent = true,
            _ => return Err(("invalid_request", "unknown prompt value")),
        }
    }
    if prompt.none && count > 1 {
        return Err(("invalid_request", "prompt=none can't be combined"));
    }
    Ok(prompt)
}
