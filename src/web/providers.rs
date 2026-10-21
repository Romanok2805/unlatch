//! Signing in with outside providers: any OpenID Connect provider, such as Google, and GitHub.
//!
//! An outside account is linked to a local one by the provider and its subject only, and only by
//! a user who is already signed in. An email address is never enough: whoever controls an
//! address at the provider would get the local account with that address. New accounts are
//! created only for verified addresses in domains the administrator listed.

use std::collections::HashMap;
use std::sync::{MutexGuard, PoisonError};

use hyper::{Method, StatusCode};
use serde::{Deserialize, Serialize};

use super::csrf;
use super::i18n::Lang;
use super::layout::auth_page;
use super::signin::after_provider;
use super::{App, Failure, is_local_path, session};
use crate::crypto::{VerifyingKey, constant_time_eq, random_token, sha256, verify_jwt};
use crate::encoding::{base64url, decode_base64url};
use crate::form::encode_pairs;
use crate::html::{Html, html};
use crate::http::client::Plain;
use crate::http::cookie::{self, SetCookie};
use crate::http::{Request, Response};
use crate::log::{info, warning};
use crate::store::audit;
use crate::store::providers::{self, Provider, ProviderKind};
use crate::store::users::{self, NewUser, User, UserId, Username};
use crate::time;

const FLOW_COOKIE: &str = "provider";
const FLOW_LIFETIME: i64 = 10 * 60;
/// Discovery documents and key sets are fetched again after this.
const CACHE_LIFETIME: i64 = 60 * 60;
/// Tolerance for clocks that disagree a little.
const CLOCK_SKEW: i64 = 60;

const GITHUB_AUTHORIZE: &str = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN: &str = "https://github.com/login/oauth/access_token";
const GITHUB_USER: &str = "https://api.github.com/user";
const GITHUB_EMAILS: &str = "https://api.github.com/user/emails";

/// What a sign-in with a provider carries from the redirect to the callback, sealed in a cookie
/// so it is bound to this browser.
#[derive(Serialize, Deserialize)]
struct Flow {
    provider: i64,
    state: String,
    nonce: String,
    verifier: String,
    next: String,
    /// Set when a signed-in user is linking the provider instead of signing in.
    link_user: Option<i64>,
    issued_at: i64,
}

#[derive(Clone, Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    #[serde(default)]
    token_endpoint_auth_methods_supported: Vec<String>,
}

/// Discovery documents and public keys of providers, by issuer.
#[derive(Default)]
pub(crate) struct Cache {
    discovery: HashMap<String, (i64, Discovery)>,
    keys: HashMap<String, (i64, Vec<VerifyingKey>)>,
}

/// Who the provider says the user is.
struct Identity {
    subject: String,
    email: Option<String>,
    email_verified: bool,
    name: Option<String>,
}

fn callback_url(app: &App, provider: &Provider) -> String {
    app.config
        .issuer
        .url(&format!("/login/{}/callback", provider.slug))
}

/// The URL to register at the provider as the redirect URI.
pub(crate) fn redirect_uri(app: &App, slug: &str) -> String {
    app.config.issuer.url(&format!("/login/{slug}/callback"))
}

/// The enabled providers, for the buttons on the sign-in page.
pub(crate) async fn enabled(app: &App) -> Result<Vec<Provider>, Failure> {
    let all = app.db.run(|conn| providers::list(conn)).await?;
    Ok(all
        .into_iter()
        .filter(|provider| provider.enabled)
        .collect())
}

/// `GET /login/<slug>`: sends the user to the provider to sign in.
pub(crate) async fn start(
    app: &App,
    request: &Request,
    slug: &str,
) -> Result<Option<Response>, Failure> {
    let lookup = slug.to_owned();
    let Some(provider) = app
        .db
        .run(move |conn| providers::by_slug(conn, &lookup))
        .await?
    else {
        return Ok(None);
    };
    if !provider.enabled {
        return Ok(None);
    }
    let next = request
        .query
        .single("next")
        .ok()
        .flatten()
        .filter(|path| is_local_path(path))
        .unwrap_or("/")
        .to_owned();
    begin(app, request, &provider, next, None).await.map(Some)
}

/// `POST /account/providers`: links or unlinks a provider for the signed-in user.
pub(crate) async fn manage(app: &App, request: &Request) -> Result<Response, Failure> {
    let Some(current) = session::current(app, request).await? else {
        return Ok(session::to_sign_in(request));
    };
    let slug = request
        .form
        .single("provider")
        .ok()
        .flatten()
        .unwrap_or_default()
        .to_owned();
    let provider = app
        .db
        .run(move |conn| providers::by_slug(conn, &slug))
        .await?;
    let (Some(provider), true) = (provider, csrf::verify(app, request)) else {
        return Ok(Response::redirect("/account"));
    };
    if request.form.single("action").ok().flatten() == Some("unlink") {
        let (id, user) = (provider.id, current.user.id);
        app.db
            .run(move |conn| providers::unlink(conn, id, user))
            .await?;
        record(
            app,
            request,
            &current.user.username,
            "unlink sign-in provider",
            &provider.name,
        )
        .await?;
        return Ok(Response::redirect("/account"));
    }
    begin(
        app,
        request,
        &provider,
        "/account".to_owned(),
        Some(current.user.id),
    )
    .await
}

async fn begin(
    app: &App,
    request: &Request,
    provider: &Provider,
    next: String,
    link_user: Option<UserId>,
) -> Result<Response, Failure> {
    let flow = Flow {
        provider: provider.id.0,
        state: random_token()?,
        nonce: random_token()?,
        verifier: random_token()?,
        next,
        link_user: link_user.map(|user| user.0),
        issued_at: time::now(),
    };
    let redirect_uri = callback_url(app, provider);
    let location = match provider.kind {
        ProviderKind::Github => {
            let query = encode_pairs([
                ("client_id", provider.client_id.as_str()),
                ("redirect_uri", &redirect_uri),
                ("scope", "read:user user:email"),
                ("state", &flow.state),
            ]);
            format!("{GITHUB_AUTHORIZE}?{query}")
        }
        ProviderKind::Oidc => {
            let discovery = match discovery(app, provider).await {
                Ok(discovery) => discovery,
                Err(reason) => return Ok(failed(app, request, provider, &reason)),
            };
            let challenge = base64url(&sha256(flow.verifier.as_bytes()));
            let query = encode_pairs([
                ("response_type", "code"),
                ("client_id", provider.client_id.as_str()),
                ("redirect_uri", &redirect_uri),
                ("scope", "openid email profile"),
                ("state", &flow.state),
                ("nonce", &flow.nonce),
                ("code_challenge", &challenge),
                ("code_challenge_method", "S256"),
            ]);
            let separator = if discovery.authorization_endpoint.contains('?') {
                '&'
            } else {
                '?'
            };
            format!("{}{separator}{query}", discovery.authorization_endpoint)
        }
    };
    let json =
        serde_json::to_vec(&flow).map_err(|_| Failure::Crypto(crate::crypto::CryptoError))?;
    let sealed = base64url(&app.keys.signin.seal(&json, FLOW_COOKIE.as_bytes())?);
    let secure = app.config.issuer.is_secure();
    // Lax, because the provider sends the browser back with a top-level navigation.
    let cookie = SetCookie {
        name: &cookie::name(FLOW_COOKIE, secure),
        value: &sealed,
        max_age: Some(FLOW_LIFETIME),
    };
    Ok(Response::redirect(location).cookie(&cookie, secure))
}

/// `GET /login/<slug>/callback`: where the provider sends the user back.
pub(crate) async fn callback(
    app: &App,
    request: &Request,
    slug: &str,
) -> Result<Option<Response>, Failure> {
    if request.method != Method::GET {
        return Ok(None);
    }
    let lookup = slug.to_owned();
    let Some(provider) = app
        .db
        .run(move |conn| providers::by_slug(conn, &lookup))
        .await?
    else {
        return Ok(None);
    };
    let query = |name| request.query.single(name).ok().flatten();
    let flow = read_flow(app, request).filter(|flow| {
        flow.provider == provider.id.0
            && query("state")
                .is_some_and(|state| constant_time_eq(state.as_bytes(), flow.state.as_bytes()))
    });
    let Some(flow) = flow else {
        return Ok(Some(failed(
            app,
            request,
            &provider,
            "the sign-in expired or came from another browser",
        )));
    };
    if let Some(error) = query("error") {
        return Ok(Some(clear_flow(
            app,
            failed(app, request, &provider, error),
        )));
    }
    let Some(code) = query("code") else {
        return Ok(Some(clear_flow(
            app,
            failed(app, request, &provider, "no code"),
        )));
    };
    let identity = match provider.kind {
        ProviderKind::Oidc => oidc_identity(app, &provider, code, &flow).await,
        ProviderKind::Github => github_identity(app, &provider, code).await,
    };
    let response = match identity {
        Ok(identity) => resolve(app, request, &provider, identity, &flow).await?,
        Err(reason) => failed(app, request, &provider, &reason),
    };
    Ok(Some(clear_flow(app, response)))
}

fn read_flow(app: &App, request: &Request) -> Option<Flow> {
    let name = cookie::name(FLOW_COOKIE, app.config.issuer.is_secure());
    let sealed = decode_base64url(request.cookie(&name)?)?;
    let json = app.keys.signin.open(&sealed, FLOW_COOKIE.as_bytes())?;
    let flow: Flow = serde_json::from_slice(json.expose()).ok()?;
    let age = time::now().saturating_sub(flow.issued_at);
    ((0..FLOW_LIFETIME).contains(&age) && is_local_path(&flow.next)).then_some(flow)
}

fn clear_flow(app: &App, response: Response) -> Response {
    let secure = app.config.issuer.is_secure();
    let cookie = SetCookie {
        name: &cookie::name(FLOW_COOKIE, secure),
        value: "",
        max_age: Some(0),
    };
    response.cookie(&cookie, secure)
}

fn client_secret(app: &App, provider: &Provider) -> Option<String> {
    let context = format!("provider {}", provider.id.0);
    let secret = app
        .keys
        .secrets
        .open(&provider.client_secret, context.as_bytes())?;
    String::from_utf8(secret.expose().clone()).ok()
}

/// The provider's discovery document, cached for an hour. Its issuer must be the configured
/// one, or keys and tokens could come from somewhere else.
async fn discovery(app: &App, provider: &Provider) -> Result<Discovery, String> {
    let issuer = provider.issuer.clone().ok_or("no issuer configured")?;
    let now = time::now();
    if let Some((fetched, cached)) = app.provider_cache().discovery.get(&issuer)
        && now.saturating_sub(*fetched) < CACHE_LIFETIME
    {
        return Ok(cached.clone());
    }
    let url = format!("{issuer}/.well-known/openid-configuration");
    let fetched: Discovery = app
        .client
        .get_json(&url, Plain::Loopback, None)
        .await
        .map_err(|e| format!("discovery at {url}: {e}"))?;
    if fetched.issuer != issuer {
        return Err(format!(
            "discovery names the issuer {:?}, not {issuer:?}",
            fetched.issuer
        ));
    }
    app.provider_cache()
        .discovery
        .insert(issuer, (now, fetched.clone()));
    Ok(fetched)
}

/// The provider's signing keys, cached for an hour, or fetched again when `refresh` is set and
/// the cache is older than a minute (a token may name a key added since).
async fn keys(
    app: &App,
    discovery: &Discovery,
    refresh: bool,
) -> Result<Vec<VerifyingKey>, String> {
    #[derive(Deserialize)]
    struct Set {
        keys: Vec<crate::crypto::Jwk>,
    }
    let now = time::now();
    if let Some((fetched, cached)) = app.provider_cache().keys.get(&discovery.issuer) {
        let age = now.saturating_sub(*fetched);
        if age < CACHE_LIFETIME && !(refresh && age > 60) {
            return Ok(cached.clone());
        }
    }
    let set: Set = app
        .client
        .get_json(&discovery.jwks_uri, Plain::Loopback, None)
        .await
        .map_err(|e| format!("keys at {}: {e}", discovery.jwks_uri))?;
    let keys: Vec<VerifyingKey> = set.keys.iter().filter_map(VerifyingKey::from_jwk).collect();
    app.provider_cache()
        .keys
        .insert(discovery.issuer.clone(), (now, keys.clone()));
    Ok(keys)
}

#[derive(Deserialize)]
struct TokenAnswer {
    id_token: Option<String>,
    access_token: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

/// Some providers send `email_verified` as a string.
#[derive(Deserialize)]
#[serde(untagged)]
enum Flag {
    Bool(bool),
    Text(String),
}

#[derive(Deserialize)]
struct IdClaims {
    iss: String,
    sub: String,
    aud: Audience,
    azp: Option<String>,
    exp: i64,
    iat: i64,
    nonce: Option<String>,
    email: Option<String>,
    email_verified: Option<Flag>,
    name: Option<String>,
}

/// Redeems the code and checks the ID token as OpenID Connect Core section 3.1.3.7 requires.
async fn oidc_identity(
    app: &App,
    provider: &Provider,
    code: &str,
    flow: &Flow,
) -> Result<Identity, String> {
    let discovery = discovery(app, provider).await?;
    let secret = client_secret(app, provider).ok_or("the client secret can't be read")?;
    let redirect_uri = callback_url(app, provider);
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri.as_str()),
        ("code_verifier", flow.verifier.as_str()),
    ];
    let methods = &discovery.token_endpoint_auth_methods_supported;
    let basic = methods.is_empty() || methods.iter().any(|method| method == "client_secret_basic");
    if !basic {
        form.push(("client_id", &provider.client_id));
        form.push(("client_secret", &secret));
    }
    let credentials = basic.then_some((provider.client_id.as_str(), secret.as_str()));
    let answer: TokenAnswer = app
        .client
        .post_form(
            &discovery.token_endpoint,
            Plain::Loopback,
            &form,
            credentials,
        )
        .await
        .map_err(|e| format!("token request: {e}"))?;
    let token = answer.id_token.ok_or("no ID token in the answer")?;

    let mut payload = verify_jwt(&token, &keys(app, &discovery, false).await?, None);
    if payload == Err(crate::crypto::JwtError::UnknownKey) {
        payload = verify_jwt(&token, &keys(app, &discovery, true).await?, None);
    }
    let payload = payload.map_err(|e| format!("ID token: {e}"))?;
    let claims: IdClaims =
        serde_json::from_slice(&payload).map_err(|e| format!("ID token claims: {e}"))?;
    let now = time::now();
    let audience_ok = match &claims.aud {
        Audience::One(aud) => *aud == provider.client_id,
        Audience::Many(auds) => {
            auds.contains(&provider.client_id)
                && (auds.len() == 1 || claims.azp.as_deref() == Some(provider.client_id.as_str()))
        }
    };
    if claims.iss != discovery.issuer
        || !audience_ok
        || claims.exp <= now.saturating_sub(CLOCK_SKEW)
        || claims.iat > now.saturating_add(CLOCK_SKEW)
        || !claims
            .nonce
            .as_deref()
            .is_some_and(|nonce| constant_time_eq(nonce.as_bytes(), flow.nonce.as_bytes()))
    {
        return Err("the ID token isn't for this sign-in".to_owned());
    }
    let email_verified = match claims.email_verified {
        Some(Flag::Bool(verified)) => verified,
        Some(Flag::Text(text)) => text == "true",
        None => false,
    };
    Ok(Identity {
        subject: claims.sub,
        email: claims.email,
        email_verified,
        name: claims.name,
    })
}

async fn github_identity(app: &App, provider: &Provider, code: &str) -> Result<Identity, String> {
    #[derive(Deserialize)]
    struct GithubUser {
        id: u64,
        login: String,
        name: Option<String>,
    }
    #[derive(Deserialize)]
    struct GithubEmail {
        email: String,
        primary: bool,
        verified: bool,
    }
    let secret = client_secret(app, provider).ok_or("the client secret can't be read")?;
    let redirect_uri = callback_url(app, provider);
    let form = [
        ("client_id", provider.client_id.as_str()),
        ("client_secret", secret.as_str()),
        ("code", code),
        ("redirect_uri", redirect_uri.as_str()),
    ];
    let answer: TokenAnswer = app
        .client
        .post_form(GITHUB_TOKEN, Plain::Loopback, &form, None)
        .await
        .map_err(|e| format!("GitHub token request: {e}"))?;
    let token = answer.access_token.ok_or("GitHub sent no access token")?;
    let user: GithubUser = app
        .client
        .get_json(GITHUB_USER, Plain::Loopback, Some(&token))
        .await
        .map_err(|e| format!("GitHub user: {e}"))?;
    let emails: Vec<GithubEmail> = app
        .client
        .get_json(GITHUB_EMAILS, Plain::Loopback, Some(&token))
        .await
        .unwrap_or_default();
    let primary = emails
        .into_iter()
        .find(|email| email.primary && email.verified);
    Ok(Identity {
        subject: user.id.to_string(),
        email_verified: primary.is_some(),
        email: primary.map(|email| email.email),
        name: user.name.or(Some(user.login)),
    })
}

/// Links, signs in, creates an account, or explains why none of those can happen.
async fn resolve(
    app: &App,
    request: &Request,
    provider: &Provider,
    identity: Identity,
    flow: &Flow,
) -> Result<Response, Failure> {
    let text = Lang::of(request).text();
    let (provider_id, subject) = (provider.id, identity.subject.clone());
    let linked = app
        .db
        .run(move |conn| providers::linked_user(conn, provider_id, &subject))
        .await?;

    if let Some(user_id) = flow.link_user.map(UserId) {
        let current = session::current(app, request).await?;
        let Some(current) = current.filter(|current| current.user.id == user_id) else {
            return Ok(message(app, request, text.provider_failed));
        };
        if linked.is_some_and(|other| other != user_id) {
            return Ok(message(app, request, text.provider_linked_elsewhere));
        }
        let subject = identity.subject.clone();
        app.db
            .run(move |conn| providers::link(conn, provider_id, &subject, user_id))
            .await?;
        record(
            app,
            request,
            &current.user.username,
            "link sign-in provider",
            &provider.name,
        )
        .await?;
        return Ok(Response::redirect("/account"));
    }

    if let Some(user_id) = linked {
        let user = app.db.run(move |conn| users::by_id(conn, user_id)).await?;
        return match user.filter(|user| !user.disabled) {
            Some(user) => after_provider(app, request, user, &flow.next).await,
            None => Ok(message(app, request, text.provider_failed)),
        };
    }

    if let Some(user) = create_account(app, request, provider, &identity).await? {
        return after_provider(app, request, user, &flow.next).await;
    }
    info!(
        "{} sign-in by an unlinked account ({})",
        provider.name, identity.subject
    );
    Ok(message(app, request, text.provider_not_linked))
}

/// Creates an account for a verified address in a domain the administrator listed, and links it.
async fn create_account(
    app: &App,
    request: &Request,
    provider: &Provider,
    identity: &Identity,
) -> Result<Option<User>, Failure> {
    let Some(email) = identity.email.clone().filter(|_| identity.email_verified) else {
        return Ok(None);
    };
    let Some((local, domain)) = email.rsplit_once('@') else {
        return Ok(None);
    };
    let domain = domain.to_ascii_lowercase();
    if !provider.auto_create_domains.contains(&domain) {
        return Ok(None);
    }
    let base: String = local
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-' | '_'))
        .skip_while(|c| !c.is_ascii_alphanumeric())
        .take(Username::MAX_LEN.saturating_sub(4))
        .collect();
    let base = if base.is_empty() {
        "user".to_owned()
    } else {
        base
    };
    // A provider's name may contain anything; keep what is safe to show and send.
    let display_name: String = identity
        .name
        .as_deref()
        .unwrap_or(local)
        .chars()
        .filter(|c| !c.is_control())
        .take(100)
        .collect();
    let display_name = if display_name.is_empty() {
        local.to_owned()
    } else {
        display_name
    };
    let (provider_id, subject) = (provider.id, identity.subject.clone());
    let created = app
        .db
        .run(move |conn| {
            // The first free name of base, base2, base3 and so on.
            for suffix in 1..1000_u32 {
                let candidate = if suffix == 1 {
                    base.clone()
                } else {
                    format!("{base}{suffix}")
                };
                let Some(username) = Username::parse(&candidate) else {
                    continue;
                };
                if users::by_username(conn, username.as_str())?.is_some() {
                    continue;
                }
                let new = NewUser {
                    username: &username,
                    display_name: &display_name,
                    email: Some(&email),
                    is_admin: false,
                };
                let id = users::create(conn, &new)?;
                conn.execute("UPDATE users SET email_verified = 1 WHERE id = ?1", [id.0])?;
                providers::link(conn, provider_id, &subject, id)?;
                return users::by_id(conn, id);
            }
            Ok(None)
        })
        .await?;
    if let Some(user) = &created {
        record(
            app,
            request,
            &user.username,
            "create user from provider",
            &provider.name,
        )
        .await?;
    }
    Ok(created)
}

async fn record(
    app: &App,
    request: &Request,
    actor: &str,
    action: &'static str,
    target: &str,
) -> Result<(), Failure> {
    let (actor, target, ip) = (
        actor.to_owned(),
        target.to_owned(),
        request.client_ip.to_string(),
    );
    app.db
        .run(move |conn| {
            audit::record(
                conn,
                &audit::Entry {
                    actor: &actor,
                    action,
                    target: &target,
                    ip: &ip,
                },
            )
        })
        .await?;
    Ok(())
}

/// A sign-in with the provider failed; the reason goes to the log, not to the page.
fn failed(app: &App, request: &Request, provider: &Provider, reason: &str) -> Response {
    warning!("sign-in with {} failed: {reason}", provider.name);
    message(app, request, Lang::of(request).text().provider_failed).status(StatusCode::BAD_GATEWAY)
}

fn message(app: &App, request: &Request, title: &str) -> Response {
    let lang = Lang::of(request);
    let text = lang.text();
    let mut content = Html::new();
    html!(
        content,
        "<h1>",
        { title },
        "</h1><div class=\"alternatives\"><a class=\"button block\" href=\"/login\">",
        { text.sign_in },
        "</a></div>"
    );
    Response::html(auth_page(app, request, lang, title, &content))
}

impl App {
    fn provider_cache(&self) -> MutexGuard<'_, Cache> {
        self.provider_cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}
