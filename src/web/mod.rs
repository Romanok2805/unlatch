//! The web interface and the protocol endpoints: shared state and routing.

mod account;
mod csrf;
mod i18n;
mod layout;
mod limits;
mod oidc;
mod qr;
mod session;
pub(crate) mod setup;
mod signin;
mod static_files;

use std::sync::{Arc, PoisonError, RwLock};

use hyper::{Method, StatusCode, header};
use tokio::sync::Semaphore;

use self::i18n::Lang;
use self::layout::error_page;
use self::limits::Limits;
use self::oidc::keys::KeyRing;
use crate::config::Config;
use crate::crypto::{CryptoError, MacKey, SealingKey};
use crate::http::cookie::{SameSite, SetCookie};
use crate::http::{Request, Response};
use crate::log::error;
use crate::store::{Db, DbError, settings};

/// Everything a request handler needs, shared by all of them.
pub(crate) struct App {
    pub(crate) config: Config,
    pub(crate) db: Db,
    pub(crate) keys: Keys,
    limits: Limits,
    /// Password hashes computed at once. Each takes tens of megabytes for a moment, so this
    /// bounds the memory a burst of sign-ins can use.
    hashing: Semaphore,
    branding: RwLock<Branding>,
    signing: RwLock<Arc<KeyRing>>,
}

const HASHING_SLOTS: usize = 2;

/// Keys derived from the master key, one per purpose.
pub(crate) struct Keys {
    pub(crate) csrf: MacKey,
    /// Seals the state carried from the password step to the code step of a sign-in.
    pub(crate) signin: SealingKey,
    /// Seals secrets stored in the database: TOTP seeds, provider secrets, signing keys.
    pub(crate) secrets: SealingKey,
    /// Seals values a form carries to its next request, such as a TOTP seed being set up.
    pub(crate) forms: SealingKey,
    /// Seals authorization requests while the user signs in.
    pub(crate) requests: SealingKey,
    /// Seals refresh tokens.
    pub(crate) refresh: SealingKey,
    /// Seals the private keys that sign tokens.
    pub(crate) signing: SealingKey,
    /// Derives the `sub` of users.
    pub(crate) subject: MacKey,
}

impl Keys {
    fn derive(config: &Config) -> Result<Self, CryptoError> {
        let master = &config.master_key;
        Ok(Self {
            csrf: master.mac_key("csrf")?,
            signin: master.sealing_key("sign-in")?,
            secrets: master.sealing_key("secrets")?,
            forms: master.sealing_key("forms")?,
            requests: master.sealing_key("authorization requests")?,
            refresh: master.sealing_key("refresh tokens")?,
            signing: master.sealing_key("signing keys")?,
            subject: master.mac_key("subject")?,
        })
    }
}

/// How the instance presents itself; the administrator can change both.
#[derive(Clone)]
pub(crate) struct Branding {
    pub(crate) name: String,
    /// A colour as `#rrggbb`.
    pub(crate) accent: String,
}

const DEFAULT_ACCENT: &str = "#2d6a5f";

impl App {
    pub(crate) async fn new(config: Config, db: Db) -> Result<Self, Failure> {
        let (name, accent) = db
            .run(|conn| Ok((settings::get(conn, "name")?, settings::get(conn, "accent")?)))
            .await?;
        let default_name = config
            .issuer
            .as_str()
            .split_once("://")
            .map_or(config.issuer.as_str(), |(_, host)| host)
            .to_owned();
        let branding = Branding {
            name: name.unwrap_or(default_name),
            accent: accent
                .filter(|value| is_colour(value))
                .unwrap_or_else(|| DEFAULT_ACCENT.to_owned()),
        };
        let keys = Keys::derive(&config)?;
        let ring = oidc::keys::maintain(&db, &keys.signing).await?;
        Ok(Self {
            keys,
            config,
            db,
            limits: Limits::new(),
            hashing: Semaphore::new(HASHING_SLOTS),
            branding: RwLock::new(branding),
            signing: RwLock::new(Arc::new(ring)),
        })
    }

    pub(crate) fn key_ring(&self) -> Arc<KeyRing> {
        Arc::clone(&self.signing.read().unwrap_or_else(PoisonError::into_inner))
    }

    fn set_key_ring(&self, ring: KeyRing) {
        *self.signing.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(ring);
    }

    pub(crate) fn branding(&self) -> Branding {
        self.branding
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// Why a request couldn't be served. Each is shown as an error page; the details go to the log.
#[derive(Debug)]
pub(crate) enum Failure {
    Db(DbError),
    Crypto(CryptoError),
    /// Too many password hashes queued; the user should try again shortly.
    Busy,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Db(e) => e.fmt(f),
            Self::Crypto(e) => e.fmt(f),
            Self::Busy => f.write_str("too many password checks at once"),
        }
    }
}

impl From<DbError> for Failure {
    fn from(e: DbError) -> Self {
        Self::Db(e)
    }
}

impl From<CryptoError> for Failure {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

/// `#rrggbb` in lowercase, the only form the theme accepts, so nothing else can reach the CSS.
fn is_colour(value: &str) -> bool {
    value.len() == 7
        && value.starts_with('#')
        && value
            .chars()
            .skip(1)
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

/// A path on this server, safe to redirect to. `//host` and `/\host` would leave it.
pub(crate) fn is_local_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("//")
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
}

pub(crate) async fn route(app: &App, request: Request) -> Response {
    match dispatch(app, &request).await {
        Ok(Some(response)) => response,
        Ok(None) => error_page(app, &request, StatusCode::NOT_FOUND),
        Err(Failure::Busy) => {
            let lang = Lang::of(&request);
            let mut page = crate::html::Html::new();
            crate::html::html!(page, "<h1>", { lang.text().busy }, "</h1>");
            let body = layout::auth_page(app, &request, lang, lang.text().busy, &page);
            Response::html(body).status(StatusCode::SERVICE_UNAVAILABLE)
        }
        Err(failure) => {
            error!("{} {}: {failure}", request.method, request.path);
            error_page(app, &request, StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn dispatch(app: &App, request: &Request) -> Result<Option<Response>, Failure> {
    let get = matches!(request.method, Method::GET | Method::HEAD);
    let post = request.method == Method::POST;
    let response = match request.path.as_str() {
        "/" if get => home(app, request).await?,
        "/healthz" if get => Response::text(StatusCode::OK, "ok"),
        "/theme.css" if get => theme(app),
        "/language" if get => language(app, request),
        "/login" if get => signin::page(app, request).await?,
        "/login" if post => signin::submit(app, request).await?,
        "/login/code" if get => signin::second_step_page(app, request, false)?,
        "/login/code" if post => signin::second_step_submit(app, request, false).await?,
        "/login/recovery" if get => signin::second_step_page(app, request, true)?,
        "/login/recovery" if post => signin::second_step_submit(app, request, true).await?,
        "/logout" if post => session::sign_out(app, request).await?,
        "/setup" if get => return setup::setup_page(app, request).await,
        "/setup" if post => return setup::setup_submit(app, request).await,
        "/password" if get => setup::link_page(app, request).await?,
        "/password" if post => setup::link_submit(app, request).await?,
        "/account" if get => account::overview(app, request).await?,
        "/account/password" if get => account::password_page(app, request).await?,
        "/account/password" if post => account::password_submit(app, request).await?,
        "/account/two-factor" if get => account::two_factor_page(app, request).await?,
        "/account/two-factor" if post => account::two_factor_submit(app, request).await?,
        "/.well-known/openid-configuration" if get => oidc::discovery(app),
        "/jwks" if get => oidc::jwks(app),
        "/authorize" if get => oidc::authorize(app, request, &request.query).await?,
        "/authorize" if post => oidc::authorize(app, request, &request.form).await?,
        "/authorize/continue" if get => oidc::resume(app, request).await?,
        "/authorize/continue" if post => oidc::decide(app, request).await?,
        "/token" if post => oidc::token(app, request).await?,
        "/userinfo" if get || post => oidc::userinfo(app, request).await?,
        "/introspect" if post => oidc::introspect(app, request).await?,
        "/revoke" if post => oidc::revoke(app, request).await?,
        "/end-session" if get || post => oidc::end_session(app, request).await?,
        path if get => return Ok(static_files::serve(path)),
        _ => return Ok(None),
    };
    Ok(Some(response))
}

async fn home(app: &App, request: &Request) -> Result<Response, Failure> {
    Ok(match session::current(app, request).await? {
        Some(_) => Response::redirect("/account"),
        None => Response::redirect("/login"),
    })
}

/// The accent colour as a stylesheet. Pages link it with the colour in the URL, so it can be
/// cached for good.
fn theme(app: &App) -> Response {
    let accent = app.branding().accent;
    Response::new(
        StatusCode::OK,
        "text/css; charset=utf-8",
        format!(":root {{ --accent: {accent}; }}\n"),
    )
    .header(header::CACHE_CONTROL, "public, max-age=31536000, immutable")
}

/// Remembers the language picked in the footer and returns to the page it was picked on.
fn language(app: &App, request: &Request) -> Response {
    let lang = request
        .query
        .single("to")
        .ok()
        .flatten()
        .and_then(Lang::from_code);
    let back = request
        .query
        .single("back")
        .ok()
        .flatten()
        .filter(|path| is_local_path(path))
        .unwrap_or("/");
    let Some(lang) = lang else {
        return error_page(app, request, StatusCode::BAD_REQUEST);
    };
    let cookie = SetCookie {
        name: i18n::COOKIE,
        value: lang.code(),
        max_age: Some(365 * 24 * 60 * 60),
        same_site: SameSite::Lax,
    };
    Response::redirect(back).cookie(&cookie, app.config.issuer.is_secure())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_local_paths_are_safe_to_return_to() {
        for good in ["/", "/account", "/authorize?req=abc"] {
            assert!(is_local_path(good), "{good}");
        }
        for bad in [
            "//evil.example",
            "/\\evil.example",
            "https://evil.example",
            "evil",
            "/a\nb",
            "",
        ] {
            assert!(!is_local_path(bad), "{bad}");
        }
    }
}
