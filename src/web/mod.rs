//! The web interface and the protocol endpoints: shared state and routing.

mod i18n;
mod layout;
mod static_files;

use std::sync::{PoisonError, RwLock};

use hyper::{Method, StatusCode, header};

use self::i18n::Lang;
use self::layout::error_page;
use crate::config::Config;
use crate::http::Request;
use crate::http::Response;
use crate::http::cookie::{SameSite, SetCookie};
use crate::store::{Db, DbError, settings};

/// Everything a request handler needs, shared by all of them.
pub(crate) struct App {
    pub(crate) config: Config,
    pub(crate) db: Db,
    branding: RwLock<Branding>,
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
    pub(crate) async fn new(config: Config, db: Db) -> Result<Self, DbError> {
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
        Ok(Self {
            config,
            db,
            branding: RwLock::new(branding),
        })
    }

    pub(crate) fn branding(&self) -> Branding {
        self.branding
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
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

#[expect(
    clippy::unused_async,
    reason = "the sign-in routes of the next stage await"
)]
pub(crate) async fn route(app: &App, request: Request) -> Response {
    let found = match request.method {
        Method::GET | Method::HEAD => match request.path.as_str() {
            "/healthz" => Some(Response::text(StatusCode::OK, "ok")),
            "/theme.css" => Some(theme(app)),
            "/language" => Some(language(app, &request)),
            path => static_files::serve(path),
        },
        _ => None,
    };
    found.unwrap_or_else(|| error_page(app, &request, StatusCode::NOT_FOUND))
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
