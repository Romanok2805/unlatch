//! Protection against forms posted to us from other sites.
//!
//! Each browser gets a random cookie, and every form we render carries an HMAC of it. Another
//! site can make a browser post a form to us, but it can read neither the cookie nor our pages,
//! so it can't produce the matching field. Browsers that send `Sec-Fetch-Site` are also refused
//! when they say the post comes from another site.

use super::App;
use crate::crypto::{CryptoError, random_token};
use crate::encoding::{base64url, decode_base64url};
use crate::html::{Html, html};
use crate::http::cookie::{self, SetCookie};
use crate::http::{Request, Response};

const COOKIE: &str = "csrf";
const FIELD: &str = "csrf";

/// The token for the forms of one page.
pub(crate) struct Csrf {
    token: String,
    /// Set when the browser had no cookie yet and needs one with the page.
    new_cookie: Option<String>,
}

impl Csrf {
    pub(crate) fn for_page(app: &App, request: &Request) -> Result<Self, CryptoError> {
        let name = cookie::name(COOKIE, app.config.issuer.is_secure());
        let existing = request
            .cookie(&name)
            .filter(|value| decode_base64url(value).is_some_and(|bytes| bytes.len() == 32));
        let (value, new_cookie) = if let Some(value) = existing {
            (value.to_owned(), None)
        } else {
            let value = random_token()?;
            (value.clone(), Some(value))
        };
        Ok(Self {
            token: base64url(&app.keys.csrf.sign(value.as_bytes())),
            new_cookie,
        })
    }

    pub(crate) fn field(&self) -> Html {
        let mut out = Html::new();
        html!(
            out,
            "<input type=\"hidden\" name=\"csrf\" value=\"",
            { self.token },
            "\">"
        );
        out
    }

    /// Adds the cookie to the response that carries the page, if the browser needs one.
    pub(crate) fn apply(&self, app: &App, response: Response) -> Response {
        let Some(value) = &self.new_cookie else {
            return response;
        };
        let secure = app.config.issuer.is_secure();
        let cookie = SetCookie {
            name: &cookie::name(COOKIE, secure),
            value,
            max_age: None,
        };
        response.cookie(&cookie, secure)
    }
}

/// Whether a posted form came from one of our pages in this browser.
pub(crate) fn verify(app: &App, request: &Request) -> bool {
    if request.header("sec-fetch-site") == Some("cross-site") {
        return false;
    }
    let name = cookie::name(COOKIE, app.config.issuer.is_secure());
    let Some(cookie) = request.cookie(&name) else {
        return false;
    };
    let Ok(Some(field)) = request.form.single(FIELD) else {
        return false;
    };
    decode_base64url(field).is_some_and(|tag| app.keys.csrf.verify(cookie.as_bytes(), &tag))
}
