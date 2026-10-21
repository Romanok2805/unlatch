//! `Set-Cookie` headers.

use std::fmt::Write as _;

use hyper::header;

use super::Response;

/// A cookie we set. Every cookie is `HttpOnly` and scoped to the whole host, so the only choices
/// are its lifetime and `SameSite`.
pub(crate) struct SetCookie<'a> {
    pub(crate) name: &'a str,
    pub(crate) value: &'a str,
    /// Seconds; `None` for a cookie that ends with the browser session, `Some(0)` to delete it.
    pub(crate) max_age: Option<i64>,
    pub(crate) same_site: SameSite,
}

#[derive(Clone, Copy)]
pub(crate) enum SameSite {
    /// Sent when the user follows a link from another site, which is how users arrive from
    /// applications, but not with cross-site form posts or subrequests.
    Lax,
    Strict,
}

/// The cookie name to use. Over https it gets the `__Host-` prefix, which makes the browser
/// insist on `Secure`, `Path=/` and no `Domain`: neither a subdomain nor plain http can set or
/// overwrite it. Browsers refuse the prefix without https, so local trials go without it.
pub(crate) fn name(base: &str, secure: bool) -> String {
    if secure {
        format!("__Host-{base}")
    } else {
        base.to_owned()
    }
}

impl Response {
    #[must_use]
    pub(crate) fn cookie(self, cookie: &SetCookie<'_>, secure: bool) -> Self {
        let mut value = format!("{}={}; Path=/; HttpOnly", cookie.name, cookie.value);
        if let Some(max_age) = cookie.max_age {
            // Writing to a String can't fail.
            let _ = write!(value, "; Max-Age={max_age}");
        }
        value.push_str(match cookie.same_site {
            SameSite::Lax => "; SameSite=Lax",
            SameSite::Strict => "; SameSite=Strict",
        });
        if secure {
            value.push_str("; Secure");
        }
        self.header(header::SET_COOKIE, value)
    }
}
