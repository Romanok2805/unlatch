//! Forward authentication: protecting services that don't speak OpenID Connect.
//!
//! The reverse proxy asks `/forward-auth` about each request to a protected host. Each host has
//! its own session cookie, set by `/_unlatch/callback`, a path on that host that the proxy routes
//! to Unlatch. No cookie is shared across subdomains, so one service never sees another's. The
//! proxy configuration is in docs/forward-auth.md.

use hyper::{StatusCode, header};

use super::i18n::Lang;
use super::layout::{auth_page, expired_page};
use super::{App, Failure, is_local_path, session};
use crate::crypto::{TokenHash, constant_time_eq, random_token, sha256};
use crate::form::encode_pairs;
use crate::html::{Html, html};
use crate::http::cookie::{self, SetCookie};
use crate::http::{Request, Response};
use crate::log::warning;
use crate::store::apps::{self, Kind};
use crate::store::proxy;
use crate::time;

const COOKIE: &str = "unlatch-proxy";
/// Set on the protected host when a sign-in starts; the code must come back to the same browser.
const STATE_COOKIE: &str = "unlatch-proxy-state";
const STATE_LIFETIME: i64 = 30 * 60;
/// A code must reach the protected host within a minute.
const CODE_LIFETIME: i64 = 60;
/// The per-host cookie lasts as long as a session can; the session decides validity.
const COOKIE_LIFETIME: i64 = 30 * 24 * 60 * 60;

/// The request the proxy asks about, from headers that only a trusted proxy may set.
struct Forwarded {
    host: String,
    uri: String,
    https: bool,
}

fn forwarded(app: &App, request: &Request) -> Option<Forwarded> {
    let trusted = app
        .config
        .trusted_proxies
        .iter()
        .any(|range| range.contains(request.peer));
    if !trusted {
        return None;
    }
    // A proxy that appends to a list the client started adds its own value last; anything
    // before it could have come from the client.
    let last = |name: &str| {
        request
            .header(name)
            .and_then(|value| value.rsplit(',').next())
            .map(|value| value.trim().to_ascii_lowercase())
    };
    let host = last("x-forwarded-host")?;
    let https = last("x-forwarded-proto").is_some_and(|proto| proto == "https");
    // A path may contain commas, so it is never a list.
    let uri = request
        .header("x-forwarded-uri")
        .or_else(|| request.header("x-original-uri"))
        .filter(|uri| is_local_path(uri))
        .unwrap_or("/")
        .to_owned();
    Some(Forwarded { host, uri, https })
}

/// `/forward-auth`, and `/forward-auth/nginx`, which answers 401 instead of a redirect because
/// nginx's `auth_request` turns only that into a redirect of its own.
pub(crate) async fn verify(app: &App, request: &Request, nginx: bool) -> Result<Response, Failure> {
    let Some(forwarded) = forwarded(app, request) else {
        warning!(
            "forward auth asked by {}, which isn't a trusted proxy",
            request.peer
        );
        return Ok(Response::text(
            StatusCode::FORBIDDEN,
            "forward auth is only for trusted proxies",
        ));
    };
    let name = cookie::name(COOKIE, forwarded.https);
    if let Some(token) = request.cookie(&name) {
        let (hash, host, now) = (TokenHash::of(token), forwarded.host.clone(), time::now());
        if let Some((user, groups)) = app
            .db
            .run(move |conn| proxy::check(conn, &hash, &host, now))
            .await?
        {
            // Every header is always sent, even empty, so a proxy that copies them can't leave
            // one the client wrote in place.
            return Ok(Response::text(StatusCode::OK, "ok")
                .header(
                    header::HeaderName::from_static("remote-user"),
                    user.username,
                )
                .header(
                    header::HeaderName::from_static("remote-name"),
                    user.display_name,
                )
                .header(
                    header::HeaderName::from_static("remote-email"),
                    user.email.unwrap_or_default(),
                )
                .header(
                    header::HeaderName::from_static("remote-groups"),
                    groups.join(","),
                ));
        }
    }
    let host = forwarded.host.clone();
    let known = app
        .db
        .run(move |conn| proxy::app_for_host(conn, &host))
        .await?;
    if known.is_none_or(|record| !record.enabled) {
        warning!(
            "forward auth for {:?}, which no application protects",
            forwarded.host
        );
        return Ok(Response::text(
            StatusCode::FORBIDDEN,
            "this host isn't protected by Unlatch",
        ));
    }
    // The state cookie is set on the protected host through this answer, which the proxy passes
    // to the browser. Only that browser can complete the sign-in, so a code issued to someone
    // else's session can't be planted on a victim.
    let state = random_token()?;
    let query = encode_pairs([
        ("host", forwarded.host.as_str()),
        ("uri", forwarded.uri.as_str()),
        ("state", state.as_str()),
    ]);
    let start = app.config.issuer.url(&format!("/proxy/start?{query}"));
    let cookie = SetCookie {
        name: &cookie::name(STATE_COOKIE, forwarded.https),
        value: &state,
        max_age: Some(STATE_LIFETIME),
    };
    let response = if nginx {
        Response::text(StatusCode::UNAUTHORIZED, "sign-in required").header(header::LOCATION, start)
    } else {
        Response::redirect(start)
    };
    Ok(response.cookie(&cookie, forwarded.https))
}

/// `GET /proxy/start`: signs the user in if needed, checks access, and sends a one-time code
/// to the protected host.
pub(crate) async fn start(app: &App, request: &Request) -> Result<Response, Failure> {
    let value = |name| {
        request
            .query
            .single(name)
            .ok()
            .flatten()
            .unwrap_or_default()
    };
    let host = value("host").to_ascii_lowercase();
    let path = Some(value("uri"))
        .filter(|uri| is_local_path(uri))
        .unwrap_or("/")
        .to_owned();
    if value("state").len() < 32 {
        return Ok(expired_page(app, request));
    }
    let state_hash = sha256(value("state").as_bytes());
    let lookup = host.clone();
    let Some(record) = app
        .db
        .run(move |conn| proxy::app_for_host(conn, &lookup))
        .await?
    else {
        return Ok(super::layout::error_page(
            app,
            request,
            StatusCode::NOT_FOUND,
        ));
    };
    let Some(current) = session::current(app, request).await? else {
        return Ok(session::to_sign_in(request));
    };
    let (checked, user) = (record.clone(), current.user.id);
    if record.kind != Kind::Proxy
        || !app
            .db
            .run(move |conn| apps::allows(conn, &checked, user))
            .await?
    {
        return Ok(no_access(
            app,
            request,
            &record.name,
            &current.user.username,
        ));
    }
    let code = random_token()?;
    let (hash, session_id, app_id) = (TokenHash::of(&code), current.id, record.id);
    let expires_at = time::now().saturating_add(CODE_LIFETIME);
    app.db
        .run(move |conn| {
            proxy::create_code(
                conn,
                &hash,
                session_id,
                app_id,
                &path,
                &state_hash,
                expires_at,
            )
        })
        .await?;
    // Always https, except on this machine: the scheme in a link could be chosen by whoever made
    // the link, and a code sent over plain http could be read on the way.
    let scheme = if is_loopback(&host) { "http" } else { "https" };
    let query = encode_pairs([("code", code.as_str())]);
    Ok(Response::redirect(format!(
        "{scheme}://{host}/_unlatch/callback?{query}"
    )))
}

fn is_loopback(host: &str) -> bool {
    let name = if host.starts_with('[') {
        host.split(']')
            .next()
            .map_or(host, |name| name.trim_start_matches('['))
    } else {
        host.split(':').next().unwrap_or(host)
    };
    matches!(name, "127.0.0.1" | "::1" | "localhost")
}

/// The host a request to `/_unlatch/...` was made to: from the trusted proxy, or the `Host`
/// header when Unlatch is reached directly.
fn request_host(app: &App, request: &Request) -> (String, bool) {
    if let Some(forwarded) = forwarded(app, request) {
        return (forwarded.host, forwarded.https);
    }
    let host = request
        .header(header::HOST)
        .unwrap_or_default()
        .to_ascii_lowercase();
    (host, app.config.issuer.is_secure())
}

/// `GET /_unlatch/callback` on a protected host: trades the one-time code for a cookie of this
/// host. The code alone is never the cookie, so a code that leaked into a log is worthless once
/// used.
pub(crate) async fn callback(app: &App, request: &Request) -> Result<Response, Failure> {
    let (host, https) = request_host(app, request);
    let code = request
        .query
        .single("code")
        .ok()
        .flatten()
        .unwrap_or_default();
    let (hash, now) = (TokenHash::of(code), time::now());
    let redeemed = app
        .db
        .run(move |conn| proxy::take_code(conn, &hash, now))
        .await?;
    let state = request
        .cookie(&cookie::name(STATE_COOKIE, https))
        .unwrap_or_default();
    let Some(redeemed) = redeemed
        .filter(|redeemed| constant_time_eq(&sha256(state.as_bytes()), &redeemed.state_hash))
    else {
        return Ok(expired_page(app, request));
    };
    let (session_id, app_id, path) = (redeemed.session, redeemed.app, redeemed.path);
    let record = app.db.run(move |conn| apps::by_id(conn, app_id)).await?;
    if record.is_none_or(|record| record.host.as_deref() != Some(host.as_str())) {
        return Ok(expired_page(app, request));
    }
    let token = random_token()?;
    let token_hash = TokenHash::of(&token);
    app.db
        .run(move |conn| proxy::create_session(conn, &token_hash, session_id, app_id))
        .await?;
    let cookie = SetCookie {
        name: &cookie::name(COOKIE, https),
        value: &token,
        max_age: Some(COOKIE_LIFETIME),
    };
    let path = if is_local_path(&path) {
        path
    } else {
        "/".to_owned()
    };
    let clear_state = SetCookie {
        name: &cookie::name(STATE_COOKIE, https),
        value: "",
        max_age: Some(0),
    };
    Ok(Response::redirect(path)
        .cookie(&cookie, https)
        .cookie(&clear_state, https))
}

/// `GET /_unlatch/logout` on a protected host: forgets this host's session and continues to
/// sign out of Unlatch, which asks for confirmation.
pub(crate) async fn sign_out(app: &App, request: &Request) -> Result<Response, Failure> {
    let (_, https) = request_host(app, request);
    let name = cookie::name(COOKIE, https);
    if let Some(token) = request.cookie(&name) {
        let hash = TokenHash::of(token);
        app.db
            .run(move |conn| proxy::delete_session(conn, &hash))
            .await?;
    }
    let cookie = SetCookie {
        name: &name,
        value: "",
        max_age: Some(0),
    };
    Ok(Response::redirect(app.config.issuer.url("/end-session")).cookie(&cookie, https))
}

fn no_access(app: &App, request: &Request, name: &str, username: &str) -> Response {
    let lang = Lang::of(request);
    let text = lang.text();
    let title = format!("{} {name}", text.no_access);
    let mut content = Html::new();
    html!(
        content,
        "<h1>",
        { title },
        "</h1><p>",
        { username },
        "</p><div class=\"alternatives\"><a class=\"button block\" href=\"/login?force=1&amp;next=",
        { crate::form::encode(&request.target) },
        "\">",
        { text.switch_account },
        "</a></div>"
    );
    Response::html(auth_page(app, request, lang, &title, &content)).status(StatusCode::FORBIDDEN)
}

#[cfg(test)]
mod tests {
    use super::is_loopback;

    #[test]
    fn only_this_machine_counts_as_loopback() {
        for host in [
            "127.0.0.1",
            "127.0.0.1:8080",
            "localhost:3000",
            "[::1]:8080",
        ] {
            assert!(is_loopback(host), "{host}");
        }
        for host in [
            "photos.example.com",
            "127.0.0.1.example.com",
            "localhost.example.com",
        ] {
            assert!(!is_loopback(host), "{host}");
        }
    }
}
