//! Browser sessions: the cookie, finding the session it belongs to, starting and ending one.

use super::oidc::backchannel;
use super::signin::SignedIn;
use super::{App, Failure, csrf};
use crate::crypto::{TokenHash, random_bytes, random_token};
use crate::encoding::base64url;
use crate::form::encode;
use crate::http::cookie::{self, SetCookie};
use crate::http::{Request, Response};
use crate::store::sessions::{self, ActiveSession, NewSession, SessionId};
use crate::store::users::UserId;
use crate::time;

const COOKIE: &str = "session";
/// A session ends after a week without use, and a month after sign-in in any case.
const IDLE_LIFETIME: i64 = 7 * 24 * 60 * 60;
const MAX_LIFETIME: i64 = 30 * 24 * 60 * 60;
/// Activity is written at most this often, not on every request.
const TOUCH_INTERVAL: i64 = 60 * 60;

fn cookie_name(app: &App) -> String {
    cookie::name(COOKIE, app.config.issuer.is_secure())
}

/// The session of the browser that sent the request, if it has a valid one.
pub(crate) async fn current(
    app: &App,
    request: &Request,
) -> Result<Option<ActiveSession>, Failure> {
    let Some(token) = request.cookie(&cookie_name(app)) else {
        return Ok(None);
    };
    let hash = TokenHash::of(token);
    let now = time::now();
    let Some(session) = app
        .db
        .run(move |conn| sessions::find(conn, &hash, now))
        .await?
    else {
        return Ok(None);
    };
    if now.saturating_sub(session.last_seen_at) >= TOUCH_INTERVAL {
        let id = session.id;
        let expires_at = now
            .saturating_add(IDLE_LIFETIME)
            .min(session.auth_time.saturating_add(MAX_LIFETIME));
        app.db
            .run(move |conn| sessions::touch(conn, id, now, expires_at))
            .await?;
    }
    Ok(Some(session))
}

/// A redirect to the sign-in page that comes back to this page afterwards.
pub(crate) fn to_sign_in(request: &Request) -> Response {
    Response::redirect(format!("/login?next={}", encode(&request.target)))
}

/// Starts a session for someone who has just signed in, replacing the session the browser had.
/// A new token every time means a token planted in the browser beforehand is worthless.
pub(crate) async fn start(
    app: &App,
    request: &Request,
    signed_in: SignedIn,
    response: Response,
) -> Result<Response, Failure> {
    if let Some(previous) = current(app, request).await? {
        end(app, Ending::One(previous.id)).await?;
    }
    let token = random_token()?;
    let public_id = base64url(&random_bytes::<16>()?);
    let token_hash = TokenHash::of(&token);
    let now = time::now();
    let ip = request.client_ip.to_string();
    let user_agent: String = request
        .header("user-agent")
        .unwrap_or_default()
        .chars()
        .take(200)
        .collect();
    let user_id = signed_in.user();
    let amr = signed_in.amr();
    app.db
        .run(move |conn| {
            sessions::create(
                conn,
                &NewSession {
                    token_hash,
                    public_id: &public_id,
                    user_id,
                    amr,
                    now,
                    expires_at: now.saturating_add(IDLE_LIFETIME),
                    ip: &ip,
                    user_agent: &user_agent,
                },
            )
        })
        .await?;
    let secure = app.config.issuer.is_secure();
    let cookie = SetCookie {
        name: &cookie_name(app),
        value: &token,
        max_age: Some(MAX_LIFETIME),
    };
    Ok(response.cookie(&cookie, secure))
}

/// A cookie that deletes the session cookie in the browser.
pub(crate) fn clear(app: &App, response: Response) -> Response {
    let secure = app.config.issuer.is_secure();
    let cookie = SetCookie {
        name: &cookie_name(app),
        value: "",
        max_age: Some(0),
    };
    response.cookie(&cookie, secure)
}

/// `POST /logout`: ends the session in this browser.
pub(crate) async fn sign_out(app: &App, request: &Request) -> Result<Response, Failure> {
    if !csrf::verify(app, request) {
        return Ok(Response::redirect("/account"));
    }
    if let Some(session) = current(app, request).await? {
        end(app, Ending::One(session.id)).await?;
    }
    Ok(clear(app, Response::redirect("/login")))
}

/// Which sessions to end.
pub(crate) enum Ending {
    One(SessionId),
    /// A session, if it belongs to this user.
    Owned(SessionId, UserId),
    /// Every session of a user, except one.
    AllOf(UserId, Option<SessionId>),
}

/// Ends sessions, with their codes and grants, and tells the applications that asked to know.
/// Every way of ending a session goes through here, so none forgets the notice.
pub(crate) async fn end(app: &App, ending: Ending) -> Result<(), Failure> {
    let targets = app
        .db
        .run(move |conn| {
            let ids = match ending {
                Ending::One(id) => vec![id],
                Ending::Owned(id, user) => sessions::ids_of_user(conn, user, None)?
                    .into_iter()
                    .filter(|owned| *owned == id)
                    .collect(),
                Ending::AllOf(user, except) => sessions::ids_of_user(conn, user, except)?,
            };
            let mut targets = Vec::new();
            for id in ids {
                targets.extend(sessions::logout_targets(conn, id)?);
                sessions::delete(conn, id)?;
            }
            Ok(targets)
        })
        .await?;
    backchannel::notify(app, targets);
    Ok(())
}
