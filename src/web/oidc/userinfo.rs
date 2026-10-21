//! Endpoints that look at tokens: userinfo, introspection and revocation.

use hyper::{StatusCode, header};
use serde::Serialize;

use super::super::{App, Failure};
use super::dpop;
use super::token::authenticate;
use super::tokens::{self, AccessClaims, Confirmation, UserClaims};
use crate::crypto::verify_jwt;
use crate::http::{Request, Response};
use crate::store::sessions::{self, ActiveSession};
use crate::store::{grants, groups};
use crate::time;

/// An access token we issued that is still valid, with the session it belongs to, if any.
async fn check_access_token(
    app: &App,
    token: &str,
) -> Result<Option<(AccessClaims, Option<ActiveSession>)>, Failure> {
    let ring = app.key_ring();
    let Ok(payload) = verify_jwt(token, &ring.verifying_keys(), Some("at+jwt")) else {
        return Ok(None);
    };
    let Ok(claims) = serde_json::from_slice::<AccessClaims>(&payload) else {
        return Ok(None);
    };
    let now = time::now();
    if claims.iss != app.config.issuer.as_str() || claims.exp <= now {
        return Ok(None);
    }
    let Some(sid) = claims.sid.clone() else {
        // A client credentials token belongs to no session.
        return Ok(Some((claims, None)));
    };
    let session = app
        .db
        .run(move |conn| sessions::by_public_id(conn, &sid, now))
        .await?;
    // The session must still exist and still be the subject's, or the token is dead.
    match session {
        Some(session) if tokens::subject(app, session.user.id) == claims.sub => {
            Ok(Some((claims, Some(session))))
        }
        _ => Ok(None),
    }
}

/// The access token in the `Authorization` header, and whether it came under the `DPoP` scheme
/// (RFC 9449 section 7.1) rather than `Bearer`.
fn presented_token(request: &Request) -> Option<(&str, bool)> {
    let (scheme, token) = request.header(header::AUTHORIZATION)?.split_once(' ')?;
    let dpop = if scheme.eq_ignore_ascii_case("DPoP") {
        true
    } else if scheme.eq_ignore_ascii_case("Bearer") {
        false
    } else {
        return None;
    };
    Some((token.trim(), dpop))
}

fn unauthorized(challenge: String) -> Response {
    Response::text(StatusCode::UNAUTHORIZED, "the access token was refused")
        .header(header::WWW_AUTHENTICATE, challenge)
}

/// The challenge for a token that is missing or was refused; either scheme is welcome.
fn invalid_token(refused: bool) -> Response {
    let algs = dpop::algorithms().join(" ");
    unauthorized(if refused {
        format!("Bearer error=\"invalid_token\", DPoP error=\"invalid_token\", algs=\"{algs}\"")
    } else {
        format!("Bearer, DPoP algs=\"{algs}\"")
    })
}

/// `GET` or `POST /userinfo`: the claims about the user the token was issued for.
pub(crate) async fn userinfo(app: &App, request: &Request) -> Result<Response, Failure> {
    let Some((token, dpop_scheme)) = presented_token(request) else {
        return Ok(invalid_token(false));
    };
    let Some((claims, Some(session))) = check_access_token(app, token).await? else {
        return Ok(invalid_token(true));
    };
    // A bound token needs a proof of its key, and the DPoP scheme is only for bound tokens, so
    // neither can pass for the other.
    match (&claims.cnf, dpop_scheme) {
        (None, false) => {}
        (Some(cnf), true) => match dpop::check(app, request, "/userinfo", Some(token)) {
            Ok(Some(key)) if key == cnf.jkt => {}
            Ok(_) => {
                return Ok(invalid_proof(
                    "the DPoP proof is missing or for another key",
                ));
            }
            Err(description) => return Ok(invalid_proof(description)),
        },
        _ => return Ok(invalid_token(true)),
    }
    if !claims.scope.split(' ').any(|scope| scope == "openid") {
        return Ok(
            Response::text(StatusCode::FORBIDDEN, "the token lacks the openid scope").header(
                header::WWW_AUTHENTICATE,
                "Bearer error=\"insufficient_scope\", scope=\"openid\"",
            ),
        );
    }
    let user = session.user.id;
    let groups = app
        .db
        .run(move |conn| groups::names_for_user(conn, user))
        .await?;
    Ok(Response::json(&UserClaims::new(
        app,
        &session.user,
        groups,
        &claims.scope,
    )))
}

fn invalid_proof(description: &str) -> Response {
    let algs = dpop::algorithms().join(" ");
    unauthorized(format!(
        "DPoP error=\"invalid_dpop_proof\", error_description=\"{description}\", algs=\"{algs}\""
    ))
}

#[derive(Serialize, Default)]
struct Introspection {
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_type: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iat: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cnf: Option<Confirmation>,
}

/// `POST /introspect` (RFC 7662). A client may only learn about tokens issued to it or meant
/// for it; anything else is reported inactive, like an invalid token.
pub(crate) async fn introspect(app: &App, request: &Request) -> Result<Response, Failure> {
    let client = match authenticate(app, request, true).await? {
        Ok(client) => client,
        Err(response) => return Ok(response),
    };
    let client_id = client.client_id.unwrap_or_default();
    let token = request
        .form
        .single("token")
        .ok()
        .flatten()
        .unwrap_or_default();
    let Some((claims, session)) = check_access_token(app, token).await? else {
        return Ok(Response::json(&Introspection::default()));
    };
    if claims.client_id != client_id && claims.aud != client_id {
        return Ok(Response::json(&Introspection::default()));
    }
    Ok(Response::json(&Introspection {
        active: true,
        scope: Some(claims.scope),
        client_id: Some(claims.client_id),
        username: session.map(|session| session.user.username),
        token_type: Some(if claims.cnf.is_some() {
            "DPoP"
        } else {
            "Bearer"
        }),
        exp: Some(claims.exp),
        iat: Some(claims.iat),
        sub: Some(claims.sub),
        aud: Some(claims.aud),
        iss: Some(claims.iss),
        cnf: claims.cnf,
    }))
}

/// `POST /revoke` (RFC 7009). A refresh token ends its grant. Access tokens can't be recalled
/// one by one; they expire within minutes, and ending the session stops them at once at our
/// endpoints. The answer is the same either way, as the RFC asks.
pub(crate) async fn revoke(app: &App, request: &Request) -> Result<Response, Failure> {
    let client = match authenticate(app, request, false).await? {
        Ok(client) => client,
        Err(response) => return Ok(response),
    };
    let token = request
        .form
        .single("token")
        .ok()
        .flatten()
        .unwrap_or_default();
    if let Some((grant_id, _)) = tokens::open_refresh_token(app, token) {
        let client_app = client.id;
        app.db
            .run(move |conn| {
                if grants::find(conn, grant_id)?.is_some_and(|grant| grant.app == client_app) {
                    grants::delete(conn, grant_id)?;
                }
                Ok(())
            })
            .await?;
    }
    Ok(Response::new(
        StatusCode::OK,
        "text/plain; charset=utf-8",
        "",
    ))
}
