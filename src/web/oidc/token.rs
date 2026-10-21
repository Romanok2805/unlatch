//! The token endpoint and client authentication.

use hyper::{StatusCode, header};

use super::super::{App, Failure};
use super::ACCESS_TOKEN_LIFETIME;
use super::tokens::{self, Holder, TokenResponse, UserClaims};
use crate::crypto::{TokenHash, constant_time_eq, sha256};
use crate::encoding::{base64url, decode_base64_standard};
use crate::form::decode_component;
use crate::http::{Request, Response};
use crate::store::apps::{self, AppRecord, Kind};
use crate::store::grants;
use crate::store::groups;
use crate::store::sessions::{self, ActiveSession};
use crate::time;

/// An OAuth error response (RFC 6749 section 5.2).
pub(crate) fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    #[derive(serde::Serialize)]
    struct Body<'a> {
        error: &'a str,
        error_description: &'a str,
    }
    Response::json(&Body {
        error,
        error_description: description,
    })
    .status(status)
}

/// Authenticates the client of a back-channel request with `client_secret_basic` or
/// `client_secret_post`. A public client sends only its `client_id` and is identified, not
/// authenticated; `confidential_only` refuses those.
pub(crate) async fn authenticate(
    app: &App,
    request: &Request,
    confidential_only: bool,
) -> Result<Result<AppRecord, Response>, Failure> {
    let basic = request.header(header::AUTHORIZATION).and_then(|value| {
        value
            .strip_prefix("Basic ")
            .or_else(|| value.strip_prefix("basic "))
    });
    let unauthorized = |used_basic: bool| {
        let response = oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "client authentication failed",
        );
        if used_basic {
            response.header(header::WWW_AUTHENTICATE, "Basic realm=\"unlatch\"")
        } else {
            response
        }
    };
    let form = |name| request.form.single(name).ok().flatten();
    let (client_id, secret) = match basic {
        Some(credentials) => {
            if form("client_secret").is_some() {
                return Ok(Err(oauth_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "use one authentication method",
                )));
            }
            let Some((id, secret)) = parse_basic(credentials) else {
                return Ok(Err(unauthorized(true)));
            };
            if form("client_id").is_some_and(|body_id| body_id != id) {
                return Ok(Err(unauthorized(true)));
            }
            (id, Some(secret))
        }
        None => match form("client_id") {
            Some(id) => (id.to_owned(), form("client_secret").map(str::to_owned)),
            None => return Ok(Err(unauthorized(false))),
        },
    };
    let lookup = client_id.clone();
    let client = app
        .db
        .run(move |conn| apps::by_client_id(conn, &lookup))
        .await?;
    let Some(client) = client.filter(|client| client.enabled && client.kind == Kind::Oidc) else {
        return Ok(Err(unauthorized(basic.is_some())));
    };
    let authenticated = match (&client.client_secret_hash, &secret) {
        (Some(hash), Some(secret)) => constant_time_eq(hash, &sha256(secret.as_bytes())),
        (None, None) => !confidential_only,
        // A public client sending a secret, or a confidential one without it.
        _ => false,
    };
    if !authenticated {
        return Ok(Err(unauthorized(basic.is_some())));
    }
    Ok(Ok(client))
}

/// `client_id:client_secret`, each form-encoded, in padded base64 (RFC 6749 section 2.3.1).
fn parse_basic(credentials: &str) -> Option<(String, String)> {
    let unpadded = credentials.trim().trim_end_matches('=');
    if !credentials.trim().len().is_multiple_of(4) {
        return None;
    }
    let decoded = String::from_utf8(decode_base64_standard(unpadded)?).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    Some((decode_component(id).ok()?, decode_component(secret).ok()?))
}

/// `POST /token`
pub(crate) async fn token(app: &App, request: &Request) -> Result<Response, Failure> {
    let grant_type = request
        .form
        .single("grant_type")
        .ok()
        .flatten()
        .unwrap_or_default();
    let confidential_only = grant_type == "client_credentials";
    let client = match authenticate(app, request, confidential_only).await? {
        Ok(client) => client,
        Err(response) => return Ok(response),
    };
    match grant_type {
        "authorization_code" => authorization_code(app, request, client).await,
        "refresh_token" => refresh(app, request, client).await,
        "client_credentials" => client_credentials(app, request, &client),
        _ => Ok(oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "use authorization_code, refresh_token or client_credentials",
        )),
    }
}

fn invalid_grant(description: &str) -> Response {
    oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", description)
}

/// A PKCE code verifier: 43 to 128 unreserved characters (RFC 7636 section 4.1).
fn valid_verifier(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

async fn authorization_code(
    app: &App,
    request: &Request,
    client: AppRecord,
) -> Result<Response, Failure> {
    let form = |name| request.form.single(name).ok().flatten().unwrap_or_default();
    let (code, redirect_uri, verifier) = (
        form("code"),
        form("redirect_uri").to_owned(),
        form("code_verifier"),
    );
    if !valid_verifier(verifier) {
        return Ok(invalid_grant("code_verifier is missing or malformed"));
    }
    let hash = TokenHash::of(code);
    let challenge = base64url(&sha256(verifier.as_bytes()));
    let now = time::now();
    let checked = client.clone();
    let outcome = app
        .db
        .run(move |conn| {
            let Some(code) = grants::find_code(conn, &hash)? else {
                return Ok(Err("the code is invalid"));
            };
            // A second use means the code leaked; whatever the first use got is revoked.
            if let Some(grant) = code.grant {
                grants::delete(conn, grant)?;
                return Ok(Err("the code was already used"));
            }
            if code.expires_at <= now
                || code.app != checked.id
                || code.redirect_uri != redirect_uri
                || !constant_time_eq(challenge.as_bytes(), code.challenge.as_bytes())
            {
                return Ok(Err("the code is invalid"));
            }
            let Some(session) = sessions::by_id(conn, code.session, now)? else {
                return Ok(Err("the session has ended"));
            };
            if !apps::allows(conn, &checked, session.user.id)? {
                return Ok(Err("the user may no longer use this application"));
            }
            let grant = grants::create(
                conn,
                session.id,
                code.app,
                &code.scope,
                code.resource.as_deref(),
            )?;
            grants::mark_redeemed(conn, &hash, grant)?;
            let groups = groups::names_for_user(conn, session.user.id)?;
            Ok(Ok((code, session, grant, groups)))
        })
        .await?;
    let (code, session, grant, groups) = match outcome {
        Ok(found) => found,
        Err(reason) => return Ok(invalid_grant(reason)),
    };
    let refresh = offline(&code.scope).then_some((grant, 0));
    issue(
        app,
        &client,
        &session,
        &code.scope,
        code.resource.as_deref(),
        code.nonce.as_deref(),
        groups,
        refresh,
    )
}

async fn refresh(app: &App, request: &Request, client: AppRecord) -> Result<Response, Failure> {
    let token = request
        .form
        .single("refresh_token")
        .ok()
        .flatten()
        .unwrap_or_default();
    let Some((grant_id, generation)) = tokens::open_refresh_token(app, token) else {
        return Ok(invalid_grant("the refresh token is invalid"));
    };
    let narrowed: Option<Vec<String>> = request.form.single("scope").ok().flatten().map(|scope| {
        scope
            .split(' ')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect()
    });
    let now = time::now();
    let checked = client.clone();
    let outcome = app
        .db
        .run(move |conn| {
            let Some(grant) = grants::find(conn, grant_id)? else {
                return Ok(Err("the refresh token is invalid"));
            };
            if grant.app != checked.id {
                return Ok(Err("the refresh token is invalid"));
            }
            // An older generation means someone kept a copy of a token that was replaced.
            if generation != grant.generation || !grants::advance(conn, grant.id, generation)? {
                grants::delete(conn, grant.id)?;
                return Ok(Err("the refresh token was already used"));
            }
            let Some(session) = sessions::by_id(conn, grant.session, now)? else {
                grants::delete(conn, grant.id)?;
                return Ok(Err("the session has ended"));
            };
            if !apps::allows(conn, &checked, session.user.id)? {
                grants::delete(conn, grant.id)?;
                return Ok(Err("the user may no longer use this application"));
            }
            let groups = groups::names_for_user(conn, session.user.id)?;
            Ok(Ok((grant, session, groups)))
        })
        .await?;
    let (grant, session, groups) = match outcome {
        Ok(found) => found,
        Err(reason) => return Ok(invalid_grant(reason)),
    };
    // A refresh may narrow the scope, never widen it.
    let scope = match narrowed {
        Some(requested)
            if requested
                .iter()
                .all(|s| grant.scope.split(' ').any(|g| g == s)) =>
        {
            requested.join(" ")
        }
        Some(_) => {
            return Ok(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_scope",
                "the scope exceeds the original grant",
            ));
        }
        None => grant.scope.clone(),
    };
    let next_generation = generation.saturating_add(1);
    // The new refresh token keeps the scope of the grant, as RFC 6749 section 6 requires.
    let refresh = offline(&grant.scope).then_some((grant.id, next_generation));
    issue(
        app,
        &client,
        &session,
        &scope,
        grant.resource.as_deref(),
        None,
        groups,
        refresh,
    )
}

/// Whether a scope lets the client keep access with refresh tokens.
fn offline(scope: &str) -> bool {
    scope.split(' ').any(|scope| scope == "offline_access")
}

#[expect(
    clippy::too_many_arguments,
    reason = "each is a separate input to the response"
)]
fn issue(
    app: &App,
    client: &AppRecord,
    session: &ActiveSession,
    scope: &str,
    resource: Option<&str>,
    nonce: Option<&str>,
    groups: Vec<String>,
    refresh: Option<(grants::GrantId, i64)>,
) -> Result<Response, Failure> {
    let ring = app.key_ring();
    let now = time::now();
    let client_id = client.client_id.clone().unwrap_or_default();
    let subject = tokens::subject(app, session.user.id);
    let holder = Holder::User { subject, session };
    let access_token = tokens::access_token(app, &ring, now, &client_id, &holder, scope, resource)?;
    let has = |name| scope.split(' ').any(|s| s == name);
    let id_token = if has("openid") {
        let claims = UserClaims::new(app, &session.user, groups, scope);
        Some(tokens::id_token(
            app,
            &ring,
            now,
            &client_id,
            client.id_token_alg,
            session,
            &claims,
            nonce,
        )?)
    } else {
        None
    };
    let refresh_token = refresh
        .map(|(grant, generation)| tokens::refresh_token(app, grant, generation))
        .transpose()?;
    Ok(Response::json(&TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_LIFETIME,
        id_token,
        refresh_token,
        scope: scope.to_owned(),
    }))
}

/// A service asking for a token for itself. Its audience is the API it names with `resource`,
/// which must be registered for it, or itself.
fn client_credentials(
    app: &App,
    request: &Request,
    client: &AppRecord,
) -> Result<Response, Failure> {
    let resource = request.form.single("resource").ok().flatten();
    if resource.is_some_and(|resource| !client.resources.iter().any(|known| known == resource)) {
        return Ok(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "the resource isn't registered for this application",
        ));
    }
    let client_id = client.client_id.clone().unwrap_or_default();
    let access_token = tokens::access_token(
        app,
        &app.key_ring(),
        time::now(),
        &client_id,
        &Holder::Client,
        "",
        resource,
    )?;
    Ok(Response::json(&TokenResponse {
        access_token,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_LIFETIME,
        id_token: None,
        refresh_token: None,
        scope: String::new(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_credentials_are_form_decoded() {
        // "my%20app:p%3Ass" in base64
        assert_eq!(
            parse_basic("bXklMjBhcHA6cCUzQXNz"),
            Some(("my app".to_owned(), "p:ss".to_owned()))
        );
        assert_eq!(parse_basic("YTpi"), Some(("a".to_owned(), "b".to_owned())));
        assert_eq!(
            parse_basic("YTpiYw=="),
            Some(("a".to_owned(), "bc".to_owned()))
        );
        assert_eq!(parse_basic("YTpiYw"), None);
        assert_eq!(parse_basic("bm9jb2xvbg=="), None);
    }

    #[test]
    fn verifiers_follow_rfc_7636() {
        assert!(valid_verifier(&"a".repeat(43)));
        assert!(!valid_verifier(&"a".repeat(42)));
        assert!(!valid_verifier(&"a".repeat(129)));
        assert!(!valid_verifier(&format!("{}+", "a".repeat(43))));
    }
}
