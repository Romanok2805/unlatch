//! Cross-origin requests from browser apps to the token, userinfo and revocation endpoints.
//!
//! An origin is allowed if a redirect URI of an enabled application lives there. These endpoints
//! authenticate with tokens or client credentials, never with cookies, so credentials are not
//! allowed across origins.

use hyper::{StatusCode, header};

use super::super::{App, Failure};
use crate::http::{Request, Response};
use crate::store::apps;

/// The request's origin, if it is one of our applications'.
async fn allowed_origin(app: &App, request: &Request) -> Result<Option<String>, Failure> {
    let Some(origin) = request.header("origin").map(str::to_owned) else {
        return Ok(None);
    };
    let origins = app.db.run(|conn| apps::redirect_origins(conn)).await?;
    Ok(origins.contains(&origin).then_some(origin))
}

/// Adds the CORS header to a response for an allowed origin.
pub(crate) async fn allow(
    app: &App,
    request: &Request,
    response: Response,
) -> Result<Response, Failure> {
    let response = response.header(header::VARY, "Origin");
    Ok(match allowed_origin(app, request).await? {
        Some(origin) => response.header(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin),
        None => response,
    })
}

/// Answers a preflight `OPTIONS` request.
pub(crate) async fn preflight(app: &App, request: &Request) -> Result<Response, Failure> {
    let Some(origin) = allowed_origin(app, request).await? else {
        return Ok(Response::text(StatusCode::FORBIDDEN, "origin not allowed")
            .header(header::VARY, "Origin"));
    };
    Ok(Response::new(StatusCode::NO_CONTENT, "text/plain", "")
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin)
        .header(header::ACCESS_CONTROL_ALLOW_METHODS, "GET, POST")
        .header(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            "authorization, content-type",
        )
        .header(header::ACCESS_CONTROL_MAX_AGE, "600")
        .header(header::VARY, "Origin"))
}
