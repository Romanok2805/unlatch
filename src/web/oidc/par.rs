//! Pushed authorization requests (RFC 9126): the client sends its request straight to us, and the
//! browser carries only a reference. Nobody on the way can read or change the request, and a
//! confidential client proves who it is before the user sees anything.

use hyper::StatusCode;
use serde::Serialize;

use super::super::{App, Failure};
use super::request::{self, Arrival, Rejection};
use super::token::{authenticate, oauth_error};
use super::{PUSHED_REQUEST_LIFETIME, dpop};
use crate::http::{Request, Response};

#[derive(Serialize)]
struct Pushed {
    request_uri: String,
    expires_in: i64,
}

/// `POST /par`
pub(crate) async fn push(app: &App, request: &Request) -> Result<Response, Failure> {
    let client = match authenticate(app, request, false).await? {
        Ok(client) => client,
        Err(response) => return Ok(response),
    };
    let mut auth = match request::check(app, &request.form, Arrival::Pushed).await? {
        Ok((auth, checked)) if checked.id == client.id => auth,
        Ok(_) | Err(Rejection::Page) => {
            return Ok(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "the client_id or redirect_uri isn't registered",
            ));
        }
        Err(Rejection::Redirect {
            error, description, ..
        }) => return Ok(oauth_error(StatusCode::BAD_REQUEST, error, description)),
    };
    // A proof sent with the request binds the code to its key, as dpop_jkt would (RFC 9449
    // section 10.1).
    match dpop::check(app, request, "/par", None) {
        Ok(None) => {}
        Ok(Some(key)) if auth.dpop_jkt.as_ref().is_none_or(|jkt| *jkt == key) => {
            auth.dpop_jkt = Some(key);
        }
        Ok(Some(_)) => {
            return Ok(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_dpop_proof",
                "the DPoP proof and dpop_jkt name different keys",
            ));
        }
        Err(description) => {
            return Ok(oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_dpop_proof",
                description,
            ));
        }
    }
    Ok(Response::json(&Pushed {
        request_uri: auth.request_uri(&app.keys.requests)?,
        expires_in: PUSHED_REQUEST_LIFETIME,
    })
    .status(StatusCode::CREATED))
}
