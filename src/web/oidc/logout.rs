//! Signing out at an application's request (OpenID Connect RP-Initiated Logout 1.0).

use hyper::{Method, StatusCode};
use serde::Deserialize;

use super::super::csrf::{self, Csrf};
use super::super::i18n::Lang;
use super::super::layout::{auth_page, error_page};
use super::super::{App, Failure, session};
use super::append_query;
use crate::crypto::verify_jwt;
use crate::form::Form;
use crate::html::{Html, html};
use crate::http::{Request, Response};
use crate::store::apps;

#[derive(Deserialize)]
struct Hint {
    iss: String,
    aud: String,
    sid: Option<String>,
}

/// `GET` or `POST /end-session`. The user is asked to confirm, so a link on another site can't
/// sign them out, unless the application sends an ID token of this very session as a hint.
/// Afterwards the user returns to the application if it named a registered address.
pub(crate) async fn end_session(app: &App, request: &Request) -> Result<Response, Failure> {
    let params: &Form = if request.method == Method::POST {
        &request.form
    } else {
        &request.query
    };
    let value = |name| params.single(name).ok().flatten();
    // An expired ID token is still a valid hint, so only the signature and issuer are checked.
    let hint = value("id_token_hint")
        .and_then(|token| verify_jwt(token, &app.key_ring().verifying_keys(), Some("JWT")).ok())
        .and_then(|payload| serde_json::from_slice::<Hint>(&payload).ok())
        .filter(|hint| hint.iss == app.config.issuer.as_str());
    let client_id = match (
        hint.as_ref().map(|hint| hint.aud.as_str()),
        value("client_id"),
    ) {
        (Some(aud), Some(id)) if aud != id => {
            return Ok(error_page(app, request, StatusCode::BAD_REQUEST));
        }
        (Some(aud), _) => Some(aud.to_owned()),
        (None, id) => id.map(str::to_owned),
    };
    let return_to = match (client_id, value("post_logout_redirect_uri")) {
        (Some(client_id), Some(uri)) => {
            let client = app
                .db
                .run(move |conn| apps::by_client_id(conn, &client_id))
                .await?;
            match client {
                Some(client)
                    if client
                        .post_logout_uris
                        .iter()
                        .any(|known| known.as_str() == uri) =>
                {
                    Some(uri)
                }
                _ => return Ok(error_page(app, request, StatusCode::BAD_REQUEST)),
            }
        }
        (None, Some(_)) => return Ok(error_page(app, request, StatusCode::BAD_REQUEST)),
        (_, None) => None,
    };

    if let Some(current) = session::current(app, request).await? {
        let hinted =
            hint.as_ref().and_then(|hint| hint.sid.as_deref()) == Some(current.public_id.as_str());
        let confirmed = request.method == Method::POST && csrf::verify(app, request);
        if !hinted && !confirmed {
            return confirm_page(app, request, params, &current.user.username);
        }
        session::end(app, session::Ending::One(current.id)).await?;
    }
    let response = match return_to {
        Some(uri) => {
            let state: Vec<(&str, &str)> = value("state")
                .map(|state| ("state", state))
                .into_iter()
                .collect();
            Response::redirect(append_query(uri, &state))
        }
        None => signed_out_page(app, request),
    };
    Ok(session::clear(app, response))
}

fn confirm_page(
    app: &App,
    request: &Request,
    params: &Form,
    username: &str,
) -> Result<Response, Failure> {
    let lang = Lang::of(request);
    let text = lang.text();
    let csrf = Csrf::for_page(app, request)?;
    let mut content = Html::new();
    html!(
        content,
        "<h1>",
        { text.sign_out_confirm },
        "</h1><p>",
        { username },
        "</p><form class=\"stack\" method=\"post\" action=\"/end-session\">",
        { csrf.field() }
    );
    for name in [
        "id_token_hint",
        "client_id",
        "post_logout_redirect_uri",
        "state",
    ] {
        if let Some(value) = params.single(name).ok().flatten() {
            html!(
                content,
                "<input type=\"hidden\" name=\"",
                { name },
                "\" value=\"",
                { value },
                "\">"
            );
        }
    }
    html!(
        content,
        "<button class=\"primary block\">",
        { text.sign_out },
        "</button></form>"
    );
    let page = auth_page(app, request, lang, text.sign_out_confirm, &content);
    Ok(csrf.apply(app, Response::html(page)))
}

fn signed_out_page(app: &App, request: &Request) -> Response {
    let lang = Lang::of(request);
    let text = lang.text();
    let mut content = Html::new();
    html!(
        content,
        "<h1>",
        { text.signed_out },
        "</h1><div class=\"alternatives\"><a class=\"button block\" href=\"/login\">",
        { text.sign_in },
        "</a></div>"
    );
    Response::html(auth_page(app, request, lang, text.signed_out, &content))
}
