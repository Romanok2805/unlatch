//! The authorization endpoint: checking the request, signing in, consent, and the code.

use hyper::StatusCode;

use super::super::csrf::{self, Csrf};
use super::super::i18n::Lang;
use super::super::layout::{auth_page, error_page, icon};
use super::super::{App, Failure, session};
use super::request::{self, AuthRequest, Rejection};
use super::{CODE_LIFETIME, append_query};
use crate::crypto::{TokenHash, random_token};
use crate::form::{Form, encode};
use crate::html::{Html, html};
use crate::http::{Request, Response};
use crate::store::apps::{self, AppRecord};
use crate::store::grants::{self, NewCode};
use crate::store::sessions::ActiveSession;
use crate::time;

const CONTINUE: &str = "/authorize/continue";

/// `GET` or `POST /authorize`: checks the request and continues with it sealed in the URL, which
/// is also where sign-in returns to.
pub(crate) async fn authorize(
    app: &App,
    request: &Request,
    form: &Form,
) -> Result<Response, Failure> {
    match request::check(app, form).await? {
        Ok((auth, _)) => Ok(Response::redirect(continue_url(
            &auth.seal(&app.keys.requests)?,
        ))),
        Err(Rejection::Page) => Ok(error_page(app, request, StatusCode::BAD_REQUEST)),
        Err(Rejection::Redirect {
            redirect_uri,
            state,
            form_post,
            error,
            description,
        }) => Ok(error_redirect(
            app,
            request,
            &ReplyTo {
                redirect_uri: &redirect_uri,
                state: state.as_deref(),
                form_post,
            },
            error,
            description,
        )),
    }
}

fn continue_url(sealed: &str) -> String {
    format!("{CONTINUE}?req={sealed}")
}

/// Where and how to answer the client.
struct ReplyTo<'a> {
    redirect_uri: &'a str,
    state: Option<&'a str>,
    form_post: bool,
}

impl AuthRequest {
    fn reply_to(&self) -> ReplyTo<'_> {
        ReplyTo {
            redirect_uri: &self.redirect_uri,
            state: self.state.as_deref(),
            form_post: self.form_post,
        }
    }
}

/// An error sent back to the client.
fn error_redirect(
    app: &App,
    request: &Request,
    to: &ReplyTo<'_>,
    error: &str,
    description: &str,
) -> Response {
    send_back(
        app,
        request,
        to,
        &[("error", error), ("error_description", description)],
    )
}

/// Sends parameters to the client with its `state` and our `iss`, so it can tell which server
/// answered (RFC 9207): in the query of a redirect, or in a form the browser posts, which keeps
/// codes out of URLs and logs.
fn send_back(app: &App, request: &Request, to: &ReplyTo<'_>, pairs: &[(&str, &str)]) -> Response {
    let mut pairs = pairs.to_vec();
    if let Some(state) = to.state {
        pairs.push(("state", state));
    }
    pairs.push(("iss", app.config.issuer.as_str()));
    if !to.form_post {
        return Response::redirect(append_query(to.redirect_uri, &pairs));
    }
    let lang = Lang::of(request);
    let text = lang.text();
    let mut content = Html::new();
    html!(
        content,
        "<form method=\"post\" action=\"",
        { to.redirect_uri },
        "\" data-autosubmit-form>"
    );
    for (name, value) in &pairs {
        html!(
            content,
            "<input type=\"hidden\" name=\"",
            { name },
            "\" value=\"",
            { value },
            "\">"
        );
    }
    html!(
        content,
        "<button class=\"primary block\">",
        { text.continue_setup },
        "</button></form>"
    );
    Response::html(auth_page(app, request, lang, text.continue_setup, &content))
}

/// The name of the application a sign-in is for, when the sign-in continues an authorization.
pub(crate) fn client_name_for(app: &App, next: &str) -> Option<String> {
    let sealed = next.strip_prefix(CONTINUE)?.strip_prefix("?req=")?;
    AuthRequest::open(sealed, &app.keys.requests).map(|auth| auth.client_name)
}

fn open(app: &App, request: &Request) -> Option<AuthRequest> {
    let from = |form: &Form| form.single("req").ok().flatten().map(str::to_owned);
    let sealed = from(&request.form).or_else(|| from(&request.query))?;
    AuthRequest::open(&sealed, &app.keys.requests)
}

/// What is still needed before a code can be issued.
enum Next {
    SignIn { force: bool },
    NoAccess(ActiveSession),
    Consent(ActiveSession),
    Code(ActiveSession),
}

async fn next_step(
    app: &App,
    request: &Request,
    auth: &AuthRequest,
    client: &AppRecord,
) -> Result<Next, Failure> {
    let Some(session) = session::current(app, request).await? else {
        return Ok(Next::SignIn { force: false });
    };
    let now = time::now();
    // A fresh sign-in is due if the client asked for one after the request was made, or if the
    // last one is older than max_age.
    let stale = auth
        .max_age
        .is_some_and(|max_age| now.saturating_sub(session.auth_time) > max_age);
    if (auth.prompt.login && session.auth_time < auth.issued_at) || stale {
        return Ok(Next::SignIn { force: true });
    }
    let (app_record, user) = (client.clone(), session.user.id);
    let app_id = client.id;
    let (allowed, consented) = app
        .db
        .run(move |conn| {
            Ok((
                apps::allows(conn, &app_record, user)?,
                apps::consent(conn, app_id, user)?,
            ))
        })
        .await?;
    if !allowed {
        return Ok(Next::NoAccess(session));
    }
    let covered = consented.is_some_and(|granted| {
        auth.scopes()
            .all(|scope| granted.split(' ').any(|g| g == scope))
    });
    if auth.prompt.consent || !(client.skip_consent || covered) {
        return Ok(Next::Consent(session));
    }
    Ok(Next::Code(session))
}

/// `GET /authorize/continue`
pub(crate) async fn resume(app: &App, request: &Request) -> Result<Response, Failure> {
    let Some(auth) = open(app, request) else {
        return Ok(expired(app, request));
    };
    let client_id = auth.client_id.clone();
    let Some(client) = app
        .db
        .run(move |conn| apps::by_client_id(conn, &client_id))
        .await?
    else {
        return Ok(expired(app, request));
    };
    if !client.enabled {
        return Ok(error_redirect(
            app,
            request,
            &auth.reply_to(),
            "unauthorized_client",
            "the application is disabled",
        ));
    }
    match next_step(app, request, &auth, &client).await? {
        Next::SignIn { .. } if auth.prompt.none => Ok(error_redirect(
            app,
            request,
            &auth.reply_to(),
            "login_required",
            "the user isn't signed in",
        )),
        Next::SignIn { force } => {
            let mut url = format!("/login?next={}", encode(&request.target));
            if force {
                url.push_str("&force=1");
            }
            if let Some(hint) = &auth.login_hint {
                url.push_str("&username=");
                url.push_str(&encode(hint));
            }
            Ok(Response::redirect(url))
        }
        Next::NoAccess(_) if auth.prompt.none => Ok(error_redirect(
            app,
            request,
            &auth.reply_to(),
            "access_denied",
            "the user may not use this application",
        )),
        Next::NoAccess(session) => no_access(app, request, &auth, &session),
        Next::Consent(_) if auth.prompt.none => Ok(error_redirect(
            app,
            request,
            &auth.reply_to(),
            "consent_required",
            "the user hasn't consented",
        )),
        Next::Consent(session) => consent_page(app, request, &auth, &client, &session),
        Next::Code(session) => issue_code(app, request, &auth, &client, &session).await,
    }
}

/// `POST /authorize/continue`: the answer on the consent page.
pub(crate) async fn decide(app: &App, request: &Request) -> Result<Response, Failure> {
    let Some(auth) = open(app, request) else {
        return Ok(expired(app, request));
    };
    if !csrf::verify(app, request) {
        return Ok(Response::redirect(continue_url(
            &auth.seal(&app.keys.requests)?,
        )));
    }
    let client_id = auth.client_id.clone();
    let Some(client) = app
        .db
        .run(move |conn| apps::by_client_id(conn, &client_id))
        .await?
    else {
        return Ok(expired(app, request));
    };
    let session = match next_step(app, request, &auth, &client).await? {
        Next::Consent(session) | Next::Code(session) => session,
        Next::SignIn { .. } | Next::NoAccess(_) => {
            return Ok(Response::redirect(continue_url(
                &auth.seal(&app.keys.requests)?,
            )));
        }
    };
    if request.form.single("decision").ok().flatten() != Some("allow") {
        return Ok(error_redirect(
            app,
            request,
            &auth.reply_to(),
            "access_denied",
            "the user declined",
        ));
    }
    let (app_id, user, scope) = (client.id, session.user.id, auth.scope.clone());
    app.db
        .run(move |conn| apps::save_consent(conn, app_id, user, &scope))
        .await?;
    issue_code(app, request, &auth, &client, &session).await
}

/// Stores a code for one minute and sends it to the client.
async fn issue_code(
    app: &App,
    request: &Request,
    auth: &AuthRequest,
    client: &AppRecord,
    session: &ActiveSession,
) -> Result<Response, Failure> {
    let code = random_token()?;
    let (hash, app_id, session_id) = (TokenHash::of(&code), client.id, session.id);
    let (redirect_uri, scope, nonce) = (
        auth.redirect_uri.clone(),
        auth.scope.clone(),
        auth.nonce.clone(),
    );
    let (challenge, resource) = (auth.code_challenge.clone(), auth.resource.clone());
    let expires_at = time::now().saturating_add(CODE_LIFETIME);
    app.db
        .run(move |conn| {
            grants::create_code(
                conn,
                &NewCode {
                    hash,
                    app: app_id,
                    session: session_id,
                    redirect_uri: &redirect_uri,
                    scope: &scope,
                    nonce: nonce.as_deref(),
                    code_challenge: &challenge,
                    resource: resource.as_deref(),
                    expires_at,
                },
            )
        })
        .await?;
    Ok(send_back(
        app,
        request,
        &auth.reply_to(),
        &[("code", code.as_str())],
    ))
}

fn consent_page(
    app: &App,
    request: &Request,
    auth: &AuthRequest,
    client: &AppRecord,
    session: &ActiveSession,
) -> Result<Response, Failure> {
    let lang = Lang::of(request);
    let text = lang.text();
    let csrf = Csrf::for_page(app, request)?;
    let host = auth
        .redirect_uri
        .split_once("://")
        .map_or(auth.redirect_uri.as_str(), |(_, rest)| {
            rest.split(['/', '?']).next().unwrap_or(rest)
        });
    let title = format!("{} {}", text.consent_title, client.name);
    let mut content = Html::new();
    html!(
        content,
        "<h1>",
        { title },
        "</h1><p>",
        { host },
        "</p><ul class=\"rows\">"
    );
    for scope in auth.scopes() {
        let (glyph, label) = match scope {
            "openid" => ("key-round", text.scope_openid),
            "profile" => ("user", text.scope_profile),
            "email" => ("mail", text.scope_email),
            "groups" => ("users", text.scope_groups),
            _ => ("refresh-cw", text.scope_offline_access),
        };
        html!(
            content,
            "<li>",
            { icon(glyph) },
            "<span>",
            { label },
            "</span></li>"
        );
    }
    let sealed = auth.seal(&app.keys.requests)?;
    html!(
        content,
        "</ul><form class=\"actions\" method=\"post\" action=\"/authorize/continue\">",
        { csrf.field() },
        "<input type=\"hidden\" name=\"req\" value=\"",
        { sealed },
        "\"><button name=\"decision\" value=\"deny\">",
        { text.deny },
        "</button><button name=\"decision\" value=\"allow\" class=\"primary\">",
        { text.allow },
        "</button></form><div class=\"signed-in-as\"><span>",
        { session.user.username },
        "</span><a href=\"",
        { switch_account_url(&sealed) },
        "\">",
        { text.switch_account },
        "</a></div>"
    );
    let page = auth_page(app, request, lang, &title, &content);
    Ok(csrf.apply(app, Response::html(page)))
}

fn switch_account_url(sealed: &str) -> String {
    format!("/login?force=1&next={}", encode(&continue_url(sealed)))
}

fn no_access(
    app: &App,
    request: &Request,
    auth: &AuthRequest,
    session: &ActiveSession,
) -> Result<Response, Failure> {
    let lang = Lang::of(request);
    let text = lang.text();
    let title = format!("{} {}", text.no_access, auth.client_name);
    let sealed = auth.seal(&app.keys.requests)?;
    let mut content = Html::new();
    html!(
        content,
        "<h1>",
        { title },
        "</h1><p>",
        { session.user.username },
        "</p><div class=\"alternatives\"><a class=\"button block\" href=\"",
        { switch_account_url(&sealed) },
        "\">",
        { text.switch_account },
        "</a></div>"
    );
    Ok(
        Response::html(auth_page(app, request, lang, &title, &content))
            .status(StatusCode::FORBIDDEN),
    )
}

fn expired(app: &App, request: &Request) -> Response {
    let lang = Lang::of(request);
    let text = lang.text();
    let mut content = Html::new();
    html!(content, "<h1>", { text.request_expired }, "</h1>");
    Response::html(auth_page(
        app,
        request,
        lang,
        text.request_expired,
        &content,
    ))
    .status(StatusCode::BAD_REQUEST)
}
