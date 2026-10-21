//! Creating the first administrator, and setting a password from a one-time link.

use super::account::{new_password_fields, password_problem};
use super::csrf::{self, Csrf};
use super::i18n::Lang;
use super::layout::{auth_page, error_notice, success_notice};
use super::signin::{SignedIn, hash_password};
use super::{App, Failure, session};
use crate::crypto::{TokenHash, random_token};
use crate::encoding::{base64url, decode_base64url};
use crate::html::{Html, html};
use crate::http::{Request, Response};
use crate::store::users::{self, NewUser, Username};
use crate::store::{audit, sessions, settings};
use crate::time;

const SETUP_TOKEN: &str = "setup_token_hash";
const SETUP_EXPIRES: &str = "setup_token_expires";
const SETUP_LIFETIME: i64 = 24 * 60 * 60;
const MAX_NAME_CHARS: usize = 100;

/// Called at start-up. While there are no accounts, makes a new setup token and returns the
/// link that uses it; Unlatch prints it to the log. Only a hash of the token is stored.
pub(crate) async fn prepare(app: &App) -> Result<Option<String>, Failure> {
    let token = random_token()?;
    let hash = base64url(&TokenHash::of(&token).0);
    let expires = time::now().saturating_add(SETUP_LIFETIME).to_string();
    let needed = app
        .db
        .run(move |conn| {
            if users::count(conn)? > 0 {
                settings::remove(conn, SETUP_TOKEN)?;
                return Ok(false);
            }
            settings::set(conn, SETUP_TOKEN, &hash)?;
            settings::set(conn, SETUP_EXPIRES, &expires)?;
            Ok(true)
        })
        .await?;
    Ok(needed.then(|| app.config.issuer.url(&format!("/setup?token={token}"))))
}

/// Whether `token` is the current setup token, there are still no accounts and it hasn't expired.
fn token_valid(conn: &rusqlite::Connection, token: &str) -> Result<bool, crate::store::DbError> {
    let stored = settings::get(conn, SETUP_TOKEN)?.and_then(|hash| decode_base64url(&hash));
    let expires = settings::get(conn, SETUP_EXPIRES)?.and_then(|value| value.parse::<i64>().ok());
    let (Some(stored), Some(expires)) = (stored, expires) else {
        return Ok(false);
    };
    Ok(users::count(conn)? == 0
        && expires > time::now()
        && crate::crypto::constant_time_eq(&stored, &TokenHash::of(token).0))
}

fn token(request: &Request) -> String {
    request
        .form
        .single("token")
        .ok()
        .flatten()
        .or_else(|| request.query.single("token").ok().flatten())
        .unwrap_or_default()
        .to_owned()
}

/// `GET /setup`
pub(super) async fn setup_page(app: &App, request: &Request) -> Result<Option<Response>, Failure> {
    let token = token(request);
    if !app.db.run(move |conn| token_valid(conn, &token)).await? {
        return Ok(None);
    }
    setup_form(app, request, None).map(Some)
}

fn setup_form(app: &App, request: &Request, problem: Option<&str>) -> Result<Response, Failure> {
    let lang = Lang::of(request);
    let text = lang.text();
    let csrf = Csrf::for_page(app, request)?;
    let field = |name| request.form.single(name).ok().flatten().unwrap_or_default();
    let mut content = Html::new();
    html!(content, "<h1>", { text.setup_title }, "</h1>");
    if let Some(problem) = problem {
        html!(content, { error_notice(problem) });
    }
    html!(
        content,
        "<form class=\"stack\" method=\"post\" action=\"/setup\">",
        { csrf.field() },
        "<input type=\"hidden\" name=\"token\" value=\"",
        { token(request) },
        "\"><div><label for=\"name\">",
        { text.display_name },
        "</label><input id=\"name\" name=\"name\" value=\"",
        { field("name") },
        "\" autocomplete=\"name\" maxlength=\"100\" required autofocus></div><div><label for=\"username\">",
        { text.username },
        "</label><input id=\"username\" name=\"username\" value=\"",
        { field("username") },
        "\" autocomplete=\"username\" autocapitalize=\"none\" spellcheck=\"false\" maxlength=\"64\" ",
        "required><p class=\"field-note\">",
        { text.username_note },
        "</p></div>",
        { new_password_fields(text) },
        "<button class=\"primary block\">",
        { text.create },
        "</button></form>"
    );
    let page = auth_page(app, request, lang, text.setup_title, &content);
    Ok(csrf.apply(app, Response::html(page)))
}

/// `POST /setup`: creates the administrator, signs them in and sends them to set up two-factor
/// sign-in, which administration requires.
pub(super) async fn setup_submit(
    app: &App,
    request: &Request,
) -> Result<Option<Response>, Failure> {
    let text = Lang::of(request).text();
    let field = |name| request.form.single(name).ok().flatten().unwrap_or_default();
    let token = token(request);
    let check = token.clone();
    if !app.db.run(move |conn| token_valid(conn, &check)).await? {
        return Ok(None);
    }
    if !csrf::verify(app, request) {
        return setup_form(app, request, Some(text.form_expired)).map(Some);
    }
    let name = field("name").trim().to_owned();
    let Some(username) = Username::parse(field("username").trim()) else {
        return setup_form(app, request, Some(text.username_invalid)).map(Some);
    };
    if name.is_empty() || name.chars().count() > MAX_NAME_CHARS {
        return setup_form(app, request, Some(text.name_required)).map(Some);
    }
    if let Some(problem) = password_problem(text, username.as_str(), field("new"), field("repeat"))
    {
        return setup_form(app, request, Some(problem)).map(Some);
    }
    let hash = hash_password(app, field("new")).await?;
    let ip = request.client_ip.to_string();
    // The checks and the insert run in one closure on the database thread, so two posts with
    // the same token can't both create an administrator.
    let created = app
        .db
        .run(move |conn| {
            if !token_valid(conn, &token)? {
                return Ok(None);
            }
            let new = NewUser {
                username: &username,
                display_name: &name,
                email: None,
                is_admin: true,
            };
            let id = users::create(conn, &new)?;
            users::set_password(conn, id, &hash)?;
            settings::remove(conn, SETUP_TOKEN)?;
            settings::remove(conn, SETUP_EXPIRES)?;
            audit::record(
                conn,
                &audit::Entry {
                    actor: "setup token",
                    action: "create administrator",
                    target: username.as_str(),
                    ip: &ip,
                },
            )?;
            users::by_id(conn, id)
        })
        .await?;
    let Some(user) = created else {
        return Ok(None);
    };
    let signed_in = SignedIn::first_administrator(&user);
    session::start(
        app,
        request,
        signed_in,
        Response::redirect("/account/two-factor"),
    )
    .await
    .map(Some)
}

/// `GET /password`: the form behind a one-time link from an administrator.
pub(super) async fn link_page(app: &App, request: &Request) -> Result<Response, Failure> {
    let token = token(request);
    let hash = TokenHash::of(&token);
    let now = time::now();
    let valid = app
        .db
        .run(move |conn| users::password_link_user(conn, &hash, now))
        .await?
        .is_some();
    link_form(
        app,
        request,
        (!valid).then_some(Lang::of(request).text().link_expired),
    )
}

fn link_form(app: &App, request: &Request, problem: Option<&str>) -> Result<Response, Failure> {
    let lang = Lang::of(request);
    let text = lang.text();
    let csrf = Csrf::for_page(app, request)?;
    let mut content = Html::new();
    html!(content, "<h1>", { text.set_password_title }, "</h1>");
    if let Some(problem) = problem {
        html!(content, { error_notice(problem) });
    }
    html!(
        content,
        "<form class=\"stack\" method=\"post\" action=\"/password\">",
        { csrf.field() },
        "<input type=\"hidden\" name=\"token\" value=\"",
        { token(request) },
        "\">",
        { new_password_fields(text) },
        "<button class=\"primary block\">",
        { text.save },
        "</button></form>"
    );
    let page = auth_page(app, request, lang, text.set_password_title, &content);
    Ok(csrf.apply(app, Response::html(page)))
}

/// `POST /password`: sets the password, uses up the link and ends every session of the user.
pub(super) async fn link_submit(app: &App, request: &Request) -> Result<Response, Failure> {
    let lang = Lang::of(request);
    let text = lang.text();
    if !csrf::verify(app, request) {
        return link_form(app, request, Some(text.form_expired));
    }
    let field = |name| request.form.single(name).ok().flatten().unwrap_or_default();
    let hash = TokenHash::of(&token(request));
    let now = time::now();
    let user = app
        .db
        .run(
            move |conn| match users::password_link_user(conn, &hash, now)? {
                Some(id) => users::by_id(conn, id),
                None => Ok(None),
            },
        )
        .await?;
    let Some(user) = user else {
        return link_form(app, request, Some(text.link_expired));
    };
    if let Some(problem) = password_problem(text, &user.username, field("new"), field("repeat")) {
        return link_form(app, request, Some(problem));
    }
    let password_hash = hash_password(app, field("new")).await?;
    let ip = request.client_ip.to_string();
    let set = app
        .db
        .run(move |conn| {
            if users::password_link_user(conn, &hash, time::now())? != Some(user.id) {
                return Ok(false);
            }
            users::set_password(conn, user.id, &password_hash)?;
            users::delete_password_links(conn, user.id)?;
            sessions::delete_for_user(conn, user.id, None)?;
            audit::record(
                conn,
                &audit::Entry {
                    actor: &user.username,
                    action: "set password from link",
                    target: &user.username,
                    ip: &ip,
                },
            )?;
            Ok(true)
        })
        .await?;
    if !set {
        return link_form(app, request, Some(text.link_expired));
    }
    let mut content = Html::new();
    html!(
        content,
        "<h1>",
        { text.set_password_title },
        "</h1>",
        { success_notice(text.password_set) },
        "<div class=\"alternatives\"><a class=\"button primary block\" href=\"/login\">",
        { text.sign_in },
        "</a></div>"
    );
    Ok(Response::html(auth_page(
        app,
        request,
        lang,
        text.set_password_title,
        &content,
    )))
}
