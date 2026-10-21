//! The account page: password and two-factor sign-in.

use super::csrf::{self, Csrf};
use super::i18n::{Lang, Text};
use super::layout::{auth_page, error_notice, icon, success_notice};
use super::session_table::describe_device;
use super::signin::{check_password, hash_password, recovery_code_hash, totp_context, verify_code};
use super::{App, Failure, qr, session};
use crate::crypto::{random_bytes, totp};
use crate::encoding::{base32, base64url, decode_base64url};
use crate::html::{Html, html};
use crate::http::{Request, Response};
use crate::store::sessions::{self, ActiveSession, SessionId, SessionSummary};
use crate::store::users::UserId;
use crate::store::{audit, providers, users};
use crate::time::{self, format_utc};

const MIN_PASSWORD_CHARS: usize = 12;
const MAX_PASSWORD_CHARS: usize = 256;
const RECOVERY_CODES: usize = 10;

/// Long passwords that still top the lists from breaches. Shorter ones fail the length rule.
const COMMON_PASSWORDS: [&str; 24] = [
    "123456789012",
    "1234567890123",
    "12345678901234",
    "111111111111",
    "000000000000",
    "123123123123",
    "qwertyuiop12",
    "qwertyuiopasdf",
    "qwerty123456",
    "123456qwerty",
    "1q2w3e4r5t6y",
    "1qaz2wsx3edc",
    "zaq12wsxcde3",
    "qwertyqwerty",
    "asdfghjkl123",
    "password1234",
    "password12345",
    "password123456",
    "passwordpassword",
    "iloveyou1234",
    "letmein12345",
    "welcome12345",
    "changeme1234",
    "administrator",
];

/// What is wrong with a new password, following NIST SP 800-63B-4: long enough, not too long to
/// hash, not a known common one and not the user name. No rules about character classes.
pub(super) fn password_problem(
    text: &Text,
    username: &str,
    password: &str,
    repeated: &str,
) -> Option<&'static str> {
    let chars = password.chars().count();
    let lowered = password.to_lowercase();
    let mut distinct = password.chars();
    let first = distinct.next();
    if password != repeated {
        Some(text.passwords_differ)
    } else if chars < MIN_PASSWORD_CHARS {
        Some(text.password_too_short)
    } else if chars > MAX_PASSWORD_CHARS {
        Some(text.password_too_long)
    } else if COMMON_PASSWORDS.contains(&lowered.as_str())
        || lowered.contains(username)
        || distinct.all(|c| Some(c) == first)
    {
        Some(text.password_too_common)
    } else {
        None
    }
}

/// `GET /account`
pub(super) async fn overview(app: &App, request: &Request) -> Result<Response, Failure> {
    let Some(session) = session::current(app, request).await? else {
        return Ok(session::to_sign_in(request));
    };
    let lang = Lang::of(request);
    let text = lang.text();
    let csrf = Csrf::for_page(app, request)?;
    let user = &session.user;
    let mut content = Html::new();
    html!(
        content,
        "<h1>",
        { user.display_name },
        "</h1><p>",
        { user.username },
        "</p><ul class=\"rows\"><li>",
        { icon("key-round") },
        "<span>",
        { text.password },
        "</span><a href=\"/account/password\">",
        { text.change },
        "</a></li><li>",
        { icon("shield-check") },
        "<span>",
        { text.two_factor },
        "</span><a href=\"/account/two-factor\">",
        {
            if user.totp_secret.is_some() {
                text.on
            } else {
                text.off
            }
        },
        "</a></li>"
    );
    if user.is_admin {
        html!(
            content,
            "<li>",
            { icon("sliders-horizontal") },
            "<span>",
            { text.administration },
            "</span><a href=\"/admin\">",
            { text.open },
            "</a></li>"
        );
    }
    let (user_id, now) = (user.id, time::now());
    let others = app
        .db
        .run(move |conn| sessions::list(conn, Some(user_id), now))
        .await?;
    html!(content, "</ul>");
    provider_list(app, &mut content, text, &csrf, user.id).await?;
    html!(content, "<h2>", { text.section_sessions }, "</h2>");
    session_list(&mut content, text, &csrf, &others, session.id);
    html!(
        content,
        "<form method=\"post\" action=\"/logout\">",
        { csrf.field() },
        "<button class=\"block\">",
        { icon("log-out") },
        { text.sign_out },
        "</button></form>"
    );
    let page = auth_page(app, request, lang, text.account_title, &content);
    Ok(csrf.apply(app, Response::html(page)))
}

/// The enabled sign-in providers, each with a button to link or unlink it.
async fn provider_list(
    app: &App,
    out: &mut Html,
    text: &Text,
    csrf: &Csrf,
    user: UserId,
) -> Result<(), Failure> {
    let enabled = super::providers::enabled(app).await?;
    if enabled.is_empty() {
        return Ok(());
    }
    let linked = app
        .db
        .run(move |conn| providers::linked_providers(conn, user))
        .await?;
    html!(
        *out,
        "<h2>",
        { text.section_providers },
        "</h2><ul class=\"rows\">"
    );
    for provider in &enabled {
        let is_linked = linked.contains(&provider.id);
        let google = provider.issuer.as_deref() == Some("https://accounts.google.com");
        html!(
            *out,
            "<li>",
            { icon(if google { "google" } else { "globe" }) },
            "<span>",
            { provider.name },
            "</span><form method=\"post\" action=\"/account/providers\">",
            { csrf.field() },
            "<input type=\"hidden\" name=\"provider\" value=\"",
            { provider.slug },
            "\"><button class=\"compact\" name=\"action\" value=\"",
            { if is_linked { "unlink" } else { "link" } },
            "\">",
            { if is_linked { text.unlink } else { text.link } },
            "</button></form></li>"
        );
    }
    html!(*out, "</ul>");
    Ok(())
}

/// The user's sessions, each with a button that ends it, except the current one.
fn session_list(
    out: &mut Html,
    text: &Text,
    csrf: &Csrf,
    list: &[SessionSummary],
    current: SessionId,
) {
    html!(*out, "<ul class=\"rows\">");
    for other in list {
        html!(
            *out,
            "<li>",
            { icon("monitor-smartphone") },
            "<span>",
            { describe_device(&other.user_agent) },
            "<br><span class=\"field-note\">",
            { other.ip },
            " · ",
            { format_utc(other.last_seen_at) },
            "</span></span>"
        );
        if other.id == current {
            html!(
                *out,
                "<span class=\"field-note\">",
                { text.this_session },
                "</span>"
            );
        } else {
            html!(
                *out,
                "<form method=\"post\" action=\"/account/sessions\">",
                { csrf.field() },
                "<button class=\"compact\" name=\"session\" value=\"",
                { other.id.0 },
                "\">",
                { text.end },
                "</button></form>"
            );
        }
        html!(*out, "</li>");
    }
    html!(*out, "</ul>");
}

/// `POST /account/sessions`: ends one of the user's other sessions.
pub(super) async fn end_session(app: &App, request: &Request) -> Result<Response, Failure> {
    let Some(session) = session::current(app, request).await? else {
        return Ok(session::to_sign_in(request));
    };
    let id = request
        .form
        .single("session")
        .ok()
        .flatten()
        .and_then(|id| id.parse().ok());
    if let (true, Some(id)) = (csrf::verify(app, request), id) {
        session::end(app, session::Ending::Owned(SessionId(id), session.user.id)).await?;
    }
    Ok(Response::redirect("/account"))
}

/// `GET /account/password`
pub(super) async fn password_page(app: &App, request: &Request) -> Result<Response, Failure> {
    if session::current(app, request).await?.is_none() {
        return Ok(session::to_sign_in(request));
    }
    password_form(app, request, None, false)
}

fn password_form(
    app: &App,
    request: &Request,
    message: Option<&str>,
    done: bool,
) -> Result<Response, Failure> {
    let lang = Lang::of(request);
    let text = lang.text();
    let csrf = Csrf::for_page(app, request)?;
    let mut content = Html::new();
    html!(content, "<h1>", { text.password }, "</h1>");
    match (message, done) {
        (Some(message), true) => html!(content, { success_notice(message) }),
        (Some(message), false) => html!(content, { error_notice(message) }),
        (None, _) => {}
    }
    html!(
        content,
        "<form class=\"stack\" method=\"post\" action=\"/account/password\">",
        { csrf.field() },
        "<div><label for=\"current\">",
        { text.current_password },
        "</label><input id=\"current\" name=\"current\" type=\"password\" autocomplete=\"current-password\" required></div>",
        { new_password_fields(text) },
        "<button class=\"primary block\">",
        { text.save },
        "</button></form><div class=\"alternatives\"><a href=\"/account\">",
        { icon("arrow-left") },
        { text.account_title },
        "</a></div>"
    );
    let page = auth_page(app, request, lang, text.password, &content);
    Ok(csrf.apply(app, Response::html(page)))
}

/// The "new password" and "repeat" fields, shared with setup and password links.
pub(super) fn new_password_fields(text: &Text) -> Html {
    let mut out = Html::new();
    html!(
        out,
        "<div><label for=\"new\">",
        { text.new_password },
        "</label><input id=\"new\" name=\"new\" type=\"password\" autocomplete=\"new-password\" minlength=\"12\" required>",
        "</div><div><label for=\"repeat\">",
        { text.repeat_password },
        "</label><input id=\"repeat\" name=\"repeat\" type=\"password\" autocomplete=\"new-password\" required></div>"
    );
    out
}

/// `POST /account/password`: changes the password and signs out every other session, which may
/// belong to whoever knew the old one.
pub(super) async fn password_submit(app: &App, request: &Request) -> Result<Response, Failure> {
    let Some(session) = session::current(app, request).await? else {
        return Ok(session::to_sign_in(request));
    };
    let text = Lang::of(request).text();
    if !csrf::verify(app, request) {
        return password_form(app, request, Some(text.form_expired), false);
    }
    let field = |name| request.form.single(name).ok().flatten().unwrap_or_default();
    let user = &session.user;
    if !app
        .limits
        .password_attempt(request.client_ip, &user.username)
    {
        return password_form(app, request, Some(text.too_many_attempts), false);
    }
    if !check_password(app, field("current"), user.password_hash.clone()).await? {
        return password_form(app, request, Some(text.wrong_password), false);
    }
    app.limits
        .password_succeeded(request.client_ip, &user.username);
    if let Some(problem) = password_problem(text, &user.username, field("new"), field("repeat")) {
        return password_form(app, request, Some(problem), false);
    }
    let hash = hash_password(app, field("new")).await?;
    let (id, username, ip) = (
        user.id,
        user.username.clone(),
        request.client_ip.to_string(),
    );
    app.db
        .run(move |conn| {
            users::set_password(conn, id, &hash)?;
            audit::record(
                conn,
                &audit::Entry {
                    actor: &username,
                    action: "change password",
                    target: &username,
                    ip: &ip,
                },
            )
        })
        .await?;
    session::end(app, session::Ending::AllOf(user.id, Some(session.id))).await?;
    password_form(app, request, Some(text.password_changed), true)
}

/// `GET /account/two-factor`
pub(super) async fn two_factor_page(app: &App, request: &Request) -> Result<Response, Failure> {
    let Some(session) = session::current(app, request).await? else {
        return Ok(session::to_sign_in(request));
    };
    if session.user.totp_secret.is_some() {
        manage_page(app, request, &session, None).await
    } else {
        let secret = totp::generate_secret()?;
        enrol_page(app, request, &session, secret.expose(), None)
    }
}

/// Setting up: a QR code, the key as text, and a field for the first code. The secret travels
/// in the form, sealed and tied to this user, until a code proves the app has it; only then is
/// it stored.
fn enrol_page(
    app: &App,
    request: &Request,
    session: &ActiveSession,
    secret: &[u8],
    problem: Option<&str>,
) -> Result<Response, Failure> {
    let lang = Lang::of(request);
    let text = lang.text();
    let csrf = Csrf::for_page(app, request)?;
    let user = &session.user;
    let sealed = base64url(&app.keys.forms.seal(secret, &enrolment_context(user.id))?);
    let uri = totp::uri(secret, &app.branding().name, &user.username);
    let key: Vec<String> = base32(secret)
        .as_bytes()
        .chunks(4)
        .map(|group| String::from_utf8_lossy(group).into_owned())
        .collect();
    let mut content = Html::new();
    html!(
        content,
        "<h1>",
        { text.two_factor },
        "</h1><p>",
        { text.scan_code },
        "</p>"
    );
    if let Some(problem) = problem {
        html!(content, { error_notice(problem) });
    }
    html!(
        content,
        { qr::svg(&uri, text.scan_code) },
        "<details><summary>",
        { text.enter_key_manually },
        "</summary><code>",
        { key.join(" ") },
        "</code></details><form class=\"stack\" method=\"post\" action=\"/account/two-factor\">",
        { csrf.field() },
        "<input type=\"hidden\" name=\"action\" value=\"enable\"><input type=\"hidden\" name=\"secret\" value=\"",
        { sealed },
        "\"><div><label for=\"code\">",
        { text.code },
        "</label><input id=\"code\" name=\"code\" class=\"code-input\" inputmode=\"numeric\" ",
        "autocomplete=\"one-time-code\" maxlength=\"7\" required></div><button class=\"primary block\">",
        { text.confirm },
        "</button></form>"
    );
    let page = auth_page(app, request, lang, text.two_factor, &content);
    Ok(csrf.apply(app, Response::html(page)))
}

fn enrolment_context(user: UserId) -> Vec<u8> {
    format!("enrol {}", user.0).into_bytes()
}

async fn manage_page(
    app: &App,
    request: &Request,
    session: &ActiveSession,
    problem: Option<&str>,
) -> Result<Response, Failure> {
    let lang = Lang::of(request);
    let text = lang.text();
    let csrf = Csrf::for_page(app, request)?;
    let id = session.user.id;
    let left = app
        .db
        .run(move |conn| users::recovery_code_count(conn, id))
        .await?;
    let mut content = Html::new();
    html!(
        content,
        "<h1>",
        { text.two_factor },
        "</h1><p>",
        { text.on },
        " · ",
        { text.recovery_codes_left },
        ": ",
        { left },
        "</p>"
    );
    if let Some(problem) = problem {
        html!(content, { error_notice(problem) });
    }
    html!(
        content,
        "<form class=\"stack\" method=\"post\" action=\"/account/two-factor\">",
        { csrf.field() },
        "<div><label for=\"code\">",
        { text.code },
        "</label><input id=\"code\" name=\"code\" class=\"code-input\" inputmode=\"numeric\" ",
        "autocomplete=\"one-time-code\" maxlength=\"7\" required></div>",
        "<button class=\"primary block\" name=\"action\" value=\"codes\">",
        { text.new_recovery_codes },
        "</button>"
    );
    if session.user.is_admin {
        html!(
            content,
            "<p class=\"field-note\">",
            { text.admins_keep_two_factor },
            "</p>"
        );
    } else {
        html!(
            content,
            "<button class=\"block danger\" name=\"action\" value=\"off\">",
            { text.turn_off },
            "</button>"
        );
    }
    html!(
        content,
        "</form><div class=\"alternatives\"><a href=\"/account\">",
        { icon("arrow-left") },
        { text.account_title },
        "</a></div>"
    );
    let page = auth_page(app, request, lang, text.two_factor, &content);
    Ok(csrf.apply(app, Response::html(page)))
}

/// `POST /account/two-factor`: turns it on, makes new recovery codes or turns it off. Each
/// needs a valid code, so a session left open somewhere is not enough to change it.
pub(super) async fn two_factor_submit(app: &App, request: &Request) -> Result<Response, Failure> {
    let Some(session) = session::current(app, request).await? else {
        return Ok(session::to_sign_in(request));
    };
    let text = Lang::of(request).text();
    let user = &session.user;
    let code = request
        .form
        .single("code")
        .ok()
        .flatten()
        .unwrap_or_default();
    let action = request
        .form
        .single("action")
        .ok()
        .flatten()
        .unwrap_or_default();
    let key = user.id.0.to_string();
    let limits = &app.limits;
    let problem = if !csrf::verify(app, request) {
        Some(text.form_expired)
    } else if !limits.code_attempt(&key) {
        Some(text.too_many_attempts)
    } else {
        None
    };

    if action == "enable" && user.totp_secret.is_none() {
        let secret = request
            .form
            .single("secret")
            .ok()
            .flatten()
            .and_then(decode_base64url)
            .and_then(|sealed| app.keys.forms.open(&sealed, &enrolment_context(user.id)));
        let Some(secret) = secret else {
            return Ok(Response::redirect("/account/two-factor"));
        };
        if let Some(problem) = problem {
            return enrol_page(app, request, &session, secret.expose(), Some(problem));
        }
        let now = u64::try_from(time::now()).unwrap_or(0);
        let Some(step) = totp::verify(secret.expose(), code, now, None) else {
            return enrol_page(
                app,
                request,
                &session,
                secret.expose(),
                Some(text.wrong_code),
            );
        };
        limits.code_succeeded(&key);
        let sealed = app
            .keys
            .secrets
            .seal(secret.expose(), &totp_context(user.id))?;
        let (id, step) = (user.id, i64::try_from(step).unwrap_or(i64::MAX));
        app.db
            .run(move |conn| {
                users::set_totp(conn, id, Some(&sealed))?;
                users::accept_totp_step(conn, id, step).map(|_| ())
            })
            .await?;
        record(app, request, &session, "turn on two-factor sign-in").await?;
        return new_recovery_codes(app, request, &session).await;
    }
    if user.totp_secret.is_none() {
        return Ok(Response::redirect("/account/two-factor"));
    }
    if let Some(problem) = problem {
        return manage_page(app, request, &session, Some(problem)).await;
    }
    if !verify_code(app, user, code).await? {
        return manage_page(app, request, &session, Some(text.wrong_code)).await;
    }
    limits.code_succeeded(&key);
    match action {
        "codes" => new_recovery_codes(app, request, &session).await,
        "off" if !user.is_admin => {
            let id = user.id;
            app.db
                .run(move |conn| users::set_totp(conn, id, None))
                .await?;
            record(app, request, &session, "turn off two-factor sign-in").await?;
            Ok(Response::redirect("/account"))
        }
        _ => Ok(Response::redirect("/account/two-factor")),
    }
}

async fn record(
    app: &App,
    request: &Request,
    session: &ActiveSession,
    action: &'static str,
) -> Result<(), Failure> {
    let (username, ip) = (session.user.username.clone(), request.client_ip.to_string());
    app.db
        .run(move |conn| {
            audit::record(
                conn,
                &audit::Entry {
                    actor: &username,
                    action,
                    target: &username,
                    ip: &ip,
                },
            )
        })
        .await?;
    Ok(())
}

/// Replaces the recovery codes and shows the new ones, the only time they are visible.
async fn new_recovery_codes(
    app: &App,
    request: &Request,
    session: &ActiveSession,
) -> Result<Response, Failure> {
    let mut codes = Vec::with_capacity(RECOVERY_CODES);
    for _ in 0..RECOVERY_CODES {
        // 50 random bits, shown as two groups of five letters and digits.
        let symbols: String = base32(&random_bytes::<7>()?)
            .to_lowercase()
            .chars()
            .take(10)
            .collect();
        let (first, second) = symbols.split_at_checked(5).unwrap_or((&symbols, ""));
        codes.push(format!("{first}-{second}"));
    }
    let id = session.user.id;
    let hashes: Vec<[u8; 32]> = codes
        .iter()
        .map(|code| recovery_code_hash(app, id, code))
        .collect();
    app.db
        .run(move |conn| users::replace_recovery_codes(conn, id, &hashes))
        .await?;

    let lang = Lang::of(request);
    let text = lang.text();
    let mut content = Html::new();
    html!(
        content,
        "<h1>",
        { text.recovery_codes },
        "</h1><p>",
        { text.recovery_hint },
        "</p><ul class=\"codes\">"
    );
    for code in &codes {
        html!(content, "<li>", { code }, "</li>");
    }
    html!(
        content,
        "</ul><a class=\"button primary block\" href=\"/account\">",
        { text.done },
        "</a>"
    );
    Ok(Response::html(auth_page(
        app,
        request,
        lang,
        text.recovery_codes,
        &content,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_passwords_are_refused() {
        let text = Lang::En.text();
        let check = |password: &str| password_problem(text, "anna", password, password);
        assert_eq!(check("short"), Some(text.password_too_short));
        assert_eq!(check("Password1234"), Some(text.password_too_common));
        assert_eq!(check("my name is anna!"), Some(text.password_too_common));
        assert_eq!(check("aaaaaaaaaaaaaaa"), Some(text.password_too_common));
        assert_eq!(check("correct horse battery"), None);
        assert_eq!(
            password_problem(text, "anna", "correct horse battery", "correct horse"),
            Some(text.passwords_differ)
        );
    }
}
