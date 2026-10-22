//! Signing in: the first factor (a password or an outside provider), the code step and
//! recovery codes, or a passkey, which is both factors at once.
//!
//! The steps are types. [`FirstFactor`] exists only after a password or provider succeeded, and
//! [`SignedIn`] only after every factor the account has; both have private fields and are made
//! only in this module. A session can only be started from a `SignedIn`, so no handler can start
//! one early by mistake.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::csrf::{self, Csrf};
use super::i18n::Lang;
use super::layout::{auth_page, error_notice, icon, reveal_button};
use super::oidc::client_name_for;
use super::passkeys::{self, Refusal};
use super::{App, Failure, is_local_path, session};
use crate::crypto::password::{self, PasswordHash};
use crate::crypto::totp;
use crate::encoding::{base64url, decode_base64url};
use crate::form::encode;
use crate::html::{Html, html};
use crate::http::cookie::{self, SetCookie};
use crate::http::{Request, Response};
use crate::identifier::Identifier;
use crate::log::info;
use crate::secret::Secret;
use crate::store::audit::{self, Action};
use crate::store::users::{self, User, UserId};
use crate::time;

const PENDING_COOKIE: &str = "signin";
/// Time allowed between the password and the code.
const PENDING_LIFETIME: i64 = 5 * 60;
/// How long a sign-in waits for a free password hashing slot before giving up.
const HASHING_WAIT: Duration = Duration::from_secs(10);

/// Someone who passed the first factor and whose account also has a second one.
pub(crate) struct FirstFactor {
    user: UserId,
    issued_at: i64,
    /// Signed in with an outside provider rather than a password.
    federated: bool,
}

/// Someone who passed every factor their account has.
pub(crate) struct SignedIn {
    user: UserId,
    username: String,
    amr: &'static str,
}

impl SignedIn {
    pub(crate) fn user(&self) -> UserId {
        self.user
    }

    /// The `amr` values of this sign-in (RFC 8176): `pwd` or `fed`, then `otp` if a code was
    /// entered. A passkey gives `pop mfa`: possession of a key (`pop`, from OpenID Connect EAP),
    /// and a second factor, a PIN or biometrics, that the authenticator checked but doesn't name.
    pub(crate) fn amr(&self) -> &'static str {
        self.amr
    }

    /// The administrator who just created the first account with the setup token.
    pub(super) fn first_administrator(user: &User) -> Self {
        Self {
            user: user.id,
            username: user.username.clone(),
            amr: "pwd",
        }
    }
}

/// Checks a password on the blocking pool, at most a few at a time; each check holds tens of
/// megabytes for a moment. With no hash, an equal amount of work is done and the answer is no,
/// so the response time doesn't reveal whether the account exists.
pub(super) async fn check_password(
    app: &App,
    password: &str,
    hash: Option<PasswordHash>,
) -> Result<bool, Failure> {
    let _permit = tokio::time::timeout(HASHING_WAIT, app.hashing.acquire())
        .await
        .map_err(|_| Failure::Busy)?
        .map_err(|_| Failure::Busy)?;
    let password = Secret::new(password.to_owned());
    tokio::task::spawn_blocking(move || {
        if let Some(hash) = hash {
            password::verify(password.expose(), &hash)
        } else {
            password::verify_nonexistent(password.expose());
            false
        }
    })
    .await
    .map_err(|_| Failure::Busy)
}

pub(super) async fn hash_password(app: &App, password: &str) -> Result<PasswordHash, Failure> {
    let _permit = tokio::time::timeout(HASHING_WAIT, app.hashing.acquire())
        .await
        .map_err(|_| Failure::Busy)?
        .map_err(|_| Failure::Busy)?;
    let password = Secret::new(password.to_owned());
    tokio::task::spawn_blocking(move || password::hash(password.expose()))
        .await
        .map_err(|_| Failure::Busy)?
        .map_err(Failure::from)
}

/// Where to go after signing in: a local path from the form or the query, else the home page.
fn next(request: &Request) -> String {
    let from = |form: &crate::form::Form| form.single("next").ok().flatten().map(str::to_owned);
    from(&request.form)
        .or_else(|| from(&request.query))
        .filter(|path| is_local_path(path))
        .unwrap_or_else(|| "/".to_owned())
}

/// `GET /login`. With `force=1` the form is shown even to someone signed in, because the
/// application asked for a fresh sign-in or the user wants another account.
pub(super) async fn page(app: &App, request: &Request) -> Result<Response, Failure> {
    let next = next(request);
    let force = request.query.single("force").ok().flatten() == Some("1");
    if !force && session::current(app, request).await?.is_some() {
        return Ok(Response::redirect(next));
    }
    let hint = request
        .query
        .single("username")
        .ok()
        .flatten()
        .unwrap_or_default();
    login_page(app, request, hint, &next, None, None).await
}

/// The sign-in form. `unknown_passkey` is a passkey the browser offered that isn't stored here.
async fn login_page(
    app: &App,
    request: &Request,
    username: &str,
    next: &str,
    problem: Option<&str>,
    unknown_passkey: Option<&[u8]>,
) -> Result<Response, Failure> {
    let lang = Lang::of(request);
    let text = lang.text();
    let csrf = Csrf::for_page(app, request)?;
    let mut content = Html::new();
    html!(content, "<h1>", { text.sign_in_title }, "</h1>");
    if let Some(client) = client_name_for(app, next) {
        html!(content, "<p>", { text.sign_in_to }, " ", { client }, "</p>");
    }
    if let Some(problem) = problem {
        html!(content, { error_notice(problem) });
    }
    // Browsers that support it offer saved passkeys in the username field.
    let has_passkeys = passkeys::relying_party(app).is_some();
    let autocomplete = if has_passkeys {
        "username webauthn"
    } else {
        "username"
    };
    html!(
        content,
        "<form class=\"stack\" method=\"post\" action=\"/login\">",
        { csrf.field() },
        "<input type=\"hidden\" name=\"next\" value=\"",
        { next },
        "\"><div><label for=\"username\">",
        { text.username },
        "</label><input id=\"username\" name=\"username\" value=\"",
        { username },
        "\" autocomplete=\"",
        { autocomplete },
        "\" autocapitalize=\"none\" spellcheck=\"false\" required autofocus>",
        "</div><div><label for=\"password\">",
        { text.password },
        "</label><div class=\"password\"><input id=\"password\" name=\"password\" type=\"password\" ",
        "autocomplete=\"current-password\" required>",
        { reveal_button(lang) },
        "</div></div><button class=\"primary block\">",
        { text.sign_in },
        "</button></form>"
    );
    let providers = super::providers::enabled(app).await?;
    if has_passkeys || !providers.is_empty() {
        html!(content, "<div class=\"alternatives\">", {
            passkeys::sign_in_form(app, text, &csrf, next, unknown_passkey)?
        });
        for provider in &providers {
            html!(
                content,
                "<a class=\"button block\" href=\"/login/",
                { provider.slug },
                "?next=",
                { encode(next) },
                "\">"
            );
            if let Some(logo) = super::providers::logo(provider) {
                html!(content, { icon(logo) });
            }
            html!(
                content,
                { text.sign_in_with },
                " ",
                { provider.name },
                "</a>"
            );
        }
        html!(content, "</div>");
    }
    let page = auth_page(app, request, lang, text.sign_in_title, &content);
    Ok(csrf.apply(app, Response::html(page)))
}

/// `POST /login`
pub(super) async fn submit(app: &App, request: &Request) -> Result<Response, Failure> {
    let text = Lang::of(request).text();
    let next = next(request);
    let username = request
        .form
        .single("username")
        .ok()
        .flatten()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if !csrf::verify(app, request) {
        return login_page(
            app,
            request,
            &username,
            &next,
            Some(text.form_expired),
            None,
        )
        .await;
    }
    let password = request
        .form
        .single("password")
        .ok()
        .flatten()
        .unwrap_or_default();
    // Names that can't exist share one key, so junk names can't fill the limiter.
    let account_key = if Identifier::parse(&username).is_some() {
        username.as_str()
    } else {
        ""
    };
    if !app.limits.password_attempt(request.client_ip, account_key) {
        let problem = Some(text.too_many_attempts);
        return login_page(app, request, &username, &next, problem, None).await;
    }

    let lookup = username.clone();
    let user = app
        .db
        .run(move |conn| users::by_username(conn, &lookup))
        .await?;
    let hash = user
        .as_ref()
        .filter(|user| !user.disabled)
        .and_then(|user| user.password_hash.clone());
    let matched = check_password(app, password, hash).await?;
    let Some(user) = user.filter(|_| matched) else {
        info!("wrong password for {username:?} from {}", request.client_ip);
        let problem = Some(text.wrong_credentials);
        return login_page(app, request, &username, &next, problem, None).await;
    };
    app.limits
        .password_succeeded(request.client_ip, account_key);

    if user
        .password_hash
        .as_ref()
        .is_some_and(password::needs_rehash)
    {
        let new_hash = hash_password(app, password).await?;
        let id = user.id;
        app.db
            .run(move |conn| users::set_password(conn, id, &new_hash))
            .await?;
    }

    if user.totp_secret.is_none() {
        let signed_in = SignedIn {
            user: user.id,
            username: user.username,
            amr: "pwd",
        };
        return finish(app, request, signed_in, &next).await;
    }
    let checked = FirstFactor {
        user: user.id,
        issued_at: time::now(),
        federated: false,
    };
    set_pending(app, &checked, &next, Response::redirect("/login/code"))
}

/// `POST /login/passkey`: signs in with a passkey. The authenticator proves that the device is
/// there and checked the user's PIN or biometrics, so no code is asked for afterwards.
pub(super) async fn passkey_submit(app: &App, request: &Request) -> Result<Response, Failure> {
    let text = Lang::of(request).text();
    let next = next(request);
    let user_id = match passkeys::check_answer(app, request, None).await? {
        Ok(user) => user,
        Err(refusal) => {
            let unknown = match &refusal {
                Refusal::Unknown(id) => Some(id.as_slice()),
                _ => None,
            };
            let problem = Some(refusal.message(text));
            return login_page(app, request, "", &next, problem, unknown).await;
        }
    };
    let Some(user) = app
        .db
        .run(move |conn| users::by_id(conn, user_id))
        .await?
        .filter(|user| !user.disabled)
    else {
        return login_page(app, request, "", &next, Some(text.passkey_failed), None).await;
    };
    let signed_in = SignedIn {
        user: user.id,
        username: user.username,
        amr: "pop mfa",
    };
    finish(app, request, signed_in, &next).await
}

/// Continues a sign-in after an outside provider vouched for `user`: with the code step if the
/// account has two-factor sign-in, which a provider doesn't replace, or else straight in.
pub(super) async fn after_provider(
    app: &App,
    request: &Request,
    user: User,
    next: &str,
) -> Result<Response, Failure> {
    if user.totp_secret.is_none() {
        let signed_in = SignedIn {
            user: user.id,
            username: user.username,
            amr: "fed",
        };
        return finish(app, request, signed_in, next).await;
    }
    let checked = FirstFactor {
        user: user.id,
        issued_at: time::now(),
        federated: true,
    };
    set_pending(app, &checked, next, Response::redirect("/login/code"))
}

#[derive(Serialize, Deserialize)]
struct Pending {
    user: i64,
    issued_at: i64,
    federated: bool,
    next: String,
}

/// Carries the first step to the code step in a sealed cookie that lasts five minutes. Like every
/// cookie it is `Lax`, which matters here: after a provider, the browser arrives by a redirect
/// that began on another site.
fn set_pending(
    app: &App,
    checked: &FirstFactor,
    next: &str,
    response: Response,
) -> Result<Response, Failure> {
    let pending = Pending {
        user: checked.user.0,
        issued_at: checked.issued_at,
        federated: checked.federated,
        next: next.to_owned(),
    };
    let json =
        serde_json::to_vec(&pending).map_err(|_| Failure::Crypto(crate::crypto::CryptoError))?;
    let sealed = base64url(&app.keys.signin.seal(&json, PENDING_COOKIE.as_bytes())?);
    let secure = app.config.issuer.is_secure();
    let cookie = SetCookie {
        name: &cookie::name(PENDING_COOKIE, secure),
        value: &sealed,
        max_age: Some(PENDING_LIFETIME),
    };
    Ok(response.cookie(&cookie, secure))
}

fn pending(app: &App, request: &Request) -> Option<(FirstFactor, String)> {
    let name = cookie::name(PENDING_COOKIE, app.config.issuer.is_secure());
    let sealed = decode_base64url(request.cookie(&name)?)?;
    let json = app.keys.signin.open(&sealed, PENDING_COOKIE.as_bytes())?;
    let pending: Pending = serde_json::from_slice(json.expose()).ok()?;
    let age = time::now().saturating_sub(pending.issued_at);
    ((0..PENDING_LIFETIME).contains(&age) && is_local_path(&pending.next)).then(|| {
        let checked = FirstFactor {
            user: UserId(pending.user),
            issued_at: pending.issued_at,
            federated: pending.federated,
        };
        (checked, pending.next)
    })
}

fn clear_pending(app: &App, response: Response) -> Response {
    let secure = app.config.issuer.is_secure();
    let cookie = SetCookie {
        name: &cookie::name(PENDING_COOKIE, secure),
        value: "",
        max_age: Some(0),
    };
    response.cookie(&cookie, secure)
}

async fn finish(
    app: &App,
    request: &Request,
    signed_in: SignedIn,
    next: &str,
) -> Result<Response, Failure> {
    let entry_actor = signed_in.username.clone();
    let ip = request.client_ip.to_string();
    app.db
        .run(move |conn| {
            audit::record(
                conn,
                &audit::Entry {
                    actor: &entry_actor,
                    action: Action::SignIn,
                    target: "",
                    ip: &ip,
                },
            )
        })
        .await?;
    let response = clear_pending(app, Response::redirect(next));
    session::start(app, request, signed_in, response).await
}

/// Which second step a page is for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    Code,
    Recovery,
}

/// `GET /login/code` and `GET /login/recovery`
pub(super) fn second_step_page(
    app: &App,
    request: &Request,
    recovery: bool,
) -> Result<Response, Failure> {
    if pending(app, request).is_none() {
        return Ok(Response::redirect("/login"));
    }
    let step = if recovery { Step::Recovery } else { Step::Code };
    second_step_form(app, request, step, None)
}

fn second_step_form(
    app: &App,
    request: &Request,
    step: Step,
    problem: Option<&str>,
) -> Result<Response, Failure> {
    let lang = Lang::of(request);
    let text = lang.text();
    let csrf = Csrf::for_page(app, request)?;
    let (title, hint, action) = match step {
        Step::Code => (text.code_title, text.code_hint, "/login/code"),
        Step::Recovery => (text.recovery_title, text.recovery_hint, "/login/recovery"),
    };
    let mut content = Html::new();
    html!(content, "<h1>", { title }, "</h1><p>", { hint }, "</p>");
    if let Some(problem) = problem {
        html!(content, { error_notice(problem) });
    }
    html!(
        content,
        "<form class=\"stack\" method=\"post\" action=\"",
        { action },
        "\">",
        { csrf.field() }
    );
    match step {
        Step::Code => html!(
            content,
            "<div><label for=\"code\" class=\"visually-hidden\">",
            { text.code },
            "</label><input id=\"code\" name=\"code\" class=\"code-input\" inputmode=\"numeric\" ",
            "autocomplete=\"one-time-code\" maxlength=\"7\" required autofocus data-autosubmit></div>"
        ),
        Step::Recovery => html!(
            content,
            "<div><label for=\"code\" class=\"visually-hidden\">",
            { text.recovery_title },
            "</label><input id=\"code\" name=\"code\" class=\"code-input\" autocomplete=\"off\" ",
            "autocapitalize=\"none\" spellcheck=\"false\" maxlength=\"20\" required autofocus></div>"
        ),
    }
    html!(
        content,
        "<button class=\"primary block\">",
        { text.confirm },
        "</button></form>"
    );
    let (other, other_icon, other_label) = match step {
        Step::Code => ("/login/recovery", "life-buoy", text.use_recovery_code),
        Step::Recovery => ("/login/code", "shield-check", text.use_app_code),
    };
    html!(
        content,
        "<div class=\"alternatives\"><a href=\"",
        { other },
        "\">",
        { icon(other_icon) },
        { other_label },
        "</a></div>"
    );
    let page = auth_page(app, request, lang, title, &content);
    Ok(csrf.apply(app, Response::html(page)))
}

/// `POST /login/code` and `POST /login/recovery`
pub(super) async fn second_step_submit(
    app: &App,
    request: &Request,
    recovery: bool,
) -> Result<Response, Failure> {
    let text = Lang::of(request).text();
    let step = if recovery { Step::Recovery } else { Step::Code };
    let Some((checked, next)) = pending(app, request) else {
        return Ok(Response::redirect("/login"));
    };
    if !csrf::verify(app, request) {
        return second_step_form(app, request, step, Some(text.form_expired));
    }
    let key = checked.user.0.to_string();
    if !app.limits.code_attempt(&key) {
        return second_step_form(app, request, step, Some(text.too_many_attempts));
    }
    let input = request
        .form
        .single("code")
        .ok()
        .flatten()
        .unwrap_or_default()
        .to_owned();
    let user_id = checked.user;
    let Some(user) = app
        .db
        .run(move |conn| users::by_id(conn, user_id))
        .await?
        .filter(|user| !user.disabled)
    else {
        return Ok(clear_pending(app, Response::redirect("/login")));
    };

    let accepted = match step {
        Step::Code => verify_code(app, &user, &input).await?,
        Step::Recovery => {
            let hash = recovery_code_hash(app, user_id, &input);
            app.db
                .run(move |conn| users::use_recovery_code(conn, user_id, &hash))
                .await?
        }
    };
    if !accepted {
        info!(
            "wrong second factor for {:?} from {}",
            user.username, request.client_ip
        );
        return second_step_form(app, request, step, Some(text.wrong_code));
    }
    app.limits.code_succeeded(&key);
    let signed_in = SignedIn {
        user: user.id,
        username: user.username,
        amr: if checked.federated {
            "fed otp"
        } else {
            "pwd otp"
        },
    };
    finish(app, request, signed_in, &next).await
}

/// Checks a TOTP code and records its time step, so it can't be used again.
pub(super) async fn verify_code(app: &App, user: &User, input: &str) -> Result<bool, Failure> {
    let Some(secret) = user
        .totp_secret
        .as_ref()
        .and_then(|sealed| app.keys.secrets.open(sealed, &totp_context(user.id)))
    else {
        return Ok(false);
    };
    let now = u64::try_from(time::now()).unwrap_or(0);
    let last = user
        .totp_last_step
        .and_then(|step| u64::try_from(step).ok());
    let Some(step) = totp::verify(secret.expose(), user.totp_algorithm, input, now, last) else {
        return Ok(false);
    };
    let step = i64::try_from(step).unwrap_or(i64::MAX);
    let id = user.id;
    Ok(app
        .db
        .run(move |conn| users::accept_totp_step(conn, id, step))
        .await?)
}

/// Binds a sealed TOTP secret to its user, so it can't be copied to another account.
pub(super) fn totp_context(user: UserId) -> Vec<u8> {
    format!("totp {}", user.0).into_bytes()
}

/// Recovery codes are compared without case, spaces or dashes, so they can be typed loosely.
/// They are stored keyed with the master key: 50 random bits under a plain hash could be found
/// by trying every value against a copy of the database.
pub(super) fn recovery_code_hash(app: &App, user: UserId, input: &str) -> [u8; 32] {
    let normalized: String = input
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    app.keys
        .recovery
        .sign(format!("{} {normalized}", user.0).as_bytes())
}
