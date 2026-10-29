//! Passkeys in the browser: the options that pages hand to the script, the challenges in them,
//! the page where users add and remove passkeys, and checking an answer for sign-in or
//! administration. The checks themselves are in [`crate::crypto::passkey`].
//!
//! A challenge is sealed rather than stored: it carries the time it was issued, and its context
//! names what it is for, so pages that are never used cost nothing. Each answer is accepted
//! once.

use serde_json::{Value, json};

use super::csrf::{self, Csrf};
use super::device::describe_device;
use super::i18n::{Lang, Text};
use super::layout::{auth_page, error_notice, icon, success_notice, tooltip};
use super::{App, Failure, is_name, record_audit, session};
use crate::crypto::passkey::{self, ALGORITHMS, Assertion, RelyingParty};
use crate::crypto::sha256;
use crate::encoding::{base64url, decode_base64url};
use crate::html::{Html, html};
use crate::http::{Request, Response};
use crate::log::info;
use crate::store::audit::Action;
use crate::store::passkeys::{self, NewPasskey, Passkey, PasskeyId};
use crate::store::sessions::ActiveSession;
use crate::store::users::{User, UserId};
use crate::time::{self, format_utc};

/// How long a challenge can be answered.
const CHALLENGE_LIFETIME: i64 = 5 * 60;
/// How long the browser waits for the user, in milliseconds.
const TIMEOUT_MS: i64 = CHALLENGE_LIFETIME * 1000;
/// Adding or removing a passkey needs a sign-in this recent, or a code entered for
/// administration since. A passkey signs in on its own, so whoever finds a session left open
/// must not be able to give themselves a way back in.
const RECENT_SIGN_IN: i64 = 10 * 60;
const MAX_PASSKEYS: i64 = 20;

/// What a challenge is for. Each is sealed with its own context, so an answer to one is useless
/// for another.
#[derive(Clone, Copy)]
enum Purpose {
    SignIn,
    /// Confirming that the user signed in is still there, for administration.
    Verify(UserId),
    Add(UserId),
}

impl Purpose {
    fn context(self) -> Vec<u8> {
        match self {
            Self::SignIn => b"passkey sign-in".to_vec(),
            Self::Verify(user) => format!("passkey verify {}", user.0).into_bytes(),
            Self::Add(user) => format!("passkey add {}", user.0).into_bytes(),
        }
    }
}

/// Where passkeys are tied to. `None` when the issuer is an IP address, which can't have them.
pub(super) fn relying_party(app: &App) -> Option<RelyingParty<'_>> {
    Some(RelyingParty {
        id: app.config.issuer.domain()?,
        origin: app.config.issuer.as_str(),
    })
}

/// A new challenge in base64url: the time, sealed. Only we can make one, and the random nonce of
/// the seal makes each one different.
fn challenge(app: &App, purpose: Purpose) -> Result<String, Failure> {
    let sealed = app
        .keys
        .forms
        .seal(&time::now().to_be_bytes(), &purpose.context())?;
    Ok(base64url(&sealed))
}

/// A challenge posted back for `purpose`, if it is ours and still fresh: its bytes as the
/// browser signed them, and the time it stops being fresh.
fn open_challenge(app: &App, purpose: Purpose, text: &str) -> Option<(Vec<u8>, i64)> {
    let sealed = decode_base64url(text)?;
    let issued_at = app.keys.forms.open(&sealed, &purpose.context())?;
    let issued_at = i64::from_be_bytes(issued_at.expose().as_slice().try_into().ok()?);
    let age = time::now().saturating_sub(issued_at);
    (0..CHALLENGE_LIFETIME)
        .contains(&age)
        .then(|| (sealed, issued_at.saturating_add(CHALLENGE_LIFETIME)))
}

/// The user handle that a user's passkeys carry. Authenticators store it and send it back, so it
/// is derived with a key rather than revealing the account's row.
fn user_handle(app: &App, user: UserId) -> [u8; 32] {
    app.keys.passkeys.sign(&user.0.to_be_bytes())
}

/// Passkeys as WebAuthn's `PublicKeyCredentialDescriptor`s.
fn descriptors(passkeys: &[Passkey]) -> Vec<Value> {
    passkeys
        .iter()
        .map(|passkey| {
            json!({
                "type": "public-key",
                "id": base64url(&passkey.credential_id),
                "transports": passkey.transports.split_whitespace().collect::<Vec<_>>(),
            })
        })
        .collect()
}

/// The options for `navigator.credentials.get()`, as JSON for the script. With no `allowed`
/// passkeys, the browser offers any it has for us.
fn request_options(rp: &RelyingParty<'_>, challenge: &str, allowed: &[Passkey]) -> String {
    json!({
        "challenge": challenge,
        "rpId": rp.id,
        "timeout": TIMEOUT_MS,
        "userVerification": "required",
        "allowCredentials": descriptors(allowed),
    })
    .to_string()
}

/// The options for `navigator.credentials.create()`. A passkey must be discoverable, so it can
/// sign in without a user name, and must verify the user. The user's other passkeys are listed,
/// so the same authenticator isn't added twice.
fn creation_options(
    app: &App,
    rp: &RelyingParty<'_>,
    user: &User,
    challenge: &str,
    existing: &[Passkey],
) -> String {
    json!({
        "rp": { "id": rp.id, "name": app.branding().name },
        "user": {
            "id": base64url(&user_handle(app, user.id)),
            "name": user.username,
            "displayName": user.display_name,
        },
        "challenge": challenge,
        "pubKeyCredParams": ALGORITHMS.map(|alg| json!({ "type": "public-key", "alg": alg })),
        "timeout": TIMEOUT_MS,
        "excludeCredentials": descriptors(existing),
        "authenticatorSelection": {
            "residentKey": "required",
            "requireResidentKey": true,
            "userVerification": "required",
        },
        "attestation": "none",
    })
    .to_string()
}

/// A button that asks the browser for a passkey on a phone. With the hint `hybrid` (WebAuthn
/// Level 3) the browser shows a QR code at once; the phone scans it and answers over Bluetooth,
/// which also proves it is next to this computer. Browsers that don't know the hint offer phones
/// among their other choices. A new passkey gets `name` instead of this computer's name.
fn phone_button(label: &str, name: Option<&str>) -> Html {
    let mut out = Html::new();
    html!(
        out,
        "<button type=\"button\" class=\"block\" data-hint=\"hybrid\""
    );
    if let Some(name) = name {
        html!(out, " data-name=\"", { name }, "\"");
    }
    html!(
        out,
        " hidden>",
        { icon("smartphone") },
        { label },
        "</button>"
    );
    out
}

/// The fields of a form that the script fills: the challenge, and the browser's answer to it.
fn answer_fields(challenge: &str) -> Html {
    let mut out = Html::new();
    html!(
        out,
        "<input type=\"hidden\" name=\"challenge\" value=\"",
        { challenge },
        "\"><input type=\"hidden\" name=\"credential\">"
    );
    out
}

/// The sign-in page's buttons for passkeys, hidden until the script finds the browser supports
/// them: one for a passkey on this device or a security key, and one that goes straight to the
/// QR code for a passkey on a phone. The script also offers saved passkeys in the username field.
/// `unknown` names a passkey that the browser offered but that isn't stored here, so the script
/// can tell the browser to stop offering it.
pub(super) fn sign_in_form(
    app: &App,
    text: &Text,
    csrf: &Csrf,
    next: &str,
    unknown: Option<&[u8]>,
) -> Result<Html, Failure> {
    let mut out = Html::new();
    let Some(rp) = relying_party(app) else {
        return Ok(out);
    };
    let challenge = challenge(app, Purpose::SignIn)?;
    html!(
        out,
        "<form method=\"post\" action=\"/login/passkey\" data-passkey=\"",
        { request_options(&rp, &challenge, &[]) },
        "\""
    );
    if let Some(id) = unknown {
        html!(out, " data-passkey-unknown=\"", { base64url(id) }, "\"");
    }
    html!(
        out,
        ">",
        { csrf.field() },
        "<input type=\"hidden\" name=\"next\" value=\"",
        { next },
        "\">",
        { answer_fields(&challenge) },
        "<button type=\"button\" class=\"block\" hidden>",
        { icon("fingerprint") },
        { text.sign_in_with_passkey },
        "</button>",
        { phone_button(text.sign_in_with_phone, None) },
        "</form>"
    );
    Ok(out)
}

/// A button that confirms who is signed in with one of their passkeys, posting to `action`.
/// Empty if they have none.
pub(super) async fn verify_form(
    app: &App,
    text: &Text,
    csrf: &Csrf,
    user: UserId,
    action: &str,
) -> Result<Html, Failure> {
    let mut out = Html::new();
    let Some(rp) = relying_party(app) else {
        return Ok(out);
    };
    let own = app
        .db
        .run(move |conn| passkeys::of_user(conn, user))
        .await?;
    if own.is_empty() {
        return Ok(out);
    }
    let challenge = challenge(app, Purpose::Verify(user))?;
    html!(
        out,
        "<form method=\"post\" action=\"",
        { action },
        "\" data-passkey=\"",
        { request_options(&rp, &challenge, &own) },
        "\">",
        { csrf.field() },
        { answer_fields(&challenge) },
        "<button type=\"button\" class=\"block\" hidden>",
        { icon("fingerprint") },
        { text.use_passkey },
        "</button></form>"
    );
    Ok(out)
}

/// Why an answer wasn't accepted.
pub(super) enum Refusal {
    /// The challenge is too old or not ours, or the form came from elsewhere.
    Expired,
    /// The browser offered a passkey that isn't stored here, perhaps one removed since.
    Unknown(Vec<u8>),
    Failed,
}

impl Refusal {
    pub(super) fn message(&self, text: &Text) -> &'static str {
        match self {
            Self::Expired => text.form_expired,
            Self::Unknown(_) => text.passkey_unknown,
            Self::Failed => text.passkey_failed,
        }
    }
}

/// Checks the answer posted with `request` and returns the user whose passkey gave it. For
/// sign-in it can be anyone's; to confirm `expected`, it must be theirs.
pub(super) async fn check_answer(
    app: &App,
    request: &Request,
    expected: Option<UserId>,
) -> Result<Result<UserId, Refusal>, Failure> {
    let field = |name| request.form.single(name).ok().flatten().unwrap_or_default();
    let purpose = expected.map_or(Purpose::SignIn, Purpose::Verify);
    let refuse = |reason: &dyn std::fmt::Display| {
        info!("passkey refused from {}: {reason}", request.client_ip);
        Ok(Err(Refusal::Failed))
    };
    let (Some(rp), true) = (relying_party(app), csrf::verify(app, request)) else {
        return Ok(Err(Refusal::Expired));
    };
    let Some((challenge, fresh_until)) = open_challenge(app, purpose, field("challenge")) else {
        return Ok(Err(Refusal::Expired));
    };
    let assertion = match Assertion::parse(field("credential")) {
        Ok(assertion) => assertion,
        Err(e) => return refuse(&e),
    };
    let id = assertion.credential_id.clone();
    let Some(passkey) = app
        .db
        .run(move |conn| passkeys::by_credential_id(conn, &id))
        .await?
    else {
        return Ok(Err(Refusal::Unknown(assertion.credential_id)));
    };
    if expected.is_some_and(|user| user != passkey.user) {
        return refuse(&"the passkey belongs to someone else");
    }
    if let Some(handle) = &assertion.user_handle
        && *handle != user_handle(app, passkey.user)
    {
        return refuse(&"the user handle doesn't match the passkey");
    }
    let count = match assertion.verify(&rp, &challenge, &passkey.public_key, passkey.sign_count) {
        Ok(count) => count,
        Err(e) => return refuse(&e),
    };
    let now = time::now();
    if !app
        .passkey_answers
        .first_use(sha256(&challenge), fresh_until, now)
    {
        return refuse(&"the challenge was answered before");
    }
    let id = passkey.id;
    if !app
        .db
        .run(move |conn| passkeys::record_use(conn, id, count, now))
        .await?
    {
        return refuse(&"another sign-in with the same counter came first");
    }
    Ok(Ok(passkey.user))
}

/// Whether the session's user signed in, or confirmed it for administration, recently enough to
/// change their passkeys.
fn is_recent(session: &ActiveSession) -> bool {
    time::now().saturating_sub(session.verified_at) <= RECENT_SIGN_IN
}

/// `GET /account/passkeys`
pub(super) async fn page(app: &App, request: &Request) -> Result<Response, Failure> {
    let Some(session) = session::current(app, request).await? else {
        return Ok(session::to_sign_in(request));
    };
    passkeys_page(app, request, &session, None).await
}

/// The user's passkeys and a form to add one. After a while without signing in, a button to
/// sign in again takes the place of the form and the buttons that remove passkeys.
async fn passkeys_page(
    app: &App,
    request: &Request,
    session: &ActiveSession,
    notice: Option<Html>,
) -> Result<Response, Failure> {
    let Some(rp) = relying_party(app) else {
        return Ok(Response::redirect("/account"));
    };
    let lang = Lang::of(request);
    let text = lang.text();
    let csrf = Csrf::for_page(app, request)?;
    let user = &session.user;
    let id = user.id;
    let list = app.db.run(move |conn| passkeys::of_user(conn, id)).await?;
    let recent = is_recent(session);
    let mut content = Html::new();
    html!(content, "<h1>", { text.passkeys }, "</h1>", { notice }, {
        passkey_list(text, &csrf, &list, recent)
    });
    let full = i64::try_from(list.len()).unwrap_or(i64::MAX) >= MAX_PASSKEYS;
    if !recent {
        // A provider that skips the code leaves the session without one; see after_provider.
        let tip = if session.verified_at == 0 {
            text.tip_sign_in_with_code
        } else {
            text.tip_sign_in_again
        };
        html!(
            content,
            "<div class=\"has-tip\"><a class=\"button primary block\" ",
            "href=\"/login?force=1&amp;next=/account/passkeys\" aria-describedby=\"tip-again\">",
            { text.sign_in_again },
            "</a>",
            { tooltip("tip-again", tip) },
            "</div>"
        );
    } else if full {
        html!(
            content,
            "<p class=\"field-note\">",
            { text.passkey_limit },
            "</p>"
        );
    } else {
        let challenge = challenge(app, Purpose::Add(id))?;
        let device = describe_device(request.header("user-agent").unwrap_or_default());
        html!(
            content,
            "<form class=\"stack\" method=\"post\" action=\"/account/passkeys\" data-passkey=\"",
            { creation_options(app, &rp, user, &challenge, &list) },
            "\">",
            { csrf.field() },
            "<input type=\"hidden\" name=\"action\" value=\"add\">",
            { answer_fields(&challenge) },
            "<div><label for=\"name\">",
            { text.name },
            "</label><input id=\"name\" name=\"name\" value=\"",
            { device },
            "\" maxlength=\"100\" required></div><p class=\"field-note\" data-passkey-unsupported>",
            { text.passkeys_unsupported },
            "</p><button type=\"button\" class=\"primary block\" hidden>",
            { icon("plus") },
            { text.add_passkey },
            "</button>",
            { phone_button(text.add_on_phone, Some(text.phone)) },
            "</form>"
        );
    }
    html!(
        content,
        "<div class=\"alternatives\"><a href=\"/account\">",
        { icon("arrow-left") },
        { text.account_title },
        "</a></div>"
    );
    let page = auth_page(app, request, lang, text.passkeys, &content);
    Ok(csrf.apply(app, Response::html(page)))
}

/// The passkeys, each with when it was added and last used, and a button that removes it if
/// that is `allowed`.
fn passkey_list(text: &Text, csrf: &Csrf, list: &[Passkey], allowed: bool) -> Html {
    let mut out = Html::new();
    if list.is_empty() {
        return out;
    }
    let date = |at| {
        format_utc(at)
            .split(' ')
            .next()
            .unwrap_or_default()
            .to_owned()
    };
    html!(out, "<ul class=\"rows\">");
    for passkey in list {
        html!(
            out,
            "<li>",
            { icon("fingerprint") },
            "<span>",
            { passkey.name },
            "<br><span class=\"field-note\">",
            { text.added },
            " ",
            { date(passkey.created_at) }
        );
        if let Some(used) = passkey.last_used_at {
            html!(out, " · ", { text.last_used }, " ", { date(used) });
        }
        html!(out, "</span></span>");
        if allowed {
            html!(
                out,
                "<form method=\"post\" action=\"/account/passkeys\">",
                { csrf.field() },
                "<input type=\"hidden\" name=\"action\" value=\"delete\">",
                "<button class=\"compact\" name=\"passkey\" value=\"",
                { passkey.id.0 },
                "\">",
                { text.delete },
                "</button></form>"
            );
        }
        html!(out, "</li>");
    }
    html!(out, "</ul>");
    out
}

/// `POST /account/passkeys`: adds a passkey the browser has just created, or removes one.
pub(super) async fn submit(app: &App, request: &Request) -> Result<Response, Failure> {
    let Some(session) = session::current(app, request).await? else {
        return Ok(session::to_sign_in(request));
    };
    let text = Lang::of(request).text();
    let field = |name| request.form.single(name).ok().flatten().unwrap_or_default();
    let problem =
        async |message| passkeys_page(app, request, &session, Some(error_notice(message))).await;
    let Some(rp) = relying_party(app) else {
        return Ok(Response::redirect("/account"));
    };
    if !csrf::verify(app, request) {
        return problem(text.form_expired).await;
    }
    if !is_recent(&session) {
        return Ok(Response::redirect("/account/passkeys"));
    }
    let user = &session.user;
    let (id, username) = (user.id, user.username.as_str());
    match field("action") {
        "add" => {
            let Some((challenge, fresh_until)) =
                open_challenge(app, Purpose::Add(id), field("challenge"))
            else {
                return problem(text.form_expired).await;
            };
            let created = match passkey::register(&rp, &challenge, field("credential")) {
                Ok(created) => created,
                Err(e) => {
                    info!("new passkey refused from {}: {e}", request.client_ip);
                    return problem(text.passkey_failed).await;
                }
            };
            if !app
                .passkey_answers
                .first_use(sha256(&challenge), fresh_until, time::now())
            {
                return problem(text.passkey_failed).await;
            }
            // The page fills in a name; one that is missing or too long gets the device's.
            let name = Some(field("name").trim())
                .filter(|name| is_name(name))
                .map_or_else(
                    || describe_device(request.header("user-agent").unwrap_or_default()),
                    str::to_owned,
                );
            let transports = created.transports.join(" ");
            let added = app
                .db
                .run(move |conn| {
                    let new = NewPasskey {
                        user: id,
                        credential_id: &created.credential_id,
                        public_key: &created.public_key,
                        sign_count: created.sign_count,
                        transports: &transports,
                        name: &name,
                    };
                    passkeys::add(conn, &new, MAX_PASSKEYS)
                })
                .await;
            match added {
                Ok(true) => {}
                Ok(false) => return problem(text.passkey_limit).await,
                Err(e) if e.is_constraint_violation() => {
                    return problem(text.passkey_failed).await;
                }
                Err(e) => return Err(e.into()),
            }
            record_audit(app, request, username, Action::AddPasskey, username).await?;
            passkeys_page(
                app,
                request,
                &session,
                Some(success_notice(text.passkey_added)),
            )
            .await
        }
        "delete" => {
            if let Some(passkey) = field("passkey").parse().ok().map(PasskeyId)
                && app
                    .db
                    .run(move |conn| passkeys::delete(conn, id, passkey))
                    .await?
            {
                record_audit(app, request, username, Action::RemovePasskey, username).await?;
            }
            Ok(Response::redirect("/account/passkeys"))
        }
        _ => Ok(Response::redirect("/account/passkeys")),
    }
}
