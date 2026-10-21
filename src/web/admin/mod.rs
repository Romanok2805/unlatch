//! Administration: applications, users, groups, sessions, the audit log and settings.
//!
//! Only administrators with two-factor sign-in reach it, and only with a code entered recently:
//! within 12 hours to look, within 30 minutes to change anything. Everyone else gets a 404, so
//! the pages don't even confirm they exist.

mod apps;
mod groups;
mod lists;
mod providers;
mod settings;
mod users;

use hyper::{Method, StatusCode};

use super::csrf::{self, Csrf};
use super::i18n::Lang;
use super::layout::{Frame, Section, admin_page, auth_page, error_notice, success_notice, tooltip};
use super::signin::verify_code;
use super::{App, Failure, is_local_path, session};
use crate::form::encode;
use crate::html::{Html, html};
use crate::http::{Request, Response};
use crate::store::audit;
use crate::store::sessions::{self, ActiveSession};
use crate::time;

const VIEW_WINDOW: i64 = 12 * 60 * 60;
const CHANGE_WINDOW: i64 = 30 * 60;

/// An administrator allowed to see or change the requested page.
pub(crate) struct Admin {
    pub(crate) session: ActiveSession,
    pub(crate) lang: Lang,
    pub(crate) csrf: Csrf,
}

impl Admin {
    fn frame<'a>(&'a self, section: Section, title: &'a str) -> Frame<'a> {
        Frame {
            lang: self.lang,
            section,
            title,
            username: &self.session.user.username,
            csrf: &self.csrf,
        }
    }

    /// The page in the administration frame, with the CSRF cookie if the browser needs one.
    pub(crate) fn page(
        &self,
        app: &App,
        section: Section,
        title: &str,
        content: &Html,
    ) -> Response {
        let page = admin_page(app, &self.frame(section, title), content);
        self.csrf.apply(app, Response::html(page))
    }

    /// Records a change in the audit log.
    pub(crate) async fn record(
        &self,
        app: &App,
        request: &Request,
        action: &'static str,
        target: &str,
    ) -> Result<(), Failure> {
        let (actor, target, ip) = (
            self.session.user.username.clone(),
            target.to_owned(),
            request.client_ip.to_string(),
        );
        app.db
            .run(move |conn| {
                audit::record(
                    conn,
                    &audit::Entry {
                        actor: &actor,
                        action,
                        target: &target,
                        ip: &ip,
                    },
                )
            })
            .await?;
        Ok(())
    }
}

/// Lets an administrator through, or answers for them: sign-in, two-factor setup, a fresh
/// code, or a 404 for everyone else.
async fn guard(app: &App, request: &Request) -> Result<Result<Admin, Response>, Failure> {
    let Some(session) = session::current(app, request).await? else {
        return Ok(Err(session::to_sign_in(request)));
    };
    if !session.user.is_admin {
        return Ok(Err(super::layout::error_page(
            app,
            request,
            StatusCode::NOT_FOUND,
        )));
    }
    if session.user.totp_secret.is_none() {
        return Ok(Err(Response::redirect("/account/two-factor")));
    }
    let changing = request.method == Method::POST;
    let window = if changing { CHANGE_WINDOW } else { VIEW_WINDOW };
    if time::now().saturating_sub(session.verified_at) > window {
        let back = if changing {
            request.path.as_str()
        } else {
            request.target.as_str()
        };
        return Ok(Err(Response::redirect(format!(
            "/admin/verify?next={}",
            encode(back)
        ))));
    }
    if changing && !csrf::verify(app, request) {
        return Ok(Err(Response::redirect(format!(
            "{}?notice=expired",
            request.path
        ))));
    }
    Ok(Ok(Admin {
        session,
        lang: Lang::of(request),
        csrf: Csrf::for_page(app, request)?,
    }))
}

/// Routes `/admin/...`. `None` means not found.
pub(crate) async fn route(app: &App, request: &Request) -> Result<Option<Response>, Failure> {
    let Some(rest) = request.path.strip_prefix("/admin") else {
        return Ok(None);
    };
    if rest == "/verify" {
        return verify(app, request).await.map(Some);
    }
    let admin = match guard(app, request).await? {
        Ok(admin) => admin,
        Err(response) => return Ok(Some(response)),
    };
    let post = request.method == Method::POST;
    let mut parts = rest.trim_start_matches('/').splitn(2, '/');
    let (section, item) = (parts.next().unwrap_or_default(), parts.next());
    let response = match (section, item) {
        ("", None) => Response::redirect("/admin/apps"),
        ("apps", None) if !post => apps::list(app, request, &admin).await?,
        ("apps", Some("new")) => apps::create(app, request, &admin).await?,
        ("apps", Some(id)) => return apps::edit(app, request, &admin, id).await,
        ("users", None) if !post => users::list(app, request, &admin).await?,
        ("users", Some("new")) => users::create(app, request, &admin).await?,
        ("users", Some(id)) => return users::edit(app, request, &admin, id).await,
        ("groups", None) => groups::list(app, request, &admin).await?,
        ("groups", Some(id)) => return groups::edit(app, request, &admin, id).await,
        ("sessions", None) => lists::sessions(app, request, &admin).await?,
        ("log", None) if !post => lists::log(app, request, &admin).await?,
        ("providers", None) if !post => providers::list(app, request, &admin).await?,
        ("providers", Some(id)) => return providers::edit(app, request, &admin, id).await,
        ("settings", None) => settings::page(app, request, &admin).await?,
        _ => return Ok(None),
    };
    Ok(Some(response))
}

/// `/admin/verify`: asks for a code before administration, again after a while.
async fn verify(app: &App, request: &Request) -> Result<Response, Failure> {
    let Some(session) = session::current(app, request).await? else {
        return Ok(session::to_sign_in(request));
    };
    if !session.user.is_admin {
        return Ok(super::layout::error_page(
            app,
            request,
            StatusCode::NOT_FOUND,
        ));
    }
    let lang = Lang::of(request);
    let text = lang.text();
    let next = request
        .query
        .single("next")
        .ok()
        .flatten()
        .filter(|path| is_local_path(path) && path.starts_with("/admin"))
        .unwrap_or("/admin")
        .to_owned();
    let mut problem = None;
    if request.method == Method::POST {
        let key = session.user.id.0.to_string();
        let code = request
            .form
            .single("code")
            .ok()
            .flatten()
            .unwrap_or_default();
        let limits = &app.limits;
        if !csrf::verify(app, request) {
            problem = Some(text.form_expired);
        } else if !limits.code_attempt(&key) {
            problem = Some(text.too_many_attempts);
        } else if verify_code(app, &session.user, code).await? {
            let (id, now) = (session.id, time::now());
            app.db
                .run(move |conn| sessions::mark_verified(conn, id, now))
                .await?;
            limits.code_succeeded(&key);
            return Ok(Response::redirect(next));
        } else {
            problem = Some(text.wrong_code);
        }
    }
    let csrf = Csrf::for_page(app, request)?;
    let mut content = Html::new();
    html!(
        content,
        "<h1>",
        { text.code_title },
        "</h1><p>",
        { text.code_hint },
        "</p>"
    );
    if let Some(problem) = problem {
        html!(content, { error_notice(problem) });
    }
    html!(
        content,
        "<form class=\"stack\" method=\"post\" action=\"/admin/verify?next=",
        { encode(&next) },
        "\">",
        { csrf.field() },
        "<div><label for=\"code\" class=\"visually-hidden\">",
        { text.code },
        "</label><input id=\"code\" name=\"code\" class=\"code-input\" inputmode=\"numeric\" ",
        "autocomplete=\"one-time-code\" maxlength=\"7\" required autofocus data-autosubmit></div>",
        "<button class=\"primary block\">",
        { text.confirm },
        "</button></form>"
    );
    let page = auth_page(app, request, lang, text.code_title, &content);
    Ok(csrf.apply(app, Response::html(page)))
}

/// The notice named in the `notice` query parameter, set by the redirect after a change.
fn notice(request: &Request, lang: Lang) -> Option<Html> {
    let text = lang.text();
    match request.query.single("notice").ok().flatten()? {
        "saved" => Some(success_notice(text.saved)),
        "deleted" => Some(success_notice(text.deleted)),
        "ended" => Some(success_notice(text.session_ended)),
        "expired" => Some(error_notice(text.form_expired)),
        _ => None,
    }
}

/// A row id from a path segment.
fn parse_id(segment: &str) -> Option<i64> {
    segment.parse().ok().filter(|id: &i64| *id > 0)
}

/// A labelled text input.
fn text_input(out: &mut Html, label: &str, name: &str, value: &str, note: Option<&str>) {
    html!(
        *out,
        "<div><label for=\"",
        { name },
        "\">",
        { label },
        "</label><input id=\"",
        { name },
        "\" name=\"",
        { name },
        "\" value=\"",
        { value },
        "\" spellcheck=\"false\">"
    );
    if let Some(note) = note {
        html!(*out, "<p class=\"field-note\">", { note }, "</p>");
    }
    html!(*out, "</div>");
}

/// A labelled text area for one value per line.
fn lines_input(out: &mut Html, label: &str, name: &str, lines: &[String], note: &str) {
    html!(
        *out,
        "<div><label for=\"",
        { name },
        "\">",
        { label },
        "</label><textarea id=\"",
        { name },
        "\" name=\"",
        { name },
        "\" class=\"mono\" spellcheck=\"false\">",
        { lines.join("\n") },
        "</textarea><p class=\"field-note\">",
        { note },
        "</p></div>"
    );
}

/// A checkbox with its label, and with `tip`, a hint about what the setting does.
fn checkbox(
    out: &mut Html,
    label: &str,
    name: &str,
    value: &str,
    checked: bool,
    tip: Option<&str>,
) {
    let id = format!("tip-{name}");
    if tip.is_some() {
        html!(*out, "<div class=\"has-tip\">");
    }
    html!(
        *out,
        "<label class=\"check\"><input type=\"checkbox\" name=\"",
        { name },
        "\" value=\"",
        { value },
        "\""
    );
    if tip.is_some() {
        html!(*out, " aria-describedby=\"", { id }, "\"");
    }
    if checked {
        html!(*out, " checked");
    }
    html!(*out, ">", { label }, "</label>");
    if let Some(tip) = tip {
        html!(*out, { tooltip(&id, tip) }, "</div>");
    }
}

/// The non-empty lines of a text area, trimmed.
fn lines(request: &Request, name: &str) -> Vec<String> {
    request
        .form
        .single(name)
        .ok()
        .flatten()
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

fn field<'a>(request: &'a Request, name: &str) -> &'a str {
    request
        .form
        .single(name)
        .ok()
        .flatten()
        .unwrap_or_default()
        .trim()
}

fn checked(request: &Request, name: &str) -> bool {
    request.form.single(name).ok().flatten().is_some()
}

/// A delete button behind a disclosure, so one stray click can't delete anything.
fn danger_zone(out: &mut Html, admin: &Admin, label: &str, action: &str) {
    html!(
        *out,
        "<details class=\"danger-zone\"><summary>",
        { super::layout::icon("trash") },
        { label },
        "</summary><form method=\"post\" action=\"",
        { action },
        "\">",
        { admin.csrf.field() },
        "<button class=\"danger\" name=\"action\" value=\"delete\">",
        { admin.lang.text().confirm_delete },
        "</button></form></details>"
    );
}
