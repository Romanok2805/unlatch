//! Sessions of all users and the audit log.

use hyper::Method;

use super::{Admin, field, notice};
use crate::html::{Html, html};
use crate::http::{Request, Response};
use crate::store::audit;
use crate::store::sessions::{self, SessionId, SessionSummary};
use crate::time::{self, format_utc};
use crate::web::device::describe_device;
use crate::web::i18n::Lang;
use crate::web::layout::Section;
use crate::web::{App, Failure};

/// Entries shown in the log; older ones stay in the database until their retention ends.
const LOG_ENTRIES: i64 = 200;

/// `GET` and `POST /admin/sessions`
pub(super) async fn sessions(
    app: &App,
    request: &Request,
    admin: &Admin,
) -> Result<Response, Failure> {
    let text = admin.lang.text();
    if request.method == Method::POST {
        if let Ok(id) = field(request, "session").parse() {
            let id = SessionId(id);
            crate::web::session::end(app, crate::web::session::Ending::One(id)).await?;
            admin
                .record(app, request, audit::Action::EndSession, &id.0.to_string())
                .await?;
        }
        return Ok(Response::redirect("/admin/sessions?notice=ended"));
    }
    let now = time::now();
    let list = app
        .db
        .run(move |conn| sessions::list(conn, None, now))
        .await?;
    let mut content = Html::new();
    html!(
        content,
        "<div class=\"page-head\"><h1>",
        { text.section_sessions },
        "</h1></div>",
        { notice(request, admin.lang) }
    );
    session_table(&mut content, admin, &list);
    Ok(admin.page(app, Section::Sessions, text.section_sessions, &content))
}

/// Every session, with a button that ends it, except the administrator's own.
fn session_table(out: &mut Html, admin: &Admin, sessions: &[SessionSummary]) {
    let text = admin.lang.text();
    html!(
        *out,
        "<div class=\"table\"><table><thead><tr><th>",
        { text.username },
        "</th><th>",
        { text.device },
        "</th><th>",
        { text.address },
        "</th><th>",
        { text.signed_in_at },
        "</th><th>",
        { text.last_seen },
        "</th><th></th></tr></thead><tbody>"
    );
    for session in sessions {
        html!(
            *out,
            "<tr><td>",
            { session.username },
            "</td><td>",
            { describe_device(&session.user_agent) },
            "</td><td>",
            { session.ip },
            "</td><td>",
            { format_utc(session.auth_time) },
            "</td><td>",
            { format_utc(session.last_seen_at) },
            "</td><td class=\"num\">"
        );
        if session.id == admin.session.id {
            html!(
                *out,
                "<span class=\"muted\">",
                { text.this_session },
                "</span>"
            );
        } else {
            html!(
                *out,
                "<form method=\"post\" action=\"/admin/sessions\">",
                { admin.csrf.field() },
                "<button class=\"compact\" name=\"session\" value=\"",
                { session.id.0 },
                "\">",
                { text.end },
                "</button></form>"
            );
        }
        html!(*out, "</td></tr>");
    }
    html!(*out, "</tbody></table></div>");
}

/// `GET /admin/log`
pub(super) async fn log(app: &App, _request: &Request, admin: &Admin) -> Result<Response, Failure> {
    let text = admin.lang.text();
    let entries = app.db.run(|conn| audit::latest(conn, LOG_ENTRIES)).await?;
    let mut content = Html::new();
    html!(
        content,
        "<div class=\"page-head\"><h1>",
        { text.section_log },
        "</h1></div><div class=\"table\"><table><thead><tr><th>",
        { text.time },
        " (UTC)</th><th>",
        { text.who },
        "</th><th>",
        { text.what },
        "</th><th></th><th>",
        { text.address },
        "</th></tr></thead><tbody>"
    );
    for entry in &entries {
        html!(
            content,
            "<tr><td>",
            { format_utc(entry.at) },
            "</td><td>",
            { entry.actor },
            "</td><td>",
            { action_label(admin.lang, &entry.action) },
            "</td><td>",
            { entry.target },
            "</td><td>",
            { entry.ip },
            "</td></tr>"
        );
    }
    html!(content, "</tbody></table></div>");
    Ok(admin.page(app, Section::Log, text.section_log, &content))
}

/// An action in the reader's language; one no longer known is shown as it was recorded.
fn action_label(lang: Lang, recorded: &str) -> &str {
    audit::Action::parse(recorded).map_or(recorded, |action| lang.action(action))
}
