//! Sessions of all users and the audit log.

use hyper::Method;

use super::{Admin, field, notice};
use crate::html::{Html, html};
use crate::http::{Request, Response};
use crate::store::audit;
use crate::store::sessions::{self, SessionId};
use crate::time::{self, format_utc};
use crate::web::i18n::Lang;
use crate::web::layout::Section;
use crate::web::session_table;
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
                .record(app, request, "end session", &id.0.to_string())
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
    session_table::render(
        &mut content,
        admin.lang,
        &admin.csrf,
        &list,
        "/admin/sessions",
        Some(admin.session.id),
        true,
    );
    Ok(admin.page(app, Section::Sessions, text.section_sessions, &content))
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

/// Actions are recorded in English, so the log reads the same whatever language was in use; this
/// translates them for display.
fn action_label(lang: Lang, action: &str) -> &str {
    if lang == Lang::En {
        return action;
    }
    match action {
        "sign in" => "вход",
        "change password" => "смена пароля",
        "set password from link" => "пароль по ссылке",
        "turn on two-factor sign-in" => "включение двухфакторного входа",
        "turn off two-factor sign-in" => "выключение двухфакторного входа",
        "create administrator" => "создание администратора",
        "create application" => "создание приложения",
        "change application" => "изменение приложения",
        "delete application" => "удаление приложения",
        "issue client secret" => "новый секрет клиента",
        "invite user" => "приглашение пользователя",
        "change user" => "изменение пользователя",
        "delete user" => "удаление пользователя",
        "create password link" => "ссылка для пароля",
        "reset two-factor sign-in" => "сброс двухфакторного входа",
        "end sessions" => "завершение сеансов",
        "end session" => "завершение сеанса",
        "create group" => "создание группы",
        "rename group" => "переименование группы",
        "delete group" => "удаление группы",
        "change settings" => "изменение настроек",
        _ => action,
    }
}
