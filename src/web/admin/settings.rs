//! Instance settings: the name people see and the accent colour.

use hyper::Method;

use super::{Admin, field, notice, text_input};
use crate::html::{Html, html};
use crate::http::{Request, Response};
use crate::store::audit::Action;
use crate::store::settings;
use crate::web::layout::{Section, copy_button, error_notice};
use crate::web::{App, Branding, Failure, is_colour, is_name};

/// `GET` and `POST /admin/settings`
pub(super) async fn page(app: &App, request: &Request, admin: &Admin) -> Result<Response, Failure> {
    let text = admin.lang.text();
    let mut problem = None;
    if request.method == Method::POST {
        let name = field(request, "name").to_owned();
        let accent = field(request, "accent").to_ascii_lowercase();
        if !is_name(&name) {
            problem = Some(text.name_required);
        } else if !is_colour(&accent) {
            problem = Some(text.colour_invalid);
        } else {
            let branding = Branding { name, accent };
            let saved = branding.clone();
            app.db
                .run(move |conn| {
                    settings::set(conn, "name", &saved.name)?;
                    settings::set(conn, "accent", &saved.accent)
                })
                .await?;
            app.set_branding(branding);
            admin
                .record(app, request, Action::ChangeSettings, "")
                .await?;
            return Ok(Response::redirect("/admin/settings?notice=saved"));
        }
    }
    let branding = app.branding();
    let discovery = app.config.issuer.url("/.well-known/openid-configuration");
    let mut content = Html::new();
    html!(
        content,
        "<div class=\"page-head\"><h1>",
        { text.section_settings },
        "</h1></div>",
        { notice(request, admin.lang) }
    );
    if let Some(problem) = problem {
        html!(content, { error_notice(problem) });
    }
    html!(
        content,
        "<form method=\"post\" action=\"/admin/settings\"><section class=\"section\"><h2>",
        { text.appearance },
        "</h2><div class=\"stack\">",
        { admin.csrf.field() }
    );
    text_input(
        &mut content,
        text.instance_name,
        "name",
        &branding.name,
        None,
    );
    html!(
        content,
        "<div><label for=\"accent\">",
        { text.accent },
        "</label><input id=\"accent\" name=\"accent\" type=\"color\" value=\"",
        { branding.accent },
        "\"></div><button class=\"primary\">",
        { text.save },
        "</button></div></section></form><section class=\"section\"><h2>OpenID Connect</h2><div class=\"stack\">",
        "<div><label>",
        { text.issuer },
        "</label><div class=\"secret\"><span>",
        { app.config.issuer.as_str() },
        "</span>",
        { copy_button(admin.lang, app.config.issuer.as_str()) },
        "</div></div><div><label>Discovery</label><div class=\"secret\"><span>",
        { discovery },
        "</span>",
        { copy_button(admin.lang, &discovery) },
        "</div></div></div></section>"
    );
    Ok(admin.page(app, Section::Settings, text.section_settings, &content))
}
