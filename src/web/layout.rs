//! The frame shared by every page.

use hyper::StatusCode;

use super::csrf::Csrf;
use super::i18n::Lang;
use super::{App, static_files};
use crate::form::encode;
use crate::html::{Html, html};
use crate::http::{Request, Response};

/// An icon from the sprite. It takes the colour of the text around it and is hidden from screen
/// readers, because every icon sits next to words that say the same.
pub(crate) fn icon(name: &str) -> Html {
    let mut out = Html::new();
    html!(
        out,
        "<svg class=\"icon\" aria-hidden=\"true\"><use href=\"",
        { static_files::url("icons.svg") },
        "#",
        { name },
        "\"/></svg>"
    );
    out
}

/// A short hint for a control, shown above it while the pointer rests on it or it has keyboard
/// focus, and on touch screens while it is touched. It goes next to the control, inside an element
/// with the class `has-tip`, and the control names `id` in `aria-describedby`. Inside the control
/// it would become part of the control's name.
pub(crate) fn tooltip(id: &str, text: &str) -> Html {
    let mut out = Html::new();
    html!(
        out,
        "<span class=\"tip\" role=\"tooltip\" id=\"",
        { id },
        "\">",
        { text },
        "</span>"
    );
    out
}

/// Shows sighted users the label of a button that has only an icon. Screen readers already get
/// the label from `aria-label`, so this copy is hidden from them.
fn icon_label(text: &str) -> Html {
    let mut out = Html::new();
    html!(
        out,
        "<span class=\"tip end\" aria-hidden=\"true\">",
        { text },
        "</span>"
    );
    out
}

/// A page with one narrow column: the instance name above the content and the language switch
/// below it. Sign-in, consent and error pages use it.
pub(crate) fn auth_page(
    app: &App,
    request: &Request,
    lang: Lang,
    title: &str,
    content: &Html,
) -> Html {
    let branding = app.branding();
    let mut page = Html::new();
    head(&mut page, lang, title, &branding.name, &branding.accent);
    html!(
        page,
        "<body class=\"auth\"><main><div class=\"brand\">",
        { branding.name },
        "</div>",
        { content },
        "</main><footer>"
    );
    language_switch(&mut page, lang, &request.target);
    html!(page, "</footer></body></html>");
    page
}

/// The sections of administration, in the order of the menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Section {
    Apps,
    Users,
    Groups,
    Sessions,
    Providers,
    Log,
    Settings,
}

impl Section {
    const ALL: [Self; 7] = [
        Self::Apps,
        Self::Users,
        Self::Groups,
        Self::Sessions,
        Self::Providers,
        Self::Log,
        Self::Settings,
    ];

    const fn path(self) -> &'static str {
        match self {
            Self::Apps => "/admin/apps",
            Self::Users => "/admin/users",
            Self::Groups => "/admin/groups",
            Self::Sessions => "/admin/sessions",
            Self::Providers => "/admin/providers",
            Self::Log => "/admin/log",
            Self::Settings => "/admin/settings",
        }
    }

    const fn icon(self) -> &'static str {
        match self {
            Self::Apps => "layout-grid",
            Self::Users => "user",
            Self::Groups => "users",
            Self::Sessions => "monitor-smartphone",
            Self::Providers => "globe",
            Self::Log => "scroll-text",
            Self::Settings => "sliders-horizontal",
        }
    }

    pub(crate) fn label(self, lang: Lang) -> &'static str {
        let text = lang.text();
        match self {
            Self::Apps => text.section_apps,
            Self::Users => text.section_users,
            Self::Groups => text.section_groups,
            Self::Sessions => text.section_sessions,
            Self::Providers => text.section_providers,
            Self::Log => text.section_log,
            Self::Settings => text.section_settings,
        }
    }
}

/// What the administration frame needs besides the content.
pub(crate) struct Frame<'a> {
    pub(crate) lang: Lang,
    pub(crate) section: Section,
    pub(crate) title: &'a str,
    pub(crate) username: &'a str,
    pub(crate) csrf: &'a Csrf,
}

/// An administration page: the sections on the left, the content on the right.
pub(crate) fn admin_page(app: &App, frame: &Frame<'_>, content: &Html) -> Html {
    let branding = app.branding();
    let text = frame.lang.text();
    let mut page = Html::new();
    head(
        &mut page,
        frame.lang,
        frame.title,
        &branding.name,
        &branding.accent,
    );
    html!(
        page,
        "<body><div class=\"app\"><aside class=\"sidebar\"><div class=\"brand\">",
        { branding.name },
        "</div><nav class=\"nav\">"
    );
    for section in Section::ALL {
        html!(page, "<a href=\"", { section.path() }, "\"");
        if section == frame.section {
            html!(page, " aria-current=\"page\"");
        }
        html!(
            page,
            ">",
            { icon(section.icon()) },
            { section.label(frame.lang) },
            "</a>"
        );
    }
    html!(
        page,
        "</nav><div class=\"account\"><a href=\"/account\"><span>",
        { frame.username },
        "</span></a><form method=\"post\" action=\"/logout\">",
        { frame.csrf.field() },
        "<button class=\"quiet has-tip\" aria-label=\"",
        { text.sign_out },
        "\">",
        { icon("log-out") },
        { icon_label(text.sign_out) },
        "</button></form></div></aside><main class=\"content\">",
        { content },
        "</main></div></body></html>"
    );
    page
}

/// A button that shows the password in the field next to it. Hidden until the script runs.
pub(crate) fn reveal_button(lang: Lang) -> Html {
    let mut out = Html::new();
    html!(
        out,
        "<button type=\"button\" class=\"reveal quiet has-tip\" aria-label=\"",
        { lang.text().show_password },
        "\" aria-pressed=\"false\" hidden>",
        { icon("eye") },
        { icon_label(lang.text().show_password) },
        "</button>"
    );
    out
}

/// A button that copies `value`. Hidden until the script runs, which also says "Copied" in its
/// label for a moment.
pub(crate) fn copy_button(lang: Lang, value: &str) -> Html {
    let text = lang.text();
    let mut out = Html::new();
    html!(
        out,
        "<button type=\"button\" class=\"quiet has-tip\" data-copy=\"",
        { value },
        "\" data-copied=\"",
        { text.copied },
        "\" aria-label=\"",
        { text.copy },
        "\" hidden>",
        { icon("copy") },
        { icon_label(text.copy) },
        "</button>"
    );
    out
}

fn head(page: &mut Html, lang: Lang, title: &str, name: &str, accent: &str) {
    html!(
        *page,
        "<!doctype html><html lang=\"",
        { lang.code() },
        "\"><head><meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>",
        { title },
        " · ",
        { name },
        "</title><link rel=\"stylesheet\" href=\"",
        { static_files::url("style.css") },
        "\"><link rel=\"stylesheet\" href=\"/theme.css?v=",
        { encode(accent) },
        "\"><script src=\"",
        { static_files::url("app.js") },
        "\" defer></script></head>"
    );
}

fn language_switch(page: &mut Html, lang: Lang, back: &str) {
    let (other, name) = lang.other();
    html!(
        *page,
        "<a href=\"/language?to=",
        { other.code() },
        "&amp;back=",
        { encode(back) },
        "\" lang=\"",
        { other.code() },
        "\">",
        { name },
        "</a>"
    );
}

pub(crate) fn error_notice(text: &str) -> Html {
    let mut out = Html::new();
    html!(
        out,
        "<div class=\"notice error\" role=\"alert\">",
        { icon("circle-alert") },
        "<span>",
        { text },
        "</span></div>"
    );
    out
}

pub(crate) fn success_notice(text: &str) -> Html {
    let mut out = Html::new();
    html!(
        out,
        "<div class=\"notice success\" role=\"status\">",
        { icon("circle-check") },
        "<span>",
        { text },
        "</span></div>"
    );
    out
}

pub(crate) fn error_page(app: &App, request: &Request, status: StatusCode) -> Response {
    let lang = Lang::of(request);
    let text = lang.text();
    let title = match status {
        StatusCode::NOT_FOUND => text.not_found,
        StatusCode::BAD_REQUEST => text.bad_request,
        _ => text.server_error,
    };
    let mut content = Html::new();
    html!(
        content,
        "<h1>",
        { title },
        "</h1><p><a href=\"/\">",
        { text.home },
        "</a></p>"
    );
    Response::html(auth_page(app, request, lang, title, &content)).status(status)
}
