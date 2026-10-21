//! The frame shared by every page.

use hyper::StatusCode;

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
        "\"></head>"
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
