//! The table of sessions, on the account page and in administration.

use super::csrf::Csrf;
use super::i18n::Lang;
use crate::html::{Html, html};
use crate::store::sessions::{SessionId, SessionSummary};
use crate::time::format_utc;

/// Renders sessions with a button that ends each one by posting its id to `action`.
pub(crate) fn render(
    out: &mut Html,
    lang: Lang,
    csrf: &Csrf,
    sessions: &[SessionSummary],
    action: &str,
    current: Option<SessionId>,
    show_user: bool,
) {
    let text = lang.text();
    html!(*out, "<div class=\"table\"><table><thead><tr>");
    if show_user {
        html!(*out, "<th>", { text.username }, "</th>");
    }
    html!(
        *out,
        "<th>",
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
        html!(*out, "<tr>");
        if show_user {
            html!(*out, "<td>", { session.username }, "</td>");
        }
        html!(
            *out,
            "<td>",
            { describe_device(&session.user_agent) },
            "</td><td>",
            { session.ip },
            "</td><td>",
            { format_utc(session.auth_time) },
            "</td><td>",
            { format_utc(session.last_seen_at) },
            "</td><td class=\"num\">"
        );
        if current == Some(session.id) {
            html!(
                *out,
                "<span class=\"muted\">",
                { text.this_session },
                "</span>"
            );
        } else {
            html!(
                *out,
                "<form method=\"post\" action=\"",
                { action },
                "\">",
                { csrf.field() },
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

/// "Firefox, Windows" from a User-Agent header; enough to recognise one's own devices.
pub(crate) fn describe_device(user_agent: &str) -> String {
    let contains = |needle: &str| user_agent.contains(needle);
    let browser = if contains("Firefox/") {
        "Firefox"
    } else if contains("Edg/") {
        "Edge"
    } else if contains("OPR/") {
        "Opera"
    } else if contains("Chrome/") {
        "Chrome"
    } else if contains("Safari/") {
        "Safari"
    } else {
        ""
    };
    let system = if contains("Windows") {
        "Windows"
    } else if contains("iPhone") || contains("iPad") {
        "iOS"
    } else if contains("Mac OS X") {
        "macOS"
    } else if contains("Android") {
        "Android"
    } else if contains("Linux") {
        "Linux"
    } else {
        ""
    };
    match (browser, system) {
        ("", "") => user_agent.chars().take(40).collect(),
        (browser, "") | ("", browser) => browser.to_owned(),
        (browser, system) => format!("{browser}, {system}"),
    }
}

#[cfg(test)]
mod tests {
    use super::describe_device;

    #[test]
    fn names_common_browsers() {
        let firefox =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0";
        let safari = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 \
                      (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1";
        assert_eq!(describe_device(firefox), "Firefox, Windows");
        assert_eq!(describe_device(safari), "Safari, iOS");
        assert_eq!(describe_device("curl/8.0"), "curl/8.0");
    }
}
