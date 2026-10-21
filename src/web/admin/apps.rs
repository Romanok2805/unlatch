//! Applications: listing, creating, editing and deleting them.

use hyper::Method;

use super::{
    Admin, checkbox, checked, danger_zone, field, lines, lines_input, notice, parse_id, text_input,
};
use crate::crypto::{Algorithm, random_token, sha256};
use crate::html::{Html, html};
use crate::http::{Request, Response};
use crate::store::apps::{self, AppChanges, AppId, AppRecord, Kind};
use crate::store::groups::{self, Group, GroupId};
use crate::store::users::Username;
use crate::uri::{InvalidRedirectUri, RedirectUri};
use crate::web::i18n::Text;
use crate::web::layout::{Section, copy_button, error_notice, icon};
use crate::web::{App, Failure};

const MAX_NAME_CHARS: usize = 100;

/// `GET /admin/apps`
pub(super) async fn list(app: &App, request: &Request, admin: &Admin) -> Result<Response, Failure> {
    let text = admin.lang.text();
    let apps = app.db.run(|conn| apps::list(conn)).await?;
    let mut content = Html::new();
    html!(
        content,
        "<div class=\"page-head\"><h1>",
        { text.section_apps },
        "</h1><a class=\"button primary compact\" href=\"/admin/apps/new\">",
        { icon("plus") },
        { text.add },
        "</a></div>",
        { notice(request, admin.lang) },
        "<div class=\"table\"><table><thead><tr><th>",
        { text.name },
        "</th><th>",
        { text.kind },
        "</th><th>",
        { text.access },
        "</th><th class=\"num\">",
        { text.section_sessions },
        "</th></tr></thead><tbody>"
    );
    for listed in &apps {
        let access = if !listed.enabled {
            text.disabled
        } else if listed.all_users {
            text.everyone
        } else if listed.groups.is_empty() {
            text.nobody
        } else {
            &listed.groups
        };
        let (glyph, kind) = match listed.kind {
            Kind::Oidc => ("key-round", "OpenID Connect"),
            Kind::Proxy => ("arrow-right-left", "Forward auth"),
        };
        html!(
            content,
            "<tr><td><a href=\"/admin/apps/",
            { listed.id.0 },
            "\">",
            { listed.name },
            "</a></td><td><span class=\"with-icon\">",
            { icon(glyph) },
            { kind },
            "</span></td><td"
        );
        if !listed.enabled {
            html!(content, " class=\"off\"");
        }
        html!(
            content,
            ">",
            { access },
            "</td><td class=\"num\">",
            { listed.sessions },
            "</td></tr>"
        );
    }
    html!(content, "</tbody></table></div>");
    Ok(admin.page(app, Section::Apps, text.section_apps, &content))
}

/// `GET` and `POST /admin/apps/new`
pub(super) async fn create(
    app: &App,
    request: &Request,
    admin: &Admin,
) -> Result<Response, Failure> {
    let text = admin.lang.text();
    let kind = request.query.single("kind").ok().flatten();
    let proxy = kind == Some("proxy");
    if request.method != Method::POST {
        return Ok(create_form(app, request, admin, proxy, None));
    }
    let name = field(request, "name").to_owned();
    if name.is_empty() || name.chars().count() > MAX_NAME_CHARS {
        return Ok(create_form(
            app,
            request,
            admin,
            proxy,
            Some(text.name_required),
        ));
    }
    if proxy {
        let Some(host) = parse_host(field(request, "host")) else {
            return Ok(create_form(
                app,
                request,
                admin,
                proxy,
                Some(text.host_invalid),
            ));
        };
        let created = app
            .db
            .run(move |conn| apps::create_proxy(conn, &name, &host))
            .await;
        return match created {
            Ok(id) => {
                admin
                    .record(app, request, "create application", field(request, "name"))
                    .await?;
                Ok(Response::redirect(format!("/admin/apps/{}", id.0)))
            }
            Err(e) if e.is_constraint_violation() => Ok(create_form(
                app,
                request,
                admin,
                proxy,
                Some(text.host_taken),
            )),
            Err(e) => Err(e.into()),
        };
    }

    let Some(client_id) = Username::parse(field(request, "client_id")) else {
        return Ok(create_form(
            app,
            request,
            admin,
            proxy,
            Some(text.client_id_invalid),
        ));
    };
    let secret = if checked(request, "public") {
        None
    } else {
        Some(random_token()?)
    };
    let hash = secret
        .as_ref()
        .map(|secret| sha256(secret.as_bytes()).to_vec());
    let id_text = client_id.as_str().to_owned();
    let created = app
        .db
        .run(move |conn| apps::create_oidc(conn, &name, &id_text, hash.as_deref()))
        .await;
    let id = match created {
        Ok(id) => id,
        Err(e) if e.is_constraint_violation() => {
            return Ok(create_form(
                app,
                request,
                admin,
                proxy,
                Some(text.client_id_taken),
            ));
        }
        Err(e) => return Err(e.into()),
    };
    admin
        .record(app, request, "create application", field(request, "name"))
        .await?;
    Ok(credentials_page(
        app,
        admin,
        id,
        client_id.as_str(),
        secret.as_deref(),
    ))
}

fn create_form(
    app: &App,
    request: &Request,
    admin: &Admin,
    proxy: bool,
    problem: Option<&str>,
) -> Response {
    let text = admin.lang.text();
    let mut content = Html::new();
    html!(
        content,
        "<a class=\"back\" href=\"/admin/apps\">",
        { icon("arrow-left") },
        { text.section_apps },
        "</a><div class=\"page-head\"><h1>",
        { text.new_app },
        "</h1></div>"
    );
    if let Some(problem) = problem {
        html!(content, { error_notice(problem) });
    }
    // The two kinds take different fields, so each has its own form.
    if proxy {
        html!(
            content,
            "<p><a href=\"/admin/apps/new\">OpenID Connect</a> · <strong>Forward auth</strong></p>",
            "<form method=\"post\" action=\"/admin/apps/new?kind=proxy\">"
        );
    } else {
        html!(
            content,
            "<p><strong>OpenID Connect</strong> · <a href=\"/admin/apps/new?kind=proxy\">Forward auth</a></p>",
            "<form method=\"post\" action=\"/admin/apps/new\">"
        );
    }
    html!(
        content,
        "<section class=\"section\"><h2>",
        { text.general },
        "</h2><div class=\"stack\">",
        { admin.csrf.field() }
    );
    text_input(
        &mut content,
        text.name,
        "name",
        field(request, "name"),
        None,
    );
    if proxy {
        text_input(
            &mut content,
            text.host,
            "host",
            field(request, "host"),
            Some(text.host_note),
        );
    } else {
        text_input(
            &mut content,
            "Client ID",
            "client_id",
            field(request, "client_id"),
            Some(text.username_note),
        );
        checkbox(
            &mut content,
            text.public_client,
            "public",
            "1",
            checked(request, "public"),
        );
    }
    html!(
        content,
        "</div></section><section class=\"section\"><span></span><div class=\"stack\"><button class=\"primary\">",
        { text.create },
        "</button></div></section></form>"
    );
    admin.page(app, Section::Apps, text.new_app, &content)
}

/// Shown once after creating a client or issuing a new secret; the secret isn't stored.
fn credentials_page(
    app: &App,
    admin: &Admin,
    id: AppId,
    client_id: &str,
    secret: Option<&str>,
) -> Response {
    let text = admin.lang.text();
    let mut content = Html::new();
    html!(
        content,
        "<div class=\"page-head\"><h1>",
        { text.credentials },
        "</h1></div><div class=\"stack narrow\">"
    );
    secret_row(&mut content, admin, "Client ID", client_id);
    if let Some(secret) = secret {
        secret_row(&mut content, admin, text.client_secret, secret);
        html!(
            content,
            "<p class=\"field-note\">",
            { text.secret_shown_once },
            "</p>"
        );
    }
    html!(
        content,
        "<a class=\"button primary\" href=\"/admin/apps/",
        { id.0 },
        "\">",
        { text.continue_setup },
        "</a></div>"
    );
    admin.page(app, Section::Apps, text.credentials, &content)
}

fn secret_row(out: &mut Html, admin: &Admin, label: &str, value: &str) {
    html!(
        *out,
        "<div><label>",
        { label },
        "</label><div class=\"secret\"><span>",
        { value },
        "</span>",
        { copy_button(admin.lang, value) },
        "</div></div>"
    );
}

/// What the edit form shows: the stored settings, or what was just submitted if it had a
/// problem, so nothing typed is lost.
struct Draft {
    name: String,
    enabled: bool,
    all_users: bool,
    skip_consent: bool,
    id_token_alg: String,
    host: String,
    redirect_uris: Vec<String>,
    post_logout_uris: Vec<String>,
    resources: Vec<String>,
    groups: Vec<GroupId>,
}

impl Draft {
    fn stored(record: &AppRecord, groups: Vec<GroupId>) -> Self {
        let strings =
            |uris: &[RedirectUri]| uris.iter().map(|uri| uri.as_str().to_owned()).collect();
        Self {
            name: record.name.clone(),
            enabled: record.enabled,
            all_users: record.all_users,
            skip_consent: record.skip_consent,
            id_token_alg: record.id_token_alg.name().to_owned(),
            host: record.host.clone().unwrap_or_default(),
            redirect_uris: strings(&record.redirect_uris),
            post_logout_uris: strings(&record.post_logout_uris),
            resources: record.resources.clone(),
            groups,
        }
    }

    fn submitted(request: &Request) -> Self {
        Self {
            name: field(request, "name").to_owned(),
            enabled: checked(request, "enabled"),
            all_users: checked(request, "all_users"),
            skip_consent: checked(request, "skip_consent"),
            id_token_alg: field(request, "id_token_alg").to_owned(),
            host: field(request, "host").to_owned(),
            redirect_uris: lines(request, "redirect_uris"),
            post_logout_uris: lines(request, "post_logout_uris"),
            resources: lines(request, "resources"),
            groups: request
                .form
                .all("group")
                .filter_map(|value| value.parse().ok().map(GroupId))
                .collect(),
        }
    }

    /// The draft as changes to save, or a message about its first problem.
    fn check(&self, kind: Kind, text: &Text) -> Result<AppChanges, String> {
        if self.name.is_empty() || self.name.chars().count() > MAX_NAME_CHARS {
            return Err(text.name_required.to_owned());
        }
        let host = match kind {
            Kind::Proxy => {
                Some(parse_host(&self.host).ok_or_else(|| text.host_invalid.to_owned())?)
            }
            Kind::Oidc => None,
        };
        let checked_uris = |uris: &[String]| -> Result<Vec<String>, String> {
            uris.iter()
                .map(|line| match RedirectUri::parse(line) {
                    Ok(uri) => Ok(uri.as_str().to_owned()),
                    Err(problem) => Err(format!("{line}: {}", uri_problem(text, problem))),
                })
                .collect()
        };
        Ok(AppChanges {
            name: self.name.clone(),
            enabled: self.enabled,
            all_users: self.all_users,
            skip_consent: self.skip_consent,
            id_token_alg: Algorithm::from_name(&self.id_token_alg).unwrap_or(Algorithm::Rs256),
            host,
            redirect_uris: checked_uris(&self.redirect_uris)?,
            post_logout_uris: checked_uris(&self.post_logout_uris)?,
            resources: checked_uris(&self.resources)?,
            groups: self.groups.clone(),
        })
    }
}

fn uri_problem(text: &Text, problem: InvalidRedirectUri) -> &'static str {
    match problem {
        InvalidRedirectUri::TooLong => text.uri_too_long,
        InvalidRedirectUri::Whitespace => text.uri_whitespace,
        InvalidRedirectUri::Fragment => text.uri_fragment,
        InvalidRedirectUri::NoHost => text.uri_no_host,
        InvalidRedirectUri::PlainHttp => text.uri_plain_http,
        InvalidRedirectUri::Scheme => text.uri_scheme,
        InvalidRedirectUri::UserInfo => text.uri_user_info,
        InvalidRedirectUri::Port => text.uri_port,
        InvalidRedirectUri::Host => text.uri_host,
    }
}

/// `GET` and `POST /admin/apps/<id>`
pub(super) async fn edit(
    app: &App,
    request: &Request,
    admin: &Admin,
    id: &str,
) -> Result<Option<Response>, Failure> {
    let Some(id) = parse_id(id).map(AppId) else {
        return Ok(None);
    };
    let found = app
        .db
        .run(move |conn| {
            let Some(record) = apps::by_id(conn, id)? else {
                return Ok(None);
            };
            Ok(Some((record, apps::groups(conn, id)?, groups::list(conn)?)))
        })
        .await?;
    let Some((record, app_groups, all_groups)) = found else {
        return Ok(None);
    };
    let text = admin.lang.text();
    let view = |draft: &Draft, problem: Option<&str>| {
        Some(edit_form(
            app,
            request,
            admin,
            &record,
            draft,
            &all_groups,
            problem,
        ))
    };
    if request.method != Method::POST {
        return Ok(view(&Draft::stored(&record, app_groups), None));
    }
    match field(request, "action") {
        "delete" => {
            app.db.run(move |conn| apps::delete(conn, id)).await?;
            admin
                .record(app, request, "delete application", &record.name)
                .await?;
            Ok(Some(Response::redirect("/admin/apps?notice=deleted")))
        }
        "secret" if record.client_secret_hash.is_some() => {
            let secret = random_token()?;
            let hash = sha256(secret.as_bytes());
            app.db
                .run(move |conn| apps::set_secret(conn, id, &hash))
                .await?;
            admin
                .record(app, request, "issue client secret", &record.name)
                .await?;
            let client_id = record.client_id.clone().unwrap_or_default();
            Ok(Some(credentials_page(
                app,
                admin,
                id,
                &client_id,
                Some(&secret),
            )))
        }
        _ => {
            let draft = Draft::submitted(request);
            let changes = match draft.check(record.kind, text) {
                Ok(changes) => changes,
                Err(problem) => return Ok(view(&draft, Some(&problem))),
            };
            match app
                .db
                .run(move |conn| apps::update(conn, id, &changes))
                .await
            {
                Ok(()) => {}
                Err(e) if e.is_constraint_violation() => {
                    return Ok(view(&draft, Some(text.host_taken)));
                }
                Err(e) => return Err(e.into()),
            }
            admin
                .record(app, request, "change application", &draft.name)
                .await?;
            Ok(Some(Response::redirect(format!(
                "/admin/apps/{}?notice=saved",
                id.0
            ))))
        }
    }
}

fn edit_form(
    app: &App,
    request: &Request,
    admin: &Admin,
    record: &AppRecord,
    draft: &Draft,
    all_groups: &[Group],
    problem: Option<&str>,
) -> Response {
    let text = admin.lang.text();
    let action = format!("/admin/apps/{}", record.id.0);
    let mut content = Html::new();
    html!(
        content,
        "<a class=\"back\" href=\"/admin/apps\">",
        { icon("arrow-left") },
        { text.section_apps },
        "</a><div class=\"page-head\"><h1>",
        { record.name },
        "</h1></div>",
        { notice(request, admin.lang) }
    );
    if let Some(problem) = problem {
        html!(content, { error_notice(problem) });
    }
    html!(
        content,
        "<form method=\"post\" action=\"",
        { action },
        "\">",
        { admin.csrf.field() }
    );
    settings_sections(&mut content, admin, record.kind, draft, all_groups);
    html!(
        content,
        "<section class=\"section\"><span></span><div class=\"stack\"><button class=\"primary\" ",
        "name=\"action\" value=\"save\">",
        { text.save },
        "</button></div></section></form>"
    );
    if let Some(client_id) = &record.client_id {
        credentials_section(&mut content, app, admin, record, client_id, &action);
    }
    html!(
        content,
        "<section class=\"section\"><span></span><div class=\"stack\">"
    );
    danger_zone(&mut content, admin, text.delete, &action);
    html!(content, "</div></section>");
    admin.page(app, Section::Apps, &record.name, &content)
}

/// The editable settings: general, protocol, access and consent.
fn settings_sections(
    out: &mut Html,
    admin: &Admin,
    kind: Kind,
    draft: &Draft,
    all_groups: &[Group],
) {
    let text = admin.lang.text();
    html!(
        *out,
        "<section class=\"section\"><h2>",
        { text.general },
        "</h2><div class=\"stack\">"
    );
    text_input(out, text.name, "name", &draft.name, None);
    checkbox(out, text.enabled, "enabled", "1", draft.enabled);
    html!(*out, "</div></section>");
    match kind {
        Kind::Proxy => {
            html!(
                *out,
                "<section class=\"section\"><h2>Forward auth</h2><div class=\"stack\">"
            );
            text_input(out, text.host, "host", &draft.host, Some(text.host_note));
        }
        Kind::Oidc => {
            html!(
                *out,
                "<section class=\"section\"><h2>OpenID Connect</h2><div class=\"stack\">"
            );
            lines_input(
                out,
                text.redirect_uris,
                "redirect_uris",
                &draft.redirect_uris,
                text.one_per_line,
            );
            lines_input(
                out,
                text.post_logout_uris,
                "post_logout_uris",
                &draft.post_logout_uris,
                text.one_per_line,
            );
            lines_input(
                out,
                text.resources,
                "resources",
                &draft.resources,
                text.resources_note,
            );
            html!(
                *out,
                "<div><label for=\"id_token_alg\">",
                { text.id_token_alg },
                "</label><select id=\"id_token_alg\" name=\"id_token_alg\">"
            );
            for algorithm in Algorithm::ALL {
                html!(*out, "<option");
                if algorithm.name() == draft.id_token_alg {
                    html!(*out, " selected");
                }
                html!(*out, ">", { algorithm.name() }, "</option>");
            }
            html!(*out, "</select></div>");
        }
    }
    html!(
        *out,
        "</div></section><section class=\"section\"><h2>",
        { text.access },
        "</h2><div class=\"stack\">"
    );
    checkbox(out, text.everyone, "all_users", "1", draft.all_users);
    for group in all_groups {
        let id = group.id.0.to_string();
        checkbox(
            out,
            &group.name,
            "group",
            &id,
            draft.groups.contains(&group.id),
        );
    }
    html!(*out, "</div></section>");
    if kind == Kind::Oidc {
        html!(
            *out,
            "<section class=\"section\"><h2>",
            { text.consent },
            "</h2><div class=\"stack\">"
        );
        checkbox(
            out,
            text.skip_consent,
            "skip_consent",
            "1",
            draft.skip_consent,
        );
        html!(*out, "</div></section>");
    }
}

/// What the administrator copies into the application, and a button for a new secret.
fn credentials_section(
    out: &mut Html,
    app: &App,
    admin: &Admin,
    record: &AppRecord,
    client_id: &str,
    action: &str,
) {
    let text = admin.lang.text();
    html!(
        *out,
        "<section class=\"section\"><h2>",
        { text.credentials },
        "</h2><div class=\"stack\">"
    );
    secret_row(out, admin, text.issuer, app.config.issuer.as_str());
    secret_row(out, admin, "Client ID", client_id);
    if record.client_secret_hash.is_some() {
        html!(
            *out,
            "<form method=\"post\" action=\"",
            { action },
            "\">",
            { admin.csrf.field() },
            "<button class=\"compact\" name=\"action\" value=\"secret\">",
            { icon("refresh-cw") },
            { text.new_secret },
            "</button></form>"
        );
    } else {
        html!(
            *out,
            "<p class=\"field-note\">",
            { text.public_client },
            "</p>"
        );
    }
    html!(*out, "</div></section>");
}

/// A host name, optionally with a port, in lowercase: what `X-Forwarded-Host` will carry.
fn parse_host(text: &str) -> Option<String> {
    let (name, port) = text
        .split_once(':')
        .map_or((text, None), |(name, port)| (name, Some(port)));
    let name_valid = !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        });
    let port_valid = port.is_none_or(|port| port.parse::<u16>().is_ok_and(|port| port > 0));
    (name_valid && port_valid).then(|| text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::parse_host;

    #[test]
    fn hosts_are_plain_lowercase_names() {
        for good in ["photos.home.lan", "a.b", "app-1.example.com:8443"] {
            assert!(parse_host(good).is_some(), "{good}");
        }
        for bad in [
            "",
            "Photos.lan",
            "-a.lan",
            "a..lan",
            "a.lan:0",
            "a.lan:99999",
            "a/b",
            "a lan",
        ] {
            assert!(parse_host(bad).is_none(), "{bad}");
        }
    }
}
