//! Sign-in providers: listing, adding, editing and deleting them.

use hyper::Method;

use super::apps::parse_host;
use super::{Admin, checkbox, checked, danger_zone, field, notice, parse_id, text_input};
use crate::html::{Html, html};
use crate::http::client::{Plain, is_valid_url};
use crate::http::{Request, Response};
use crate::store::providers::{self, Provider, ProviderId, ProviderKind};
use crate::store::users::Username;
use crate::web::i18n::Text;
use crate::web::layout::{Section, copy_button, error_notice, icon};
use crate::web::providers::redirect_uri;
use crate::web::{App, Failure};

const MAX_NAME_CHARS: usize = 100;
const MAX_CLIENT_ID_LEN: usize = 200;

/// `GET /admin/providers`
pub(super) async fn list(app: &App, request: &Request, admin: &Admin) -> Result<Response, Failure> {
    let text = admin.lang.text();
    let all = app.db.run(|conn| providers::list(conn)).await?;
    let mut content = Html::new();
    html!(
        content,
        "<div class=\"page-head\"><h1>",
        { text.section_providers },
        "</h1><a class=\"button primary compact\" href=\"/admin/providers/new\">",
        { icon("plus") },
        { text.add },
        "</a></div>",
        { notice(request, admin.lang) },
        "<div class=\"table\"><table><thead><tr><th>",
        { text.name },
        "</th><th>",
        { text.kind },
        "</th><th>",
        { text.status },
        "</th></tr></thead><tbody>"
    );
    for provider in &all {
        html!(
            content,
            "<tr><td><a href=\"/admin/providers/",
            { provider.id.0 },
            "\">",
            { provider.name },
            "</a></td><td>",
            { kind_label(provider.kind) },
            "</td><td"
        );
        if provider.enabled {
            html!(content, ">", { text.enabled });
        } else {
            html!(content, " class=\"off\">", { text.disabled });
        }
        html!(content, "</td></tr>");
    }
    html!(content, "</tbody></table></div>");
    Ok(admin.page(app, Section::Providers, text.section_providers, &content))
}

const fn kind_label(kind: ProviderKind) -> &'static str {
    match kind {
        ProviderKind::Oidc => "OpenID Connect",
        ProviderKind::Github => "GitHub",
    }
}

/// The form as submitted or as stored.
struct Draft {
    name: String,
    slug: String,
    kind: ProviderKind,
    issuer: String,
    client_id: String,
    domains: String,
    enabled: bool,
}

impl Draft {
    /// A new provider, prefilled for Google, the most common one.
    fn blank() -> Self {
        Self {
            name: String::new(),
            slug: String::new(),
            kind: ProviderKind::Oidc,
            issuer: "https://accounts.google.com".to_owned(),
            client_id: String::new(),
            domains: String::new(),
            enabled: true,
        }
    }

    fn stored(provider: &Provider) -> Self {
        Self {
            name: provider.name.clone(),
            slug: provider.slug.clone(),
            kind: provider.kind,
            issuer: provider.issuer.clone().unwrap_or_default(),
            client_id: provider.client_id.clone(),
            domains: provider.auto_create_domains.join(" "),
            enabled: provider.enabled,
        }
    }

    fn submitted(request: &Request) -> Self {
        Self {
            name: field(request, "name").to_owned(),
            slug: field(request, "slug").to_owned(),
            kind: if field(request, "kind") == "github" {
                ProviderKind::Github
            } else {
                ProviderKind::Oidc
            },
            issuer: field(request, "issuer").trim_end_matches('/').to_owned(),
            client_id: field(request, "client_id").to_owned(),
            domains: field(request, "domains").to_ascii_lowercase(),
            enabled: checked(request, "enabled"),
        }
    }

    /// The provider to save, with the secret still in plain text, or the first problem.
    fn check(&self, text: &Text, secret: &str, creating: bool) -> Result<Provider, &'static str> {
        if self.name.is_empty() || self.name.chars().count() > MAX_NAME_CHARS {
            return Err(text.name_required);
        }
        let slug = Username::parse(&self.slug).ok_or(text.slug_invalid)?;
        let issuer = match self.kind {
            ProviderKind::Github => None,
            ProviderKind::Oidc => {
                let valid =
                    is_valid_url(&self.issuer, Plain::Loopback) && !self.issuer.contains('?');
                Some(
                    valid
                        .then(|| self.issuer.clone())
                        .ok_or(text.issuer_invalid)?,
                )
            }
        };
        if self.client_id.is_empty() || self.client_id.len() > MAX_CLIENT_ID_LEN {
            return Err(text.client_id_required);
        }
        if creating && secret.is_empty() {
            return Err(text.client_secret_required);
        }
        let domains: Vec<String> = self.domains.split_whitespace().map(str::to_owned).collect();
        if domains
            .iter()
            .any(|domain| domain.contains(':') || parse_host(domain).is_none())
        {
            return Err(text.domains_invalid);
        }
        Ok(Provider {
            id: ProviderId(0),
            slug: slug.as_str().to_owned(),
            name: self.name.clone(),
            kind: self.kind,
            issuer,
            client_id: self.client_id.clone(),
            client_secret: secret.as_bytes().to_vec(),
            auto_create_domains: domains,
            enabled: self.enabled,
        })
    }
}

/// `GET` and `POST /admin/providers/new`, and `/admin/providers/<id>`.
pub(super) async fn edit(
    app: &App,
    request: &Request,
    admin: &Admin,
    id: &str,
) -> Result<Option<Response>, Failure> {
    let existing = if id == "new" {
        None
    } else {
        let Some(id) = parse_id(id).map(ProviderId) else {
            return Ok(None);
        };
        let Some(provider) = app.db.run(move |conn| providers::by_id(conn, id)).await? else {
            return Ok(None);
        };
        Some(provider)
    };
    let text = admin.lang.text();
    if request.method != Method::POST {
        let draft = existing.as_ref().map_or_else(Draft::blank, Draft::stored);
        return Ok(Some(form(
            app,
            request,
            admin,
            existing.as_ref(),
            &draft,
            None,
        )));
    }
    if let (Some(provider), "delete") = (&existing, field(request, "action")) {
        let id = provider.id;
        app.db.run(move |conn| providers::delete(conn, id)).await?;
        admin
            .record(app, request, "delete sign-in provider", &provider.name)
            .await?;
        return Ok(Some(Response::redirect("/admin/providers?notice=deleted")));
    }
    let draft = Draft::submitted(request);
    let secret = request
        .form
        .single("client_secret")
        .ok()
        .flatten()
        .unwrap_or_default();
    let mut provider = match draft.check(text, secret, existing.is_none()) {
        Ok(provider) => provider,
        Err(problem) => {
            return Ok(Some(form(
                app,
                request,
                admin,
                existing.as_ref(),
                &draft,
                Some(problem),
            )));
        }
    };
    // The secret is sealed with the provider's row as context, so the row must exist first.
    let plain_secret = std::mem::take(&mut provider.client_secret);
    let existing_id = existing.as_ref().map(|provider| provider.id);
    let saved = app
        .db
        .run(move |conn| providers::save(conn, existing_id, &provider))
        .await;
    let id = match saved {
        Ok(id) => id,
        Err(e) if e.is_constraint_violation() => {
            return Ok(Some(form(
                app,
                request,
                admin,
                existing.as_ref(),
                &draft,
                Some(text.slug_taken),
            )));
        }
        Err(e) => return Err(e.into()),
    };
    store_secret(app, id, &plain_secret).await?;
    admin
        .record(app, request, "change sign-in provider", &draft.name)
        .await?;
    Ok(Some(Response::redirect(format!(
        "/admin/providers/{}?notice=saved",
        id.0
    ))))
}

fn form(
    app: &App,
    request: &Request,
    admin: &Admin,
    existing: Option<&Provider>,
    draft: &Draft,
    problem: Option<&str>,
) -> Response {
    let text = admin.lang.text();
    let action = existing.map_or_else(
        || "/admin/providers/new".to_owned(),
        |provider| format!("/admin/providers/{}", provider.id.0),
    );
    let title = existing.map_or(text.new_provider, |provider| provider.name.as_str());
    let mut content = Html::new();
    html!(
        content,
        "<a class=\"back\" href=\"/admin/providers\">",
        { icon("arrow-left") },
        { text.section_providers },
        "</a><div class=\"page-head\"><h1>",
        { title },
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
        { admin.csrf.field() },
        "<section class=\"section\"><h2>",
        { text.general },
        "</h2><div class=\"stack\">"
    );
    text_input(&mut content, text.name, "name", &draft.name, None);
    text_input(
        &mut content,
        text.slug,
        "slug",
        &draft.slug,
        Some(text.slug_note),
    );
    connection_fields(&mut content, text, draft, existing.is_some());
    text_input(
        &mut content,
        text.auto_create_domains,
        "domains",
        &draft.domains,
        Some(text.auto_create_note),
    );
    checkbox(
        &mut content,
        text.enabled,
        "enabled",
        "1",
        draft.enabled,
        None,
    );
    html!(
        content,
        "</div></section><section class=\"section\"><span></span><div class=\"stack\"><button class=\"primary\" ",
        "name=\"action\" value=\"save\">",
        { text.save },
        "</button></div></section></form>"
    );
    if let Some(provider) = existing {
        callback_section(&mut content, app, admin, provider, &action);
    }
    admin.page(app, Section::Providers, title, &content)
}

/// What Unlatch needs to reach the provider. A stored secret is never shown; leaving the field
/// empty keeps it.
fn connection_fields(out: &mut Html, text: &Text, draft: &Draft, has_secret: bool) {
    html!(
        *out,
        "<div><label for=\"kind\">",
        { text.kind },
        "</label><select id=\"kind\" name=\"kind\">"
    );
    for kind in [ProviderKind::Oidc, ProviderKind::Github] {
        html!(*out, "<option value=\"", { kind.name() }, "\"");
        if kind == draft.kind {
            html!(*out, " selected");
        }
        html!(*out, ">", { kind_label(kind) }, "</option>");
    }
    html!(*out, "</select></div>");
    text_input(
        out,
        text.issuer,
        "issuer",
        &draft.issuer,
        Some(text.issuer_note),
    );
    text_input(out, "Client ID", "client_id", &draft.client_id, None);
    html!(
        *out,
        "<div><label for=\"client_secret\">",
        { text.client_secret },
        "</label><input id=\"client_secret\" name=\"client_secret\" type=\"password\" autocomplete=\"off\">"
    );
    if has_secret {
        html!(
            *out,
            "<p class=\"field-note\">",
            { text.secret_keep_note },
            "</p>"
        );
    }
    html!(*out, "</div>");
}

/// Seals a new client secret with the provider's row as context and stores it. An empty secret
/// keeps the stored one.
async fn store_secret(app: &App, id: ProviderId, secret: &[u8]) -> Result<(), Failure> {
    if secret.is_empty() {
        return Ok(());
    }
    let sealed = app
        .keys
        .secrets
        .seal(secret, format!("provider {}", id.0).as_bytes())?;
    app.db
        .run(move |conn| {
            conn.execute(
                "UPDATE providers SET client_secret = ?2 WHERE id = ?1",
                rusqlite::params![id.0, sealed],
            )?;
            Ok(())
        })
        .await?;
    Ok(())
}

/// The address to register at the provider, and deletion.
fn callback_section(out: &mut Html, app: &App, admin: &Admin, provider: &Provider, action: &str) {
    let text = admin.lang.text();
    let callback = redirect_uri(app, &provider.slug);
    html!(
        *out,
        "<section class=\"section\"><h2>",
        { text.redirect_uris },
        "</h2><div class=\"stack\"><div class=\"secret\"><span>",
        { callback },
        "</span>",
        { copy_button(admin.lang, &callback) },
        "</div><p class=\"field-note\">",
        { text.callback_note },
        "</p></div></section><section class=\"section\"><span></span><div class=\"stack\">"
    );
    danger_zone(out, admin, text.delete, action);
    html!(*out, "</div></section>");
}
