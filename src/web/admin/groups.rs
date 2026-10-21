//! Groups: listing, creating, renaming and deleting them.

use hyper::Method;

use super::{Admin, danger_zone, field, notice, parse_id, text_input};
use crate::html::{Html, html};
use crate::http::{Request, Response};
use crate::store::groups::{self, GroupId};
use crate::store::users::Username;
use crate::web::layout::{Section, error_notice, icon};
use crate::web::{App, Failure};

/// `GET` and `POST /admin/groups`: the list, and a form that adds a group.
pub(super) async fn list(app: &App, request: &Request, admin: &Admin) -> Result<Response, Failure> {
    let text = admin.lang.text();
    let mut problem = None;
    if request.method == Method::POST {
        // Group names follow the rules for user names: they travel in tokens and are compared
        // by applications, so they need one unambiguous spelling.
        match Username::parse(field(request, "name")) {
            None => problem = Some(text.username_invalid),
            Some(name) => {
                let created = app
                    .db
                    .run(move |conn| groups::create(conn, name.as_str()))
                    .await;
                match created {
                    Ok(_) => {
                        admin
                            .record(app, request, "create group", field(request, "name"))
                            .await?;
                        return Ok(Response::redirect("/admin/groups?notice=saved"));
                    }
                    Err(e) if e.is_constraint_violation() => problem = Some(text.group_taken),
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }
    let groups = app.db.run(|conn| groups::list(conn)).await?;
    let mut content = Html::new();
    html!(
        content,
        "<div class=\"page-head\"><h1>",
        { text.section_groups },
        "</h1></div>",
        { notice(request, admin.lang) }
    );
    if let Some(problem) = problem {
        html!(content, { error_notice(problem) });
    }
    html!(
        content,
        "<div class=\"table\"><table><thead><tr><th>",
        { text.name },
        "</th><th class=\"num\">",
        { text.members },
        "</th></tr></thead><tbody>"
    );
    for group in &groups {
        html!(
            content,
            "<tr><td><a href=\"/admin/groups/",
            { group.id.0 },
            "\">",
            { group.name },
            "</a></td><td class=\"num\">",
            { group.members },
            "</td></tr>"
        );
    }
    html!(
        content,
        "</tbody></table></div><form method=\"post\" action=\"/admin/groups\"><section class=\"section\"><h2>",
        { text.new_group },
        "</h2><div class=\"stack\">",
        { admin.csrf.field() }
    );
    text_input(
        &mut content,
        text.name,
        "name",
        "",
        Some(text.username_note),
    );
    html!(
        content,
        "<button class=\"primary\">",
        { icon("plus") },
        { text.create },
        "</button></div></section></form>"
    );
    Ok(admin.page(app, Section::Groups, text.section_groups, &content))
}

/// `GET` and `POST /admin/groups/<id>`: renaming, members and deletion.
pub(super) async fn edit(
    app: &App,
    request: &Request,
    admin: &Admin,
    id: &str,
) -> Result<Option<Response>, Failure> {
    let Some(id) = parse_id(id).map(GroupId) else {
        return Ok(None);
    };
    let found = app
        .db
        .run(move |conn| {
            let group = groups::list(conn)?.into_iter().find(|group| group.id == id);
            Ok(group.map(|group| (group, groups::members(conn, id))))
        })
        .await?;
    let Some((group, members)) = found else {
        return Ok(None);
    };
    let members = members?;
    let text = admin.lang.text();
    let action = format!("/admin/groups/{}", id.0);
    let mut problem = None;
    if request.method == Method::POST {
        match change(app, request, admin, &group).await? {
            Ok(response) => return Ok(Some(response)),
            Err(message) => problem = Some(message),
        }
    }
    let mut content = Html::new();
    html!(
        content,
        "<a class=\"back\" href=\"/admin/groups\">",
        { icon("arrow-left") },
        { text.section_groups },
        "</a><div class=\"page-head\"><h1>",
        { group.name },
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
        "\"><section class=\"section\"><h2>",
        { text.general },
        "</h2><div class=\"stack\">",
        { admin.csrf.field() }
    );
    text_input(
        &mut content,
        text.name,
        "name",
        &group.name,
        Some(text.group_rename_note),
    );
    html!(
        content,
        "<button class=\"primary\" name=\"action\" value=\"rename\">",
        { text.save },
        "</button></div></section></form><section class=\"section\"><h2>",
        { text.members },
        "</h2><div class=\"stack\">"
    );
    if members.is_empty() {
        html!(content, "<p class=\"muted\">", { text.no_members }, "</p>");
    }
    for member in &members {
        html!(content, "<span>", { member }, "</span>");
    }
    html!(
        content,
        "</div></section><section class=\"section\"><span></span><div class=\"stack\">"
    );
    danger_zone(&mut content, admin, text.delete, &action);
    html!(content, "</div></section>");
    Ok(Some(admin.page(
        app,
        Section::Groups,
        &group.name,
        &content,
    )))
}

/// Renames or deletes a group; the error is a message for the form.
async fn change(
    app: &App,
    request: &Request,
    admin: &Admin,
    group: &groups::Group,
) -> Result<Result<Response, &'static str>, Failure> {
    let text = admin.lang.text();
    let id = group.id;
    if field(request, "action") == "delete" {
        app.db.run(move |conn| groups::delete(conn, id)).await?;
        admin
            .record(app, request, "delete group", &group.name)
            .await?;
        return Ok(Ok(Response::redirect("/admin/groups?notice=deleted")));
    }
    let Some(name) = Username::parse(field(request, "name")) else {
        return Ok(Err(text.username_invalid));
    };
    match app
        .db
        .run(move |conn| groups::rename(conn, id, name.as_str()))
        .await
    {
        Ok(()) => {
            admin
                .record(app, request, "rename group", &group.name)
                .await?;
            Ok(Ok(Response::redirect(format!(
                "/admin/groups/{}?notice=saved",
                id.0
            ))))
        }
        Err(e) if e.is_constraint_violation() => Ok(Err(text.group_taken)),
        Err(e) => Err(e.into()),
    }
}
