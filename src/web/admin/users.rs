//! Users: listing, inviting, editing, password links and deletion.

use hyper::Method;

use super::{Admin, checkbox, checked, danger_zone, field, notice, parse_id, text_input};
use crate::crypto::{TokenHash, random_token};
use crate::html::{Html, html};
use crate::http::{Request, Response};
use crate::identifier::Identifier;
use crate::store::audit::Action;
use crate::store::groups::{self, Group, GroupId};
use crate::store::users::{self, NewUser, User, UserChanges, UserId};
use crate::time;
use crate::web::i18n::Text;
use crate::web::layout::{Section, copy_button, error_notice, icon, success_notice, tooltip};
use crate::web::session::{self, Ending};
use crate::web::{App, Failure, is_name};

/// Invitation and reset links work for three days.
const LINK_LIFETIME: i64 = 3 * 24 * 60 * 60;
const MAX_EMAIL_LEN: usize = 254;

/// `GET /admin/users`
pub(super) async fn list(app: &App, request: &Request, admin: &Admin) -> Result<Response, Failure> {
    let text = admin.lang.text();
    let users = app.db.run(|conn| users::list(conn)).await?;
    let mut content = Html::new();
    html!(
        content,
        "<div class=\"page-head\"><h1>",
        { text.section_users },
        "</h1><a class=\"button primary compact\" href=\"/admin/users/new\">",
        { icon("plus") },
        { text.invite },
        "</a></div>",
        { notice(request, admin.lang) },
        "<div class=\"table\"><table><thead><tr><th>",
        { text.username },
        "</th><th>",
        { text.display_name },
        "</th><th>",
        { text.status },
        "</th><th>",
        { text.two_factor },
        "</th></tr></thead><tbody>"
    );
    for user in &users {
        let status = if user.disabled {
            text.disabled
        } else if user.password_hash.is_none() {
            text.invited
        } else if user.is_admin {
            text.administrator
        } else {
            ""
        };
        html!(
            content,
            "<tr><td><a href=\"/admin/users/",
            { user.id.0 },
            "\">",
            { user.username },
            "</a></td><td>",
            { user.display_name },
            "</td><td>",
            { status },
            "</td><td>",
            {
                if user.totp_secret.is_some() {
                    text.on
                } else {
                    text.off
                }
            },
            "</td></tr>"
        );
    }
    html!(content, "</tbody></table></div>");
    Ok(admin.page(app, Section::Users, text.section_users, &content))
}

/// `GET` and `POST /admin/users/new`: creates an account without a password and shows the link
/// with which its owner sets one.
pub(super) async fn create(
    app: &App,
    request: &Request,
    admin: &Admin,
) -> Result<Response, Failure> {
    let text = admin.lang.text();
    if request.method != Method::POST {
        return Ok(create_form(app, request, admin, None));
    }
    let Some(username) = Identifier::parse(field(request, "username")) else {
        return Ok(create_form(
            app,
            request,
            admin,
            Some(text.identifier_invalid),
        ));
    };
    let name = field(request, "name").to_owned();
    if !is_name(&name) {
        return Ok(create_form(app, request, admin, Some(text.name_required)));
    }
    let Ok(email) = parse_email(field(request, "email")) else {
        return Ok(create_form(app, request, admin, Some(text.email_invalid)));
    };
    let is_admin = checked(request, "admin");
    let token = random_token()?;
    let hash = TokenHash::of(&token);
    let expires_at = time::now().saturating_add(LINK_LIFETIME);
    let new_name = username.clone();
    let created = app
        .db
        .run(move |conn| {
            let id = users::create(
                conn,
                &NewUser {
                    username: &new_name,
                    display_name: &name,
                    email: email.as_deref(),
                    email_verified: false,
                    is_admin,
                },
            )?;
            users::create_password_link(conn, id, &hash, expires_at)?;
            Ok(id)
        })
        .await;
    let id = match created {
        Ok(id) => id,
        Err(e) if e.is_constraint_violation() => {
            return Ok(create_form(app, request, admin, Some(text.username_taken)));
        }
        Err(e) => return Err(e.into()),
    };
    admin
        .record(app, request, Action::InviteUser, username.as_str())
        .await?;
    Ok(link_page(
        app,
        admin,
        id,
        username.as_str(),
        &token,
        text.invitation_link,
    ))
}

fn create_form(app: &App, request: &Request, admin: &Admin, problem: Option<&str>) -> Response {
    let text = admin.lang.text();
    let mut content = Html::new();
    html!(
        content,
        "<a class=\"back\" href=\"/admin/users\">",
        { icon("arrow-left") },
        { text.section_users },
        "</a><div class=\"page-head\"><h1>",
        { text.invite },
        "</h1></div>"
    );
    if let Some(problem) = problem {
        html!(content, { error_notice(problem) });
    }
    html!(
        content,
        "<form method=\"post\" action=\"/admin/users/new\"><section class=\"section\"><h2>",
        { text.general },
        "</h2><div class=\"stack\">",
        { admin.csrf.field() }
    );
    text_input(
        &mut content,
        text.username,
        "username",
        field(request, "username"),
        Some(text.identifier_note),
    );
    text_input(
        &mut content,
        text.display_name,
        "name",
        field(request, "name"),
        None,
    );
    text_input(
        &mut content,
        text.email,
        "email",
        field(request, "email"),
        None,
    );
    checkbox(
        &mut content,
        text.administrator,
        "admin",
        "1",
        checked(request, "admin"),
        Some(text.tip_administrator),
    );
    html!(
        content,
        "</div></section><section class=\"section\"><span></span><div class=\"stack\"><button class=\"primary\">",
        { text.create },
        "</button></div></section></form>"
    );
    admin.page(app, Section::Users, text.invite, &content)
}

/// Shows a one-time password link. Only its hash is stored, so this is the only time it exists.
fn link_page(
    app: &App,
    admin: &Admin,
    id: UserId,
    username: &str,
    token: &str,
    title: &str,
) -> Response {
    let text = admin.lang.text();
    let link = app.config.issuer.url(&format!("/password?token={token}"));
    let mut content = Html::new();
    html!(
        content,
        "<div class=\"page-head\"><h1>",
        { title },
        "</h1></div><div class=\"stack narrow\"><p>",
        { username },
        "</p><div class=\"secret\"><span>",
        { link },
        "</span>",
        { copy_button(admin.lang, &link) },
        "</div><p class=\"field-note\">",
        { text.link_note },
        "</p><a class=\"button primary\" href=\"/admin/users/",
        { id.0 },
        "\">",
        { text.done },
        "</a></div>"
    );
    admin.page(app, Section::Users, title, &content)
}

/// What the edit form shows: the stored account, or what was just submitted if it had a
/// problem, so nothing typed is lost.
struct Draft {
    display_name: String,
    email: String,
    email_verified: bool,
    is_admin: bool,
    disabled: bool,
    groups: Vec<GroupId>,
}

impl Draft {
    fn stored(user: &User, groups: Vec<GroupId>) -> Self {
        Self {
            display_name: user.display_name.clone(),
            email: user.email.clone().unwrap_or_default(),
            email_verified: user.email_verified,
            is_admin: user.is_admin,
            disabled: user.disabled,
            groups,
        }
    }

    /// The submitted form. Administrators can't demote or disable themselves, so for their own
    /// account those two keep their stored values.
    fn submitted(request: &Request, user: &User, editing_self: bool) -> Self {
        let (is_admin, disabled) = if editing_self {
            (user.is_admin, user.disabled)
        } else {
            (checked(request, "admin"), checked(request, "disabled"))
        };
        Self {
            display_name: field(request, "name").to_owned(),
            email: field(request, "email").to_owned(),
            email_verified: checked(request, "email_verified"),
            is_admin,
            disabled,
            groups: request
                .form
                .all("group")
                .filter_map(|value| value.parse().ok().map(GroupId))
                .collect(),
        }
    }

    fn check(&self, text: &Text) -> Result<UserChanges, &'static str> {
        if !is_name(&self.display_name) {
            return Err(text.name_required);
        }
        let email = parse_email(&self.email).map_err(|()| text.email_invalid)?;
        Ok(UserChanges {
            email_verified: email.is_some() && self.email_verified,
            display_name: self.display_name.clone(),
            email,
            is_admin: self.is_admin,
            disabled: self.disabled,
            groups: self.groups.clone(),
        })
    }
}

/// `GET` and `POST /admin/users/<id>`
pub(super) async fn edit(
    app: &App,
    request: &Request,
    admin: &Admin,
    id: &str,
) -> Result<Option<Response>, Failure> {
    let Some(id) = parse_id(id).map(UserId) else {
        return Ok(None);
    };
    let found = app
        .db
        .run(move |conn| {
            let Some(user) = users::by_id(conn, id)? else {
                return Ok(None);
            };
            Ok(Some((user, users::groups(conn, id)?, groups::list(conn)?)))
        })
        .await?;
    let Some((user, user_groups, all_groups)) = found else {
        return Ok(None);
    };
    let view = |draft: &Draft, problem: Option<&str>| {
        Some(edit_form(
            app,
            request,
            admin,
            &user,
            draft,
            &all_groups,
            problem,
        ))
    };
    if request.method != Method::POST {
        return Ok(view(&Draft::stored(&user, user_groups), None));
    }
    let text = admin.lang.text();
    let editing_self = user.id == admin.session.user.id;
    match field(request, "action") {
        "delete" => {
            if editing_self {
                return Ok(view(
                    &Draft::stored(&user, user_groups),
                    Some(text.keep_an_admin),
                ));
            }
            // Sessions end first, while their applications can still be found to be told.
            session::end(app, Ending::AllOf(id, None)).await?;
            if app
                .db
                .run(move |conn| users::delete(conn, id))
                .await?
                .is_err()
            {
                return Ok(view(
                    &Draft::stored(&user, user_groups),
                    Some(text.keep_an_admin),
                ));
            }
            admin
                .record(app, request, Action::DeleteUser, &user.username)
                .await?;
            Ok(Some(Response::redirect("/admin/users?notice=deleted")))
        }
        "link" | "reset_two_factor" | "sign_out" => act(app, request, admin, &user).await.map(Some),
        _ => {
            let draft = Draft::submitted(request, &user, editing_self);
            let changes = match draft.check(text) {
                Ok(changes) => changes,
                Err(problem) => return Ok(view(&draft, Some(problem))),
            };
            if changes.disabled {
                session::end(app, Ending::AllOf(id, None)).await?;
            }
            if app
                .db
                .run(move |conn| users::update(conn, id, &changes))
                .await?
                .is_err()
            {
                return Ok(view(&draft, Some(text.keep_an_admin)));
            }
            admin
                .record(app, request, Action::ChangeUser, &user.username)
                .await?;
            Ok(Some(Response::redirect(format!(
                "/admin/users/{}?notice=saved",
                id.0
            ))))
        }
    }
}

/// The buttons in the sign-in section: a password link, resetting two-factor sign-in and
/// ending every session.
async fn act(
    app: &App,
    request: &Request,
    admin: &Admin,
    user: &User,
) -> Result<Response, Failure> {
    let text = admin.lang.text();
    let id = user.id;
    match field(request, "action") {
        "link" => {
            let token = random_token()?;
            let hash = TokenHash::of(&token);
            let expires_at = time::now().saturating_add(LINK_LIFETIME);
            app.db
                .run(move |conn| users::create_password_link(conn, id, &hash, expires_at))
                .await?;
            admin
                .record(app, request, Action::CreatePasswordLink, &user.username)
                .await?;
            Ok(link_page(
                app,
                admin,
                id,
                &user.username,
                &token,
                text.password_link,
            ))
        }
        "reset_two_factor" => {
            app.db
                .run(move |conn| users::set_totp(conn, id, None))
                .await?;
            admin
                .record(app, request, Action::ResetTwoFactor, &user.username)
                .await?;
            Ok(Response::redirect(format!(
                "/admin/users/{}?notice=saved",
                id.0
            )))
        }
        _ => {
            session::end(app, Ending::AllOf(id, None)).await?;
            admin
                .record(app, request, Action::EndSessions, &user.username)
                .await?;
            Ok(Response::redirect(format!(
                "/admin/users/{}?notice=ended",
                id.0
            )))
        }
    }
}

/// An optional email address. Only the shape is checked; whether the address works is up to
/// the administrator, who also says whether it was verified.
fn parse_email(text: &str) -> Result<Option<String>, ()> {
    if text.is_empty() {
        return Ok(None);
    }
    let (local, domain) = text.rsplit_once('@').ok_or(())?;
    let valid = !local.is_empty()
        && domain.contains('.')
        && text.len() <= MAX_EMAIL_LEN
        && !text.chars().any(|c| c.is_whitespace() || c.is_control());
    valid.then(|| Some(text.to_owned())).ok_or(())
}

fn edit_form(
    app: &App,
    request: &Request,
    admin: &Admin,
    user: &User,
    draft: &Draft,
    all_groups: &[Group],
    problem: Option<&str>,
) -> Response {
    let text = admin.lang.text();
    let action = format!("/admin/users/{}", user.id.0);
    let editing_self = user.id == admin.session.user.id;
    let mut content = Html::new();
    html!(
        content,
        "<a class=\"back\" href=\"/admin/users\">",
        { icon("arrow-left") },
        { text.section_users },
        "</a><div class=\"page-head\"><h1>",
        { user.username },
        "</h1></div>",
        { notice(request, admin.lang) }
    );
    if let Some(problem) = problem {
        html!(content, { error_notice(problem) });
    }
    if user.password_hash.is_none() {
        html!(content, { success_notice(text.invited) });
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
    text_input(
        &mut content,
        text.display_name,
        "name",
        &draft.display_name,
        None,
    );
    text_input(&mut content, text.email, "email", &draft.email, None);
    checkbox(
        &mut content,
        text.email_verified,
        "email_verified",
        "1",
        draft.email_verified,
        Some(text.tip_email_verified),
    );
    if !editing_self {
        checkbox(
            &mut content,
            text.administrator,
            "admin",
            "1",
            draft.is_admin,
            Some(text.tip_administrator),
        );
        checkbox(
            &mut content,
            text.disabled,
            "disabled",
            "1",
            draft.disabled,
            Some(text.tip_disabled),
        );
    }
    html!(
        content,
        "</div></section><section class=\"section\"><h2>",
        { text.section_groups },
        "</h2><div class=\"stack\">"
    );
    for group in all_groups {
        let id = group.id.0.to_string();
        checkbox(
            &mut content,
            &group.name,
            "group",
            &id,
            draft.groups.contains(&group.id),
            None,
        );
    }
    html!(
        content,
        "</div></section><section class=\"section\"><span></span><div class=\"stack\"><button class=\"primary\" ",
        "name=\"action\" value=\"save\">",
        { text.save },
        "</button></div></section></form>"
    );
    sign_in_section(&mut content, admin, user, &action);
    if !editing_self {
        html!(
            content,
            "<section class=\"section\"><span></span><div class=\"stack\">"
        );
        danger_zone(&mut content, admin, text.delete, &action);
        html!(content, "</div></section>");
    }
    admin.page(app, Section::Users, &user.username, &content)
}

/// Buttons for the account's sign-in: a password link, two-factor reset and ending sessions.
fn sign_in_section(out: &mut Html, admin: &Admin, user: &User, action: &str) {
    let text = admin.lang.text();
    html!(
        *out,
        "<section class=\"section\"><h2>",
        { text.sign_in_title },
        "</h2><div class=\"stack\">"
    );
    let mut button = |value: &str, glyph: &str, label: &str, tip: &str| {
        let id = format!("tip-{value}");
        html!(
            *out,
            "<div class=\"has-tip\"><form method=\"post\" action=\"",
            { action },
            "\">",
            { admin.csrf.field() },
            "<button class=\"compact\" name=\"action\" value=\"",
            { value },
            "\" aria-describedby=\"",
            { id },
            "\">",
            { icon(glyph) },
            { label },
            "</button></form>",
            { tooltip(&id, tip) },
            "</div>"
        );
    };
    button(
        "link",
        "key-round",
        text.password_link,
        text.tip_password_link,
    );
    if user.totp_secret.is_some() {
        button(
            "reset_two_factor",
            "shield-check",
            text.reset_two_factor,
            text.tip_reset_two_factor,
        );
    }
    button(
        "sign_out",
        "log-out",
        text.end_sessions,
        text.tip_end_sessions,
    );
    html!(*out, "</div></section>");
}

#[cfg(test)]
mod tests {
    use super::parse_email;

    #[test]
    fn emails_need_a_local_part_and_a_domain() {
        assert_eq!(parse_email(""), Ok(None));
        assert_eq!(
            parse_email("anna@example.com"),
            Ok(Some("anna@example.com".to_owned()))
        );
        for bad in ["anna", "@example.com", "anna@example", "an na@example.com"] {
            assert_eq!(parse_email(bad), Err(()), "{bad}");
        }
    }
}
