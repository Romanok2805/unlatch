//! Applications: OpenID Connect clients and hosts behind forward authentication.

use rusqlite::{Connection, OptionalExtension as _, Row, params};

use super::DbError;
use super::groups::GroupId;
use super::users::UserId;
use crate::crypto::Algorithm;
use crate::uri::RedirectUri;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AppId(pub(crate) i64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Oidc,
    Proxy,
}

#[derive(Clone)]
pub(crate) struct AppRecord {
    pub(crate) id: AppId,
    pub(crate) name: String,
    pub(crate) kind: Kind,
    pub(crate) enabled: bool,
    pub(crate) all_users: bool,
    pub(crate) skip_consent: bool,
    pub(crate) client_id: Option<String>,
    /// SHA-256 of the secret; `None` for public clients.
    pub(crate) client_secret_hash: Option<Vec<u8>>,
    pub(crate) id_token_alg: Algorithm,
    pub(crate) backchannel_logout_uri: Option<String>,
    pub(crate) host: Option<String>,
    pub(crate) redirect_uris: Vec<RedirectUri>,
    pub(crate) post_logout_uris: Vec<RedirectUri>,
    /// APIs a client may ask tokens for with the `resource` parameter (RFC 8707).
    pub(crate) resources: Vec<String>,
}

const COLUMNS: &str = "id, name, kind, enabled, all_users, skip_consent, client_id, \
                       client_secret_hash, id_token_alg, backchannel_logout_uri, host";

fn from_row(row: &Row<'_>) -> rusqlite::Result<AppRecord> {
    let kind: String = row.get(2)?;
    let alg: String = row.get(8)?;
    Ok(AppRecord {
        id: AppId(row.get(0)?),
        name: row.get(1)?,
        kind: if kind == "proxy" {
            Kind::Proxy
        } else {
            Kind::Oidc
        },
        enabled: row.get(3)?,
        all_users: row.get(4)?,
        skip_consent: row.get(5)?,
        client_id: row.get(6)?,
        client_secret_hash: row.get(7)?,
        id_token_alg: Algorithm::from_name(&alg).unwrap_or(Algorithm::Rs256),
        backchannel_logout_uri: row.get(9)?,
        host: row.get(10)?,
        redirect_uris: Vec::new(),
        post_logout_uris: Vec::new(),
        resources: Vec::new(),
    })
}

fn with_uris(conn: &Connection, mut app: AppRecord) -> Result<AppRecord, DbError> {
    let mut statement =
        conn.prepare("SELECT purpose, uri FROM app_uris WHERE app_id = ?1 ORDER BY uri")?;
    let rows = statement.query_map([app.id.0], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    for row in rows {
        let (purpose, uri) = row?;
        match purpose.as_str() {
            "resource" => app.resources.push(uri),
            // Stored URIs were validated when saved; one that no longer parses is skipped.
            "redirect" => app.redirect_uris.extend(RedirectUri::parse(&uri).ok()),
            _ => app.post_logout_uris.extend(RedirectUri::parse(&uri).ok()),
        }
    }
    Ok(app)
}

pub(crate) fn by_client_id(
    conn: &Connection,
    client_id: &str,
) -> Result<Option<AppRecord>, DbError> {
    let app = conn
        .query_row(
            &format!("SELECT {COLUMNS} FROM apps WHERE client_id = ?1 AND kind = 'oidc'"),
            [client_id],
            from_row,
        )
        .optional()?;
    app.map(|app| with_uris(conn, app)).transpose()
}

pub(crate) fn by_id(conn: &Connection, id: AppId) -> Result<Option<AppRecord>, DbError> {
    let app = conn
        .query_row(
            &format!("SELECT {COLUMNS} FROM apps WHERE id = ?1"),
            [id.0],
            from_row,
        )
        .optional()?;
    app.map(|app| with_uris(conn, app)).transpose()
}

/// Whether the user may use the application: it is enabled, and open to everyone or to a group
/// the user is in.
pub(crate) fn allows(conn: &Connection, app: &AppRecord, user: UserId) -> Result<bool, DbError> {
    if !app.enabled {
        return Ok(false);
    }
    if app.all_users {
        return Ok(true);
    }
    Ok(conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM app_groups JOIN group_members USING (group_id)
                        WHERE app_groups.app_id = ?1 AND group_members.user_id = ?2)",
        params![app.id.0, user.0],
        |row| row.get(0),
    )?)
}

/// The scope the user already consented to for this application, if any.
pub(crate) fn consent(
    conn: &Connection,
    app: AppId,
    user: UserId,
) -> Result<Option<String>, DbError> {
    Ok(conn
        .query_row(
            "SELECT scope FROM consents WHERE app_id = ?1 AND user_id = ?2",
            params![app.0, user.0],
            |row| row.get(0),
        )
        .optional()?)
}

pub(crate) fn save_consent(
    conn: &Connection,
    app: AppId,
    user: UserId,
    scope: &str,
) -> Result<(), DbError> {
    conn.execute(
        "INSERT INTO consents (app_id, user_id, scope) VALUES (?1, ?2, ?3)
         ON CONFLICT (user_id, app_id) DO UPDATE SET scope = excluded.scope",
        params![app.0, user.0, scope],
    )?;
    Ok(())
}

pub(crate) struct AppSummary {
    pub(crate) id: AppId,
    pub(crate) name: String,
    pub(crate) kind: Kind,
    pub(crate) enabled: bool,
    pub(crate) all_users: bool,
    pub(crate) groups: String,
    pub(crate) sessions: i64,
}

pub(crate) fn list(conn: &Connection) -> Result<Vec<AppSummary>, DbError> {
    let mut statement = conn.prepare(
        "SELECT apps.id, apps.name, apps.kind, apps.enabled, apps.all_users,
                (SELECT group_concat(groups.name, ', ') FROM app_groups
                 JOIN groups ON groups.id = app_groups.group_id WHERE app_groups.app_id = apps.id),
                (SELECT count(DISTINCT session_id) FROM grants WHERE grants.app_id = apps.id)
                + (SELECT count(*) FROM proxy_sessions WHERE proxy_sessions.app_id = apps.id)
         FROM apps ORDER BY apps.name COLLATE NOCASE",
    )?;
    let apps = statement
        .query_map([], |row| {
            let kind: String = row.get(2)?;
            Ok(AppSummary {
                id: AppId(row.get(0)?),
                name: row.get(1)?,
                kind: if kind == "proxy" {
                    Kind::Proxy
                } else {
                    Kind::Oidc
                },
                enabled: row.get(3)?,
                all_users: row.get(4)?,
                groups: row.get::<_, Option<String>>(5)?.unwrap_or_default(),
                sessions: row.get(6)?,
            })
        })?
        .collect::<Result<_, _>>()?;
    Ok(apps)
}

/// Creates an OpenID Connect client. `secret_hash` is `None` for a public client.
pub(crate) fn create_oidc(
    conn: &Connection,
    name: &str,
    client_id: &str,
    secret_hash: Option<&[u8]>,
) -> Result<AppId, DbError> {
    conn.execute(
        "INSERT INTO apps (name, kind, client_id, client_secret_hash, created_at)
         VALUES (?1, 'oidc', ?2, ?3, ?4)",
        params![name, client_id, secret_hash, crate::time::now()],
    )?;
    Ok(AppId(conn.last_insert_rowid()))
}

pub(crate) fn create_proxy(conn: &Connection, name: &str, host: &str) -> Result<AppId, DbError> {
    conn.execute(
        "INSERT INTO apps (name, kind, host, created_at) VALUES (?1, 'proxy', ?2, ?3)",
        params![name, host, crate::time::now()],
    )?;
    Ok(AppId(conn.last_insert_rowid()))
}

/// The settings an administrator edits.
pub(crate) struct AppChanges {
    pub(crate) name: String,
    pub(crate) enabled: bool,
    pub(crate) all_users: bool,
    pub(crate) skip_consent: bool,
    pub(crate) id_token_alg: Algorithm,
    pub(crate) backchannel_logout_uri: Option<String>,
    pub(crate) host: Option<String>,
    pub(crate) redirect_uris: Vec<String>,
    pub(crate) post_logout_uris: Vec<String>,
    pub(crate) resources: Vec<String>,
    pub(crate) groups: Vec<GroupId>,
}

pub(crate) fn update(
    conn: &mut Connection,
    id: AppId,
    changes: &AppChanges,
) -> Result<(), DbError> {
    let tx = conn.transaction()?;
    tx.execute(
        "UPDATE apps SET name = ?2, enabled = ?3, all_users = ?4, skip_consent = ?5,
                         id_token_alg = ?6, host = CASE WHEN kind = 'proxy' THEN ?7 ELSE NULL END,
                         backchannel_logout_uri = ?8
         WHERE id = ?1",
        params![
            id.0,
            changes.name,
            changes.enabled,
            changes.all_users,
            changes.skip_consent,
            changes.id_token_alg.name(),
            changes.host,
            changes.backchannel_logout_uri
        ],
    )?;
    tx.execute("DELETE FROM app_uris WHERE app_id = ?1", [id.0])?;
    for (purpose, uris) in [
        ("redirect", &changes.redirect_uris),
        ("post_logout", &changes.post_logout_uris),
        ("resource", &changes.resources),
    ] {
        for uri in uris {
            tx.execute(
                "INSERT OR IGNORE INTO app_uris (app_id, purpose, uri) VALUES (?1, ?2, ?3)",
                params![id.0, purpose, uri],
            )?;
        }
    }
    tx.execute("DELETE FROM app_groups WHERE app_id = ?1", [id.0])?;
    for group in &changes.groups {
        tx.execute(
            "INSERT INTO app_groups (app_id, group_id) VALUES (?1, ?2)",
            params![id.0, group.0],
        )?;
    }
    // Consent given for the old settings no longer says what the user agreed to.
    tx.execute("DELETE FROM consents WHERE app_id = ?1", [id.0])?;
    tx.commit()?;
    Ok(())
}

pub(crate) fn groups(conn: &Connection, id: AppId) -> Result<Vec<GroupId>, DbError> {
    let mut statement = conn.prepare("SELECT group_id FROM app_groups WHERE app_id = ?1")?;
    let groups = statement
        .query_map([id.0], |row| row.get(0).map(GroupId))?
        .collect::<Result<_, _>>()?;
    Ok(groups)
}

pub(crate) fn set_secret(conn: &Connection, id: AppId, hash: &[u8]) -> Result<(), DbError> {
    conn.execute(
        "UPDATE apps SET client_secret_hash = ?2 WHERE id = ?1 AND client_secret_hash IS NOT NULL",
        params![id.0, hash],
    )?;
    Ok(())
}

pub(crate) fn delete(conn: &Connection, id: AppId) -> Result<(), DbError> {
    conn.execute("DELETE FROM apps WHERE id = ?1", [id.0])?;
    Ok(())
}
