//! Forward authentication: one-time codes and per-host sessions.

use rusqlite::{Connection, OptionalExtension as _, params};

use super::DbError;
use super::apps::{self, AppId, AppRecord};
use super::groups;
use super::sessions::SessionId;
use super::users::{self, User};
use crate::crypto::TokenHash;

pub(crate) fn create_code(
    conn: &Connection,
    hash: &TokenHash,
    session: SessionId,
    app: AppId,
    path: &str,
    state_hash: &[u8; 32],
    expires_at: i64,
) -> Result<(), DbError> {
    conn.execute(
        "DELETE FROM proxy_codes WHERE session_id = ?1 AND app_id = ?2",
        params![session.0, app.0],
    )?;
    conn.execute(
        "INSERT INTO proxy_codes (code_hash, session_id, app_id, path, state_hash, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![hash.0, session.0, app.0, path, state_hash, expires_at],
    )?;
    Ok(())
}

/// A redeemed code: what it was issued for.
pub(crate) struct Redeemed {
    pub(crate) session: SessionId,
    pub(crate) app: AppId,
    pub(crate) path: String,
    pub(crate) state_hash: Vec<u8>,
}

/// Uses up a code, if it is still valid.
pub(crate) fn take_code(
    conn: &Connection,
    hash: &TokenHash,
    now: i64,
) -> Result<Option<Redeemed>, DbError> {
    Ok(conn
        .query_row(
            "DELETE FROM proxy_codes WHERE code_hash = ?1 AND expires_at > ?2
             RETURNING session_id, app_id, path, state_hash",
            params![hash.0, now],
            |row| {
                Ok(Redeemed {
                    session: SessionId(row.get(0)?),
                    app: AppId(row.get(1)?),
                    path: row.get(2)?,
                    state_hash: row.get(3)?,
                })
            },
        )
        .optional()?)
}

pub(crate) fn create_session(
    conn: &Connection,
    hash: &TokenHash,
    session: SessionId,
    app: AppId,
) -> Result<(), DbError> {
    // One per sign-in session and host, so repeated sign-ins can't pile up rows.
    conn.execute(
        "DELETE FROM proxy_sessions WHERE session_id = ?1 AND app_id = ?2",
        params![session.0, app.0],
    )?;
    conn.execute(
        "INSERT INTO proxy_sessions (token_hash, session_id, app_id) VALUES (?1, ?2, ?3)",
        params![hash.0, session.0, app.0],
    )?;
    Ok(())
}

pub(crate) fn delete_session(conn: &Connection, hash: &TokenHash) -> Result<(), DbError> {
    conn.execute("DELETE FROM proxy_sessions WHERE token_hash = ?1", [hash.0])?;
    Ok(())
}

/// Who may pass to `host`: the user of a valid per-host session who still has access, with
/// their groups.
pub(crate) fn check(
    conn: &Connection,
    hash: &TokenHash,
    host: &str,
    now: i64,
) -> Result<Option<(User, Vec<String>)>, DbError> {
    let found = conn
        .query_row(
            &format!(
                "SELECT {}, apps.id AS app_id
                 FROM proxy_sessions
                 JOIN sessions ON sessions.id = proxy_sessions.session_id
                 JOIN users ON users.id = sessions.user_id
                 JOIN apps ON apps.id = proxy_sessions.app_id
                 WHERE proxy_sessions.token_hash = ?1 AND apps.host = ?2
                       AND sessions.expires_at > ?3 AND NOT users.disabled",
                users::COLUMNS
            ),
            params![hash.0, host, now],
            |row| Ok((users::from_row(row)?, AppId(row.get("app_id")?))),
        )
        .optional()?;
    let Some((user, app_id)) = found else {
        return Ok(None);
    };
    let Some(app) = apps::by_id(conn, app_id)? else {
        return Ok(None);
    };
    if !apps::allows(conn, &app, user.id)? {
        return Ok(None);
    }
    let groups = groups::names_for_user(conn, user.id)?;
    Ok(Some((user, groups)))
}

/// The forward-auth application for a host.
pub(crate) fn app_for_host(conn: &Connection, host: &str) -> Result<Option<AppRecord>, DbError> {
    let id: Option<i64> = conn
        .query_row(
            "SELECT id FROM apps WHERE host = ?1 AND kind = 'proxy'",
            [host],
            |row| row.get(0),
        )
        .optional()?;
    id.map_or(Ok(None), |id| apps::by_id(conn, AppId(id)))
}
