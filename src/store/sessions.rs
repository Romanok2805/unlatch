//! Sign-in sessions of browsers.

use rusqlite::{Connection, OptionalExtension as _, params};

use super::DbError;
use super::users::{self, User, UserId};
use crate::crypto::TokenHash;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionId(pub(crate) i64);

pub(crate) struct NewSession<'a> {
    pub(crate) token_hash: TokenHash,
    pub(crate) public_id: &'a str,
    pub(crate) user_id: UserId,
    pub(crate) amr: &'a str,
    pub(crate) now: i64,
    pub(crate) expires_at: i64,
    pub(crate) ip: &'a str,
    pub(crate) user_agent: &'a str,
}

pub(crate) fn create(conn: &Connection, session: &NewSession<'_>) -> Result<SessionId, DbError> {
    conn.execute(
        "INSERT INTO sessions (token_hash, public_id, user_id, amr, auth_time, verified_at,
                               last_seen_at, expires_at, ip, user_agent)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?5, ?6, ?7, ?8)",
        params![
            session.token_hash.0,
            session.public_id,
            session.user_id.0,
            session.amr,
            session.now,
            session.expires_at,
            session.ip,
            session.user_agent
        ],
    )?;
    Ok(SessionId(conn.last_insert_rowid()))
}

pub(crate) struct ActiveSession {
    pub(crate) id: SessionId,
    pub(crate) public_id: String,
    pub(crate) user: User,
    pub(crate) amr: String,
    pub(crate) auth_time: i64,
    pub(crate) verified_at: i64,
    pub(crate) last_seen_at: i64,
}

/// The session a token belongs to, unless it has expired or its user is disabled.
pub(crate) fn find(
    conn: &Connection,
    token_hash: &TokenHash,
    now: i64,
) -> Result<Option<ActiveSession>, DbError> {
    find_where(conn, "sessions.token_hash = ?1", &token_hash.0, now)
}

/// A session by its row, with the same conditions as [`find`].
pub(crate) fn by_id(
    conn: &Connection,
    id: SessionId,
    now: i64,
) -> Result<Option<ActiveSession>, DbError> {
    find_where(conn, "sessions.id = ?1", &id.0, now)
}

/// A session by its `sid`, with the same conditions as [`find`].
pub(crate) fn by_public_id(
    conn: &Connection,
    public_id: &str,
    now: i64,
) -> Result<Option<ActiveSession>, DbError> {
    find_where(conn, "sessions.public_id = ?1", &public_id, now)
}

fn find_where(
    conn: &Connection,
    condition: &str,
    key: &dyn rusqlite::ToSql,
    now: i64,
) -> Result<Option<ActiveSession>, DbError> {
    let sql = format!(
        "SELECT {}, sessions.id AS session_id, sessions.public_id, sessions.amr,
                sessions.auth_time, sessions.verified_at, sessions.last_seen_at
         FROM sessions JOIN users ON users.id = sessions.user_id
         WHERE {condition} AND sessions.expires_at > ?2 AND NOT users.disabled",
        users::COLUMNS
    );
    Ok(conn
        .query_row(&sql, params![key, now], |row| {
            Ok(ActiveSession {
                user: users::from_row(row)?,
                id: SessionId(row.get("session_id")?),
                public_id: row.get("public_id")?,
                amr: row.get("amr")?,
                auth_time: row.get("auth_time")?,
                verified_at: row.get("verified_at")?,
                last_seen_at: row.get("last_seen_at")?,
            })
        })
        .optional()?)
}

/// Records activity and moves the idle deadline.
pub(crate) fn touch(
    conn: &Connection,
    id: SessionId,
    now: i64,
    expires_at: i64,
) -> Result<(), DbError> {
    conn.execute(
        "UPDATE sessions SET last_seen_at = ?2, expires_at = ?3 WHERE id = ?1",
        params![id.0, now, expires_at],
    )?;
    Ok(())
}

/// Records that the second factor was just entered again.
pub(crate) fn mark_verified(conn: &Connection, id: SessionId, now: i64) -> Result<(), DbError> {
    conn.execute(
        "UPDATE sessions SET verified_at = ?2 WHERE id = ?1",
        params![id.0, now],
    )?;
    Ok(())
}

/// Ends a session. Its codes, grants and forward-auth sessions go with it.
pub(crate) fn delete(conn: &Connection, id: SessionId) -> Result<(), DbError> {
    conn.execute("DELETE FROM sessions WHERE id = ?1", [id.0])?;
    Ok(())
}

pub(crate) fn delete_for_user(
    conn: &Connection,
    user_id: UserId,
    except: Option<SessionId>,
) -> Result<(), DbError> {
    conn.execute(
        "DELETE FROM sessions WHERE user_id = ?1 AND id IS NOT ?2",
        params![user_id.0, except.map(|id| id.0)],
    )?;
    Ok(())
}
