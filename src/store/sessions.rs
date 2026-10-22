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
    /// 0 when a code the account has wasn't entered.
    pub(crate) verified_at: i64,
    pub(crate) expires_at: i64,
    pub(crate) ip: &'a str,
    pub(crate) user_agent: &'a str,
}

pub(crate) fn create(conn: &Connection, session: &NewSession<'_>) -> Result<SessionId, DbError> {
    conn.execute(
        "INSERT INTO sessions (token_hash, public_id, user_id, amr, auth_time, verified_at,
                               last_seen_at, expires_at, ip, user_agent)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?5, ?7, ?8, ?9)",
        params![
            session.token_hash.0,
            session.public_id,
            session.user_id.0,
            session.amr,
            session.now,
            session.verified_at,
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

pub(crate) struct SessionSummary {
    pub(crate) id: SessionId,
    pub(crate) username: String,
    pub(crate) ip: String,
    pub(crate) user_agent: String,
    pub(crate) auth_time: i64,
    pub(crate) last_seen_at: i64,
}

/// Active sessions, newest activity first; of one user, or of everyone.
pub(crate) fn list(
    conn: &Connection,
    user: Option<UserId>,
    now: i64,
) -> Result<Vec<SessionSummary>, DbError> {
    let mut statement = conn.prepare(
        "SELECT sessions.id, users.username, sessions.ip, sessions.user_agent, sessions.auth_time,
                sessions.last_seen_at
         FROM sessions JOIN users ON users.id = sessions.user_id
         WHERE sessions.expires_at > ?1 AND (?2 IS NULL OR sessions.user_id = ?2)
         ORDER BY sessions.last_seen_at DESC",
    )?;
    let sessions = statement
        .query_map(params![now, user.map(|user| user.0)], |row| {
            Ok(SessionSummary {
                id: SessionId(row.get(0)?),
                username: row.get(1)?,
                ip: row.get(2)?,
                user_agent: row.get(3)?,
                auth_time: row.get(4)?,
                last_seen_at: row.get(5)?,
            })
        })?
        .collect::<Result<_, _>>()?;
    Ok(sessions)
}

/// The sessions of a user, except one.
pub(crate) fn ids_of_user(
    conn: &Connection,
    user: UserId,
    except: Option<SessionId>,
) -> Result<Vec<SessionId>, DbError> {
    let mut statement =
        conn.prepare("SELECT id FROM sessions WHERE user_id = ?1 AND id IS NOT ?2")?;
    let ids = statement
        .query_map(params![user.0, except.map(|id| id.0)], |row| {
            row.get(0).map(SessionId)
        })?
        .collect::<Result<_, _>>()?;
    Ok(ids)
}

/// An application to tell that a session ended (OpenID Connect Back-Channel Logout).
pub(crate) struct LogoutTarget {
    pub(crate) client_id: String,
    pub(crate) uri: String,
    pub(crate) user: UserId,
    pub(crate) sid: String,
}

/// The applications that received tokens in a session and asked to hear about its end.
pub(crate) fn logout_targets(
    conn: &Connection,
    id: SessionId,
) -> Result<Vec<LogoutTarget>, DbError> {
    let mut statement = conn.prepare(
        "SELECT DISTINCT apps.client_id, apps.backchannel_logout_uri, sessions.user_id, sessions.public_id
         FROM session_apps
         JOIN apps ON apps.id = session_apps.app_id
         JOIN sessions ON sessions.id = session_apps.session_id
         WHERE session_apps.session_id = ?1 AND apps.enabled
               AND apps.backchannel_logout_uri IS NOT NULL",
    )?;
    let targets = statement
        .query_map([id.0], |row| {
            Ok(LogoutTarget {
                client_id: row.get(0)?,
                uri: row.get(1)?,
                user: UserId(row.get(2)?),
                sid: row.get(3)?,
            })
        })?
        .collect::<Result<_, _>>()?;
    Ok(targets)
}
