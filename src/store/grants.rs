//! Authorization codes and the grants they turn into.

use rusqlite::{Connection, OptionalExtension as _, params};

use super::DbError;
use super::apps::AppId;
use super::sessions::SessionId;
use crate::crypto::TokenHash;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GrantId(pub(crate) i64);

pub(crate) struct NewCode<'a> {
    pub(crate) hash: TokenHash,
    pub(crate) app: AppId,
    pub(crate) session: SessionId,
    pub(crate) redirect_uri: &'a str,
    pub(crate) scope: &'a str,
    pub(crate) nonce: Option<&'a str>,
    pub(crate) code_challenge: &'a str,
    pub(crate) resource: Option<&'a str>,
    pub(crate) dpop_jkt: Option<&'a str>,
    pub(crate) expires_at: i64,
}

/// Stores a code. Unredeemed codes of the same session and client are replaced, so they can't
/// pile up; redeemed ones stay until they expire, to recognise a second use.
pub(crate) fn create_code(conn: &Connection, code: &NewCode<'_>) -> Result<(), DbError> {
    conn.execute(
        "DELETE FROM codes WHERE session_id = ?1 AND app_id = ?2 AND grant_id IS NULL",
        params![code.session.0, code.app.0],
    )?;
    conn.execute(
        "INSERT INTO codes (code_hash, app_id, session_id, redirect_uri, scope, nonce,
                            code_challenge, resource, dpop_jkt, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            code.hash.0,
            code.app.0,
            code.session.0,
            code.redirect_uri,
            code.scope,
            code.nonce,
            code.code_challenge,
            code.resource,
            code.dpop_jkt,
            code.expires_at
        ],
    )?;
    Ok(())
}

pub(crate) struct Code {
    pub(crate) app: AppId,
    pub(crate) session: SessionId,
    pub(crate) redirect_uri: String,
    pub(crate) scope: String,
    pub(crate) nonce: Option<String>,
    pub(crate) challenge: String,
    pub(crate) resource: Option<String>,
    pub(crate) dpop_jkt: Option<String>,
    pub(crate) expires_at: i64,
    /// Set once the code was redeemed.
    pub(crate) grant: Option<GrantId>,
}

pub(crate) fn find_code(conn: &Connection, hash: &TokenHash) -> Result<Option<Code>, DbError> {
    Ok(conn
        .query_row(
            "SELECT app_id, session_id, redirect_uri, scope, nonce, code_challenge, resource,
                    expires_at, grant_id, dpop_jkt
             FROM codes WHERE code_hash = ?1",
            [hash.0],
            |row| {
                Ok(Code {
                    app: AppId(row.get(0)?),
                    session: SessionId(row.get(1)?),
                    redirect_uri: row.get(2)?,
                    scope: row.get(3)?,
                    nonce: row.get(4)?,
                    challenge: row.get(5)?,
                    resource: row.get(6)?,
                    expires_at: row.get(7)?,
                    grant: row.get::<_, Option<i64>>(8)?.map(GrantId),
                    dpop_jkt: row.get(9)?,
                })
            },
        )
        .optional()?)
}

/// Marks a code redeemed. The row stays until it expires, so a second use is recognised.
pub(crate) fn mark_redeemed(
    conn: &Connection,
    hash: &TokenHash,
    grant: GrantId,
) -> Result<(), DbError> {
    conn.execute(
        "UPDATE codes SET grant_id = ?2 WHERE code_hash = ?1",
        params![hash.0, grant.0],
    )?;
    Ok(())
}

pub(crate) struct Grant {
    pub(crate) id: GrantId,
    pub(crate) session: SessionId,
    pub(crate) app: AppId,
    pub(crate) scope: String,
    pub(crate) resource: Option<String>,
    /// The DPoP key refreshing needs, if the grant is bound to one.
    pub(crate) dpop_jkt: Option<String>,
    pub(crate) generation: i64,
}

/// Creates a grant, and remembers that the application took part in the session.
pub(crate) fn create(
    conn: &Connection,
    session: SessionId,
    app: AppId,
    scope: &str,
    resource: Option<&str>,
    dpop_jkt: Option<&str>,
) -> Result<GrantId, DbError> {
    conn.execute(
        "INSERT OR IGNORE INTO session_apps (session_id, app_id) VALUES (?1, ?2)",
        params![session.0, app.0],
    )?;
    conn.execute(
        "INSERT INTO grants (session_id, app_id, scope, resource, dpop_jkt, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            session.0,
            app.0,
            scope,
            resource,
            dpop_jkt,
            crate::time::now()
        ],
    )?;
    Ok(GrantId(conn.last_insert_rowid()))
}

pub(crate) fn find(conn: &Connection, id: GrantId) -> Result<Option<Grant>, DbError> {
    Ok(conn
        .query_row(
            "SELECT id, session_id, app_id, scope, resource, generation, dpop_jkt
             FROM grants WHERE id = ?1",
            [id.0],
            |row| {
                Ok(Grant {
                    id: GrantId(row.get(0)?),
                    session: SessionId(row.get(1)?),
                    app: AppId(row.get(2)?),
                    scope: row.get(3)?,
                    resource: row.get(4)?,
                    generation: row.get(5)?,
                    dpop_jkt: row.get(6)?,
                })
            },
        )
        .optional()?)
}

/// Moves a grant to its next generation if it is still at `expected`. Two refreshes racing with
/// the same token can't both succeed.
pub(crate) fn advance(conn: &Connection, id: GrantId, expected: i64) -> Result<bool, DbError> {
    let changed = conn.execute(
        "UPDATE grants SET generation = generation + 1 WHERE id = ?1 AND generation = ?2",
        params![id.0, expected],
    )?;
    Ok(changed == 1)
}

pub(crate) fn delete(conn: &Connection, id: GrantId) -> Result<(), DbError> {
    conn.execute("DELETE FROM grants WHERE id = ?1", [id.0])?;
    Ok(())
}
