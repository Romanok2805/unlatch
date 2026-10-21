//! The audit log: who changed what, and every sign-in.

use rusqlite::{Connection, params};

use super::DbError;

pub(crate) struct Entry<'a> {
    /// The user name of whoever acted, or a description such as "setup token".
    pub(crate) actor: &'a str,
    pub(crate) action: &'a str,
    pub(crate) target: &'a str,
    pub(crate) ip: &'a str,
}

pub(crate) fn record(conn: &Connection, entry: &Entry<'_>) -> Result<(), DbError> {
    conn.execute(
        "INSERT INTO audit_log (at, actor, action, target, ip) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            crate::time::now(),
            entry.actor,
            entry.action,
            entry.target,
            entry.ip
        ],
    )?;
    Ok(())
}

pub(crate) struct Recorded {
    pub(crate) at: i64,
    pub(crate) actor: String,
    pub(crate) action: String,
    pub(crate) target: String,
    pub(crate) ip: String,
}

pub(crate) fn latest(conn: &Connection, limit: i64) -> Result<Vec<Recorded>, DbError> {
    let mut statement = conn
        .prepare("SELECT at, actor, action, target, ip FROM audit_log ORDER BY id DESC LIMIT ?1")?;
    let entries = statement
        .query_map([limit], |row| {
            Ok(Recorded {
                at: row.get(0)?,
                actor: row.get(1)?,
                action: row.get(2)?,
                target: row.get(3)?,
                ip: row.get(4)?,
            })
        })?
        .collect::<Result<_, _>>()?;
    Ok(entries)
}
