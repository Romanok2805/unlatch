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
