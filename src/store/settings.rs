//! Instance settings that the administrator changes in the web interface.

use rusqlite::{Connection, OptionalExtension as _, params};

use super::DbError;

pub(crate) fn get(conn: &Connection, name: &str) -> Result<Option<String>, DbError> {
    Ok(conn
        .query_row(
            "SELECT value FROM settings WHERE name = ?1",
            [name],
            |row| row.get(0),
        )
        .optional()?)
}

pub(crate) fn set(conn: &Connection, name: &str, value: &str) -> Result<(), DbError> {
    conn.execute(
        "INSERT INTO settings (name, value) VALUES (?1, ?2)
         ON CONFLICT (name) DO UPDATE SET value = excluded.value",
        params![name, value],
    )?;
    Ok(())
}

pub(crate) fn remove(conn: &Connection, name: &str) -> Result<(), DbError> {
    conn.execute("DELETE FROM settings WHERE name = ?1", [name])?;
    Ok(())
}
