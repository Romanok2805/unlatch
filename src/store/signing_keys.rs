//! Private keys that sign tokens, sealed with a key derived from the master key.

use rusqlite::{Connection, params};

use super::DbError;

pub(crate) struct StoredKey {
    pub(crate) kid: String,
    pub(crate) alg: String,
    /// PKCS #8, sealed with the kid as context.
    pub(crate) private_key: Vec<u8>,
    pub(crate) created_at: i64,
    pub(crate) active_from: i64,
    pub(crate) retired_at: Option<i64>,
}

pub(crate) fn all(conn: &Connection) -> Result<Vec<StoredKey>, DbError> {
    let mut statement = conn.prepare(
        "SELECT kid, alg, private_key, created_at, active_from, retired_at
         FROM signing_keys ORDER BY created_at",
    )?;
    let keys = statement
        .query_map([], |row| {
            Ok(StoredKey {
                kid: row.get(0)?,
                alg: row.get(1)?,
                private_key: row.get(2)?,
                created_at: row.get(3)?,
                active_from: row.get(4)?,
                retired_at: row.get(5)?,
            })
        })?
        .collect::<Result<_, _>>()?;
    Ok(keys)
}

pub(crate) fn insert(conn: &Connection, key: &StoredKey) -> Result<(), DbError> {
    conn.execute(
        "INSERT INTO signing_keys (kid, alg, private_key, created_at, active_from, retired_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            key.kid,
            key.alg,
            key.private_key,
            key.created_at,
            key.active_from,
            key.retired_at
        ],
    )?;
    Ok(())
}

pub(crate) fn retire(conn: &Connection, kid: &str, at: i64) -> Result<(), DbError> {
    conn.execute(
        "UPDATE signing_keys SET retired_at = ?2 WHERE kid = ?1 AND retired_at IS NULL",
        params![kid, at],
    )?;
    Ok(())
}

/// Deletes keys retired before `cutoff`; no token they signed is still valid.
pub(crate) fn delete_retired_before(conn: &Connection, cutoff: i64) -> Result<(), DbError> {
    conn.execute("DELETE FROM signing_keys WHERE retired_at < ?1", [cutoff])?;
    Ok(())
}
