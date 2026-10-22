//! Passkeys of users; see [`crate::crypto::passkey`].

use rusqlite::{Connection, OptionalExtension as _, Row, params};

use super::DbError;
use super::users::UserId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PasskeyId(pub(crate) i64);

pub(crate) struct Passkey {
    pub(crate) id: PasskeyId,
    pub(crate) user: UserId,
    pub(crate) credential_id: Vec<u8>,
    /// A `COSE_Key`, as the authenticator sent it.
    pub(crate) public_key: Vec<u8>,
    pub(crate) sign_count: u32,
    /// Space-separated, as `getTransports()` names them.
    pub(crate) transports: String,
    pub(crate) name: String,
    pub(crate) created_at: i64,
    pub(crate) last_used_at: Option<i64>,
}

const COLUMNS: &str = "id, user_id, credential_id, public_key, sign_count, transports, name, \
    created_at, last_used_at";

fn from_row(row: &Row<'_>) -> rusqlite::Result<Passkey> {
    Ok(Passkey {
        id: PasskeyId(row.get(0)?),
        user: UserId(row.get(1)?),
        credential_id: row.get(2)?,
        public_key: row.get(3)?,
        // No authenticator counts past u32; a larger number refuses every answer.
        sign_count: u32::try_from(row.get::<_, i64>(4)?).unwrap_or(u32::MAX),
        transports: row.get(5)?,
        name: row.get(6)?,
        created_at: row.get(7)?,
        last_used_at: row.get(8)?,
    })
}

pub(crate) struct NewPasskey<'a> {
    pub(crate) user: UserId,
    pub(crate) credential_id: &'a [u8],
    pub(crate) public_key: &'a [u8],
    pub(crate) sign_count: u32,
    pub(crate) transports: &'a str,
    pub(crate) name: &'a str,
}

/// Adds a passkey, unless the user already has `max` of them. A credential ID that is already
/// stored is a constraint violation.
pub(crate) fn add(conn: &Connection, new: &NewPasskey<'_>, max: i64) -> Result<bool, DbError> {
    if count(conn, new.user)? >= max {
        return Ok(false);
    }
    conn.execute(
        "INSERT INTO passkeys (user_id, credential_id, public_key, sign_count, transports, name,
                               created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            new.user.0,
            new.credential_id,
            new.public_key,
            i64::from(new.sign_count),
            new.transports,
            new.name,
            crate::time::now()
        ],
    )?;
    Ok(true)
}

/// The user's passkeys, oldest first.
pub(crate) fn of_user(conn: &Connection, user: UserId) -> Result<Vec<Passkey>, DbError> {
    let mut statement = conn.prepare(&format!(
        "SELECT {COLUMNS} FROM passkeys WHERE user_id = ?1 ORDER BY id"
    ))?;
    let passkeys = statement
        .query_map([user.0], from_row)?
        .collect::<Result<_, _>>()?;
    Ok(passkeys)
}

pub(crate) fn by_credential_id(conn: &Connection, id: &[u8]) -> Result<Option<Passkey>, DbError> {
    Ok(conn
        .query_row(
            &format!("SELECT {COLUMNS} FROM passkeys WHERE credential_id = ?1"),
            [id],
            from_row,
        )
        .optional()?)
}

pub(crate) fn count(conn: &Connection, user: UserId) -> Result<i64, DbError> {
    Ok(conn.query_row(
        "SELECT count(*) FROM passkeys WHERE user_id = ?1",
        [user.0],
        |row| row.get(0),
    )?)
}

/// Records a sign-in with the passkey and its new counter, unless the counter is no longer
/// ahead of the stored one. Checking in the same statement means two requests racing with one
/// answer can't both succeed.
pub(crate) fn record_use(
    conn: &Connection,
    id: PasskeyId,
    sign_count: u32,
    now: i64,
) -> Result<bool, DbError> {
    let changed = conn.execute(
        "UPDATE passkeys SET sign_count = ?2, last_used_at = ?3
         WHERE id = ?1 AND (sign_count < ?2 OR ?2 = 0)",
        params![id.0, i64::from(sign_count), now],
    )?;
    Ok(changed == 1)
}

/// Deletes one of the user's passkeys. Returns whether it existed.
pub(crate) fn delete(conn: &Connection, user: UserId, id: PasskeyId) -> Result<bool, DbError> {
    let deleted = conn.execute(
        "DELETE FROM passkeys WHERE id = ?1 AND user_id = ?2",
        params![id.0, user.0],
    )?;
    Ok(deleted == 1)
}

pub(crate) fn delete_all(conn: &Connection, user: UserId) -> Result<(), DbError> {
    conn.execute("DELETE FROM passkeys WHERE user_id = ?1", [user.0])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Db;

    #[tokio::test]
    async fn passkeys_are_limited_unique_and_their_counters_only_go_up() {
        let db = Db::open_in_memory().unwrap();
        db.run(|conn| {
            conn.execute_batch(
                "INSERT INTO users (id, username, display_name, created_at)
                     VALUES (1, 'ann', 'Ann', 0), (2, 'bob', 'Bob', 0);",
            )?;
            let new = |user, credential_id| NewPasskey {
                user: UserId(user),
                credential_id,
                public_key: b"key",
                sign_count: 5,
                transports: "internal",
                name: "Phone",
            };
            assert!(add(conn, &new(1, b"a"), 2)?);
            assert!(add(conn, &new(1, b"b"), 2)?);
            assert!(!add(conn, &new(1, b"c"), 2)?);
            assert!(
                add(conn, &new(2, b"a"), 2)
                    .unwrap_err()
                    .is_constraint_violation()
            );

            let id = by_credential_id(conn, b"a")?.unwrap().id;
            assert!(!record_use(conn, id, 5, 10)?);
            assert!(record_use(conn, id, 6, 10)?);
            assert_eq!(of_user(conn, UserId(1))?[0].last_used_at, Some(10));

            // Only the owner can delete a passkey.
            assert!(!delete(conn, UserId(2), id)?);
            assert!(delete(conn, UserId(1), id)?);
            Ok(())
        })
        .await
        .unwrap();
    }
}
