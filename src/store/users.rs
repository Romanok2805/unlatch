//! Accounts.

use rusqlite::{Connection, OptionalExtension as _, Row, params};

use super::DbError;
use crate::crypto::password::PasswordHash;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UserId(pub(crate) i64);

/// A user name: lowercase ASCII letters, digits, dots, dashes and underscores, starting with a
/// letter or digit. With one case and no look-alike characters, two different names can't be
/// mistaken for each other on screen or collide after normalisation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Username(String);

impl Username {
    pub(crate) const MAX_LEN: usize = 64;

    pub(crate) fn parse(text: &str) -> Option<Self> {
        let valid = text.len() <= Self::MAX_LEN
            && text.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
            && text.chars().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-' | '_')
            });
        valid.then(|| Self(text.to_owned()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

pub(crate) struct User {
    pub(crate) id: UserId,
    pub(crate) username: String,
    pub(crate) display_name: String,
    pub(crate) email: Option<String>,
    pub(crate) email_verified: bool,
    pub(crate) password_hash: Option<PasswordHash>,
    /// Sealed; see `auth::totp`.
    pub(crate) totp_secret: Option<Vec<u8>>,
    pub(crate) totp_last_step: Option<i64>,
    pub(crate) is_admin: bool,
    pub(crate) disabled: bool,
}

const COLUMNS: &str = "id, username, display_name, email, email_verified, password_hash, \
                       totp_secret, totp_last_step, is_admin, disabled";

fn from_row(row: &Row<'_>) -> rusqlite::Result<User> {
    Ok(User {
        id: UserId(row.get(0)?),
        username: row.get(1)?,
        display_name: row.get(2)?,
        email: row.get(3)?,
        email_verified: row.get(4)?,
        password_hash: row
            .get::<_, Option<String>>(5)?
            .map(PasswordHash::from_stored),
        totp_secret: row.get(6)?,
        totp_last_step: row.get(7)?,
        is_admin: row.get(8)?,
        disabled: row.get(9)?,
    })
}

pub(crate) struct NewUser<'a> {
    pub(crate) username: &'a Username,
    pub(crate) display_name: &'a str,
    pub(crate) email: Option<&'a str>,
    pub(crate) is_admin: bool,
}

pub(crate) fn create(conn: &Connection, user: &NewUser<'_>) -> Result<UserId, DbError> {
    conn.execute(
        "INSERT INTO users (username, display_name, email, is_admin, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            user.username.as_str(),
            user.display_name,
            user.email,
            user.is_admin,
            crate::time::now()
        ],
    )?;
    Ok(UserId(conn.last_insert_rowid()))
}

pub(crate) fn by_id(conn: &Connection, id: UserId) -> Result<Option<User>, DbError> {
    Ok(conn
        .query_row(
            &format!("SELECT {COLUMNS} FROM users WHERE id = ?1"),
            [id.0],
            from_row,
        )
        .optional()?)
}

pub(crate) fn by_username(conn: &Connection, username: &str) -> Result<Option<User>, DbError> {
    Ok(conn
        .query_row(
            &format!("SELECT {COLUMNS} FROM users WHERE username = ?1"),
            [username],
            from_row,
        )
        .optional()?)
}

pub(crate) fn count(conn: &Connection) -> Result<i64, DbError> {
    Ok(conn.query_row("SELECT count(*) FROM users", [], |row| row.get(0))?)
}

pub(crate) fn set_password(
    conn: &Connection,
    id: UserId,
    hash: &PasswordHash,
) -> Result<(), DbError> {
    conn.execute(
        "UPDATE users SET password_hash = ?2 WHERE id = ?1",
        params![id.0, hash.as_str()],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Db;

    #[test]
    fn user_names_have_one_spelling() {
        for good in ["anna", "a", "anna.k", "anna_k-2", "9lives"] {
            assert!(Username::parse(good).is_some(), "{good}");
        }
        for bad in [
            "",
            "Anna",
            ".anna",
            "-anna",
            "anna k",
            "аnna",
            "anna@lan",
            &"a".repeat(65),
        ] {
            assert!(Username::parse(bad).is_none(), "{bad}");
        }
    }

    #[tokio::test]
    async fn names_are_unique() {
        let db = Db::open_in_memory().unwrap();
        let result = db
            .run(|conn| {
                let name = Username::parse("anna").unwrap();
                let new = NewUser {
                    username: &name,
                    display_name: "Anna",
                    email: None,
                    is_admin: true,
                };
                let id = create(conn, &new)?;
                assert_eq!(by_username(conn, "anna")?.unwrap().id, id);
                create(conn, &new).map(|_| ())
            })
            .await;
        assert!(result.unwrap_err().is_constraint_violation());
    }
}
