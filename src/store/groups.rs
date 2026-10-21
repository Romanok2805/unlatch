//! Groups of users. Applications are opened to groups, and group names are sent in the `groups`
//! claim.

use rusqlite::Connection;

use super::DbError;
use super::users::UserId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GroupId(pub(crate) i64);

pub(crate) fn names_for_user(conn: &Connection, user: UserId) -> Result<Vec<String>, DbError> {
    let mut statement = conn.prepare(
        "SELECT groups.name FROM groups JOIN group_members ON group_members.group_id = groups.id
         WHERE group_members.user_id = ?1 ORDER BY groups.name",
    )?;
    let names = statement
        .query_map([user.0], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    Ok(names)
}
