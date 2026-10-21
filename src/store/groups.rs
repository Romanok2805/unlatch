//! Groups of users. Applications are opened to groups, and group names are sent in the `groups`
//! claim.

use rusqlite::{Connection, params};

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

pub(crate) struct Group {
    pub(crate) id: GroupId,
    pub(crate) name: String,
    pub(crate) members: i64,
}

pub(crate) fn list(conn: &Connection) -> Result<Vec<Group>, DbError> {
    let mut statement = conn.prepare(
        "SELECT groups.id, groups.name,
                (SELECT count(*) FROM group_members WHERE group_members.group_id = groups.id)
         FROM groups ORDER BY groups.name",
    )?;
    let groups = statement
        .query_map([], |row| {
            Ok(Group {
                id: GroupId(row.get(0)?),
                name: row.get(1)?,
                members: row.get(2)?,
            })
        })?
        .collect::<Result<_, _>>()?;
    Ok(groups)
}

pub(crate) fn create(conn: &Connection, name: &str) -> Result<GroupId, DbError> {
    conn.execute("INSERT INTO groups (name) VALUES (?1)", [name])?;
    Ok(GroupId(conn.last_insert_rowid()))
}

pub(crate) fn rename(conn: &Connection, id: GroupId, name: &str) -> Result<(), DbError> {
    conn.execute(
        "UPDATE groups SET name = ?2 WHERE id = ?1",
        params![id.0, name],
    )?;
    Ok(())
}

pub(crate) fn delete(conn: &Connection, id: GroupId) -> Result<(), DbError> {
    conn.execute("DELETE FROM groups WHERE id = ?1", [id.0])?;
    Ok(())
}

/// The user names of a group's members.
pub(crate) fn members(conn: &Connection, id: GroupId) -> Result<Vec<String>, DbError> {
    let mut statement = conn.prepare(
        "SELECT users.username FROM users JOIN group_members ON group_members.user_id = users.id
         WHERE group_members.group_id = ?1 ORDER BY users.username",
    )?;
    let names = statement
        .query_map([id.0], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    Ok(names)
}
