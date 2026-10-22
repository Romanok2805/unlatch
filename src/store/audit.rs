//! The audit log: who changed what, and every sign-in.

use rusqlite::{Connection, params};

use super::DbError;

/// What was done. The log stores it in English, so it reads the same whatever language was in
/// use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    SignIn,
    ChangePassword,
    SetPasswordFromLink,
    TurnOnTwoFactor,
    TurnOffTwoFactor,
    AddPasskey,
    RemovePasskey,
    CreateAdministrator,
    CreateApplication,
    ChangeApplication,
    DeleteApplication,
    IssueClientSecret,
    InviteUser,
    ChangeUser,
    DeleteUser,
    CreatePasswordLink,
    ResetTwoFactor,
    RemovePasskeys,
    EndSessions,
    EndSession,
    CreateGroup,
    RenameGroup,
    DeleteGroup,
    ChangeSettings,
    ChangeProvider,
    DeleteProvider,
    LinkProvider,
    UnlinkProvider,
    CreateUserFromProvider,
}

impl Action {
    const ALL: [Self; 29] = [
        Self::SignIn,
        Self::ChangePassword,
        Self::SetPasswordFromLink,
        Self::TurnOnTwoFactor,
        Self::TurnOffTwoFactor,
        Self::AddPasskey,
        Self::RemovePasskey,
        Self::CreateAdministrator,
        Self::CreateApplication,
        Self::ChangeApplication,
        Self::DeleteApplication,
        Self::IssueClientSecret,
        Self::InviteUser,
        Self::ChangeUser,
        Self::DeleteUser,
        Self::CreatePasswordLink,
        Self::ResetTwoFactor,
        Self::RemovePasskeys,
        Self::EndSessions,
        Self::EndSession,
        Self::CreateGroup,
        Self::RenameGroup,
        Self::DeleteGroup,
        Self::ChangeSettings,
        Self::ChangeProvider,
        Self::DeleteProvider,
        Self::LinkProvider,
        Self::UnlinkProvider,
        Self::CreateUserFromProvider,
    ];

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::SignIn => "sign in",
            Self::ChangePassword => "change password",
            Self::SetPasswordFromLink => "set password from link",
            Self::TurnOnTwoFactor => "turn on two-factor sign-in",
            Self::TurnOffTwoFactor => "turn off two-factor sign-in",
            Self::AddPasskey => "add passkey",
            Self::RemovePasskey => "remove passkey",
            Self::CreateAdministrator => "create administrator",
            Self::CreateApplication => "create application",
            Self::ChangeApplication => "change application",
            Self::DeleteApplication => "delete application",
            Self::IssueClientSecret => "issue client secret",
            Self::InviteUser => "invite user",
            Self::ChangeUser => "change user",
            Self::DeleteUser => "delete user",
            Self::CreatePasswordLink => "create password link",
            Self::ResetTwoFactor => "reset two-factor sign-in",
            Self::RemovePasskeys => "remove passkeys",
            Self::EndSessions => "end sessions",
            Self::EndSession => "end session",
            Self::CreateGroup => "create group",
            Self::RenameGroup => "rename group",
            Self::DeleteGroup => "delete group",
            Self::ChangeSettings => "change settings",
            Self::ChangeProvider => "change sign-in provider",
            Self::DeleteProvider => "delete sign-in provider",
            Self::LinkProvider => "link sign-in provider",
            Self::UnlinkProvider => "unlink sign-in provider",
            Self::CreateUserFromProvider => "create user from provider",
        }
    }

    /// The action a stored entry names, if it is still one we know.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|action| action.as_str() == text)
    }
}

pub(crate) struct Entry<'a> {
    /// The user name of whoever acted, or a description such as "setup token".
    pub(crate) actor: &'a str,
    pub(crate) action: Action,
    pub(crate) target: &'a str,
    pub(crate) ip: &'a str,
}

pub(crate) fn record(conn: &Connection, entry: &Entry<'_>) -> Result<(), DbError> {
    conn.execute(
        "INSERT INTO audit_log (at, actor, action, target, ip) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            crate::time::now(),
            entry.actor,
            entry.action.as_str(),
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

#[cfg(test)]
mod tests {
    use super::Action;

    #[test]
    fn every_action_reads_back_from_the_log() {
        for action in Action::ALL {
            assert_eq!(Action::parse(action.as_str()), Some(action));
        }
    }
}
