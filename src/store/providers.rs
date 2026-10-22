//! Outside sign-in providers, and the links between their accounts and ours.

use rusqlite::{Connection, OptionalExtension as _, Row, params};

use super::DbError;
use super::users::UserId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProviderId(pub(crate) i64);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderKind {
    Oidc,
    /// GitHub speaks OAuth 2.0 without OpenID Connect; identities come from its API.
    Github,
}

impl ProviderKind {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Oidc => "oidc",
            Self::Github => "github",
        }
    }
}

#[derive(Clone)]
pub(crate) struct Provider {
    pub(crate) id: ProviderId,
    /// Part of the callback URL registered at the provider.
    pub(crate) slug: String,
    pub(crate) name: String,
    pub(crate) kind: ProviderKind,
    pub(crate) issuer: Option<String>,
    pub(crate) client_id: String,
    /// Sealed, with the context `web::providers::secret_context` gives; [`save`] leaves it alone
    /// and [`set_secret`] stores it.
    pub(crate) client_secret: Vec<u8>,
    /// Email domains whose verified users get an account on first sign-in.
    pub(crate) auto_create_domains: Vec<String>,
    pub(crate) enabled: bool,
    /// Accounts with two-factor sign-in aren't asked for their code after signing in here.
    pub(crate) skip_code: bool,
}

/// Google is an OpenID Connect provider like any other, except for its logo and its `hd` claim.
pub(crate) const GOOGLE_ISSUER: &str = "https://accounts.google.com";

impl Provider {
    pub(crate) fn is_google(&self) -> bool {
        self.issuer.as_deref() == Some(GOOGLE_ISSUER)
    }
}

const COLUMNS: &str = "id, slug, name, kind, issuer, client_id, client_secret, \
                       auto_create_domains, enabled, skip_code";

fn from_row(row: &Row<'_>) -> rusqlite::Result<Provider> {
    let kind: String = row.get(3)?;
    let domains: String = row.get(7)?;
    Ok(Provider {
        id: ProviderId(row.get(0)?),
        slug: row.get(1)?,
        name: row.get(2)?,
        kind: if kind == "github" {
            ProviderKind::Github
        } else {
            ProviderKind::Oidc
        },
        issuer: row.get(4)?,
        client_id: row.get(5)?,
        client_secret: row.get(6)?,
        auto_create_domains: domains.split_whitespace().map(str::to_owned).collect(),
        enabled: row.get(8)?,
        skip_code: row.get(9)?,
    })
}

pub(crate) fn list(conn: &Connection) -> Result<Vec<Provider>, DbError> {
    let mut statement = conn.prepare(&format!("SELECT {COLUMNS} FROM providers ORDER BY name"))?;
    let providers = statement
        .query_map([], from_row)?
        .collect::<Result<_, _>>()?;
    Ok(providers)
}

pub(crate) fn by_slug(conn: &Connection, slug: &str) -> Result<Option<Provider>, DbError> {
    Ok(conn
        .query_row(
            &format!("SELECT {COLUMNS} FROM providers WHERE slug = ?1"),
            [slug],
            from_row,
        )
        .optional()?)
}

pub(crate) fn by_id(conn: &Connection, id: ProviderId) -> Result<Option<Provider>, DbError> {
    Ok(conn
        .query_row(
            &format!("SELECT {COLUMNS} FROM providers WHERE id = ?1"),
            [id.0],
            from_row,
        )
        .optional()?)
}

/// Creates a provider, or updates the one with `id`, apart from its secret.
pub(crate) fn save(
    conn: &Connection,
    id: Option<ProviderId>,
    provider: &Provider,
) -> Result<ProviderId, DbError> {
    let domains = provider.auto_create_domains.join(" ");
    match id {
        None => {
            conn.execute(
                "INSERT INTO providers (slug, name, kind, issuer, client_id, client_secret,
                                        auto_create_domains, enabled, skip_code)
                 VALUES (?1, ?2, ?3, ?4, ?5, X'', ?6, ?7, ?8)",
                params![
                    provider.slug,
                    provider.name,
                    provider.kind.name(),
                    provider.issuer,
                    provider.client_id,
                    domains,
                    provider.enabled,
                    provider.skip_code
                ],
            )?;
            Ok(ProviderId(conn.last_insert_rowid()))
        }
        Some(id) => {
            conn.execute(
                "UPDATE providers SET slug = ?1, name = ?2, kind = ?3, issuer = ?4, client_id = ?5,
                        auto_create_domains = ?6, enabled = ?7, skip_code = ?8
                 WHERE id = ?9",
                params![
                    provider.slug,
                    provider.name,
                    provider.kind.name(),
                    provider.issuer,
                    provider.client_id,
                    domains,
                    provider.enabled,
                    provider.skip_code,
                    id.0
                ],
            )?;
            Ok(id)
        }
    }
}

/// Stores a sealed client secret. It is sealed with the row as context, so the row comes first.
pub(crate) fn set_secret(conn: &Connection, id: ProviderId, sealed: &[u8]) -> Result<(), DbError> {
    conn.execute(
        "UPDATE providers SET client_secret = ?2 WHERE id = ?1",
        params![id.0, sealed],
    )?;
    Ok(())
}

pub(crate) fn delete(conn: &Connection, id: ProviderId) -> Result<(), DbError> {
    conn.execute("DELETE FROM providers WHERE id = ?1", [id.0])?;
    Ok(())
}

/// The user an outside account is linked to.
pub(crate) fn linked_user(
    conn: &Connection,
    provider: ProviderId,
    subject: &str,
) -> Result<Option<UserId>, DbError> {
    Ok(conn
        .query_row(
            "SELECT user_id FROM provider_links WHERE provider_id = ?1 AND subject = ?2",
            params![provider.0, subject],
            |row| row.get(0).map(UserId),
        )
        .optional()?)
}

/// Links an outside account to a user. A user has at most one link per provider.
pub(crate) fn link(
    conn: &Connection,
    provider: ProviderId,
    subject: &str,
    user: UserId,
) -> Result<(), DbError> {
    conn.execute(
        "DELETE FROM provider_links WHERE provider_id = ?1 AND user_id = ?2",
        params![provider.0, user.0],
    )?;
    conn.execute(
        "INSERT INTO provider_links (provider_id, subject, user_id, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![provider.0, subject, user.0, crate::time::now()],
    )?;
    Ok(())
}

pub(crate) fn unlink(conn: &Connection, provider: ProviderId, user: UserId) -> Result<(), DbError> {
    conn.execute(
        "DELETE FROM provider_links WHERE provider_id = ?1 AND user_id = ?2",
        params![provider.0, user.0],
    )?;
    Ok(())
}

/// The providers a user has linked.
pub(crate) fn linked_providers(
    conn: &Connection,
    user: UserId,
) -> Result<Vec<ProviderId>, DbError> {
    let mut statement =
        conn.prepare("SELECT provider_id FROM provider_links WHERE user_id = ?1")?;
    let ids = statement
        .query_map([user.0], |row| row.get(0).map(ProviderId))?
        .collect::<Result<_, _>>()?;
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Db;

    #[tokio::test]
    async fn providers_ask_for_the_code_unless_saved_otherwise() {
        let db = Db::open_in_memory().unwrap();
        db.run(|conn| {
            // A provider from before schema version 4.
            conn.execute(
                "INSERT INTO providers (slug, name, kind, client_id, client_secret)
                 VALUES ('old', 'Old', 'github', 'x', X'')",
                [],
            )?;
            let mut provider = by_slug(conn, "old")?.unwrap();
            assert!(!provider.skip_code);

            provider.skip_code = true;
            save(conn, Some(provider.id), &provider)?;
            assert!(by_slug(conn, "old")?.unwrap().skip_code);

            provider.slug = "new".to_owned();
            let id = save(conn, None, &provider)?;
            assert!(by_id(conn, id)?.unwrap().skip_code);
            Ok(())
        })
        .await
        .unwrap();
    }
}
