//! The SQLite database.
//!
//! One thread owns the connection. Async code sends it closures and awaits their results, so
//! queries never block the runtime and never interleave; a closure is the natural place for a
//! transaction.

pub(crate) mod apps;
pub(crate) mod audit;
pub(crate) mod grants;
pub(crate) mod groups;
pub(crate) mod passkeys;
pub(crate) mod providers;
pub(crate) mod proxy;
pub(crate) mod sessions;
pub(crate) mod settings;
pub(crate) mod signing_keys;
pub(crate) mod users;

use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{fmt, io, thread};

use rusqlite::{Connection, ErrorCode};
use tokio::sync::{mpsc, oneshot};

/// Queries waiting beyond this make their callers wait too, instead of queueing without bound.
const QUEUE_LEN: usize = 256;

/// Each entry upgrades the schema by one version. Entries are never edited after a release.
const MIGRATIONS: [&str; 4] = [
    include_str!("schema.sql"),
    include_str!("v2.sql"),
    include_str!("v3.sql"),
    include_str!("v4.sql"),
];

type Job = Box<dyn FnOnce(&mut Connection) + Send>;

#[derive(Debug)]
pub(crate) enum DbError {
    Sqlite(rusqlite::Error),
    Io(io::Error),
    Closed,
    TooNew { version: u32 },
}

impl DbError {
    /// Whether the query broke a rule of the schema, such as a taken user name.
    pub(crate) fn is_constraint_violation(&self) -> bool {
        matches!(self, Self::Sqlite(e) if e.sqlite_error_code() == Some(ErrorCode::ConstraintViolation))
    }
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(e) => write!(f, "database error: {e}"),
            Self::Io(e) => write!(f, "database file error: {e}"),
            Self::Closed => f.write_str("the database thread has stopped"),
            Self::TooNew { version } => write!(
                f,
                "the database has schema version {version}, written by a newer version of Unlatch"
            ),
        }
    }
}

impl From<rusqlite::Error> for DbError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}

#[derive(Clone)]
pub(crate) struct Db {
    jobs: mpsc::Sender<Job>,
}

impl Db {
    /// Opens or creates the database and upgrades its schema, backing it up first.
    pub(crate) fn open(path: &Path) -> Result<Self, DbError> {
        create_private_file(path)?;
        let mut conn = Connection::open(path)?;
        configure(&conn)?;
        migrate(&mut conn, Some(path))?;
        Self::start(conn)
    }

    #[cfg(test)]
    pub(crate) fn open_in_memory() -> Result<Self, DbError> {
        let mut conn = Connection::open_in_memory()?;
        configure(&conn)?;
        migrate(&mut conn, None)?;
        Self::start(conn)
    }

    fn start(mut conn: Connection) -> Result<Self, DbError> {
        let (jobs, mut queue) = mpsc::channel::<Job>(QUEUE_LEN);
        thread::Builder::new()
            .name("database".to_owned())
            .spawn(move || {
                while let Some(job) = queue.blocking_recv() {
                    job(&mut conn);
                }
            })
            .map_err(DbError::Io)?;
        Ok(Self { jobs })
    }

    /// Runs `query` on the database thread.
    pub(crate) async fn run<T, Q>(&self, query: Q) -> Result<T, DbError>
    where
        T: Send + 'static,
        Q: FnOnce(&mut Connection) -> Result<T, DbError> + Send + 'static,
    {
        let (reply, result) = oneshot::channel();
        let job: Job = Box::new(move |conn| {
            // If the caller stopped waiting, nobody needs the result.
            drop(reply.send(query(conn)));
        });
        self.jobs.send(job).await.map_err(|_| DbError::Closed)?;
        result.await.map_err(|_| DbError::Closed)?
    }
}

/// Removes what has expired: sessions with everything issued from them, codes, links, and audit
/// entries past their retention. Runs every hour.
pub(crate) fn delete_expired(
    conn: &Connection,
    now: i64,
    audit_retention: i64,
) -> Result<(), DbError> {
    conn.execute("DELETE FROM sessions WHERE expires_at <= ?1", [now])?;
    conn.execute("DELETE FROM codes WHERE expires_at <= ?1", [now])?;
    conn.execute("DELETE FROM proxy_codes WHERE expires_at <= ?1", [now])?;
    conn.execute("DELETE FROM password_links WHERE expires_at <= ?1", [now])?;
    conn.execute(
        "DELETE FROM audit_log WHERE at < ?1",
        [now.saturating_sub(audit_retention)],
    )?;
    Ok(())
}

/// The database holds password hashes and sealed secrets, so only its owner may read it. SQLite
/// gives the journal files the same permissions.
#[cfg(unix)]
fn create_private_file(path: &Path) -> Result<(), DbError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(DbError::Io(e)),
    }
}

#[cfg(not(unix))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the same signature as the Unix version"
)]
fn create_private_file(_path: &Path) -> Result<(), DbError> {
    Ok(())
}

fn configure(conn: &Connection) -> Result<(), DbError> {
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get::<_, String>(0))?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    // A revocation that was confirmed must survive a power cut.
    conn.pragma_update(None, "synchronous", "FULL")?;
    // Deleted rows, such as old secrets, are overwritten instead of lingering in free pages.
    conn.pragma_update(None, "secure_delete", "ON")?;
    conn.pragma_update(None, "trusted_schema", "OFF")?;
    Ok(())
}

fn migrate(conn: &mut Connection, path: Option<&Path>) -> Result<(), DbError> {
    let version: u32 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let applied = usize::try_from(version).unwrap_or(usize::MAX);
    if applied > MIGRATIONS.len() {
        return Err(DbError::TooNew { version });
    }
    if let Some(path) = path.filter(|_| applied > 0 && applied < MIGRATIONS.len()) {
        // The copy holds the same secrets, so it is created private first; VACUUM INTO fills an
        // empty file, where it would otherwise create one anyone may read.
        let backup = backup_path(path, version)?;
        create_private_file(Path::new(&backup))?;
        conn.execute("VACUUM INTO ?1", [backup])?;
    }
    for (index, sql) in MIGRATIONS.iter().enumerate().skip(applied) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.pragma_update(
            None,
            "user_version",
            u32::try_from(index.saturating_add(1)).unwrap_or(u32::MAX),
        )?;
        tx.commit()?;
    }
    Ok(())
}

/// A file next to the database that doesn't exist yet, such as `unlatch.db.v3-1761123456.bak`.
fn backup_path(path: &Path, version: u32) -> Result<String, DbError> {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".v{version}-{}.bak", crate::time::now()));
    PathBuf::from(name)
        .into_os_string()
        .into_string()
        .map_err(|_| DbError::Io(io::Error::other("the database path isn't valid Unicode")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn schema_applies_and_enforces_its_rules() {
        let db = Db::open_in_memory().unwrap();
        let version = db
            .run(|conn| {
                Ok(conn.pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))?)
            })
            .await
            .unwrap();
        assert_eq!(usize::try_from(version).unwrap(), MIGRATIONS.len());

        // An app must be exactly one kind.
        let bad = db
            .run(|conn| {
                conn.execute(
                    "INSERT INTO apps (name, kind, client_id, host, created_at) VALUES ('x', 'oidc', 'x', 'x.lan', 0)",
                    [],
                )?;
                Ok(())
            })
            .await;
        assert!(bad.unwrap_err().is_constraint_violation());
    }

    #[cfg(unix)]
    #[test]
    fn the_copy_before_a_migration_is_private() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = std::env::temp_dir().join(format!("unlatch-migrate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("unlatch.db");
        let mut conn = Connection::open(&path).unwrap();
        conn.execute_batch(MIGRATIONS[0]).unwrap();
        conn.pragma_update(None, "user_version", 1).unwrap();
        migrate(&mut conn, Some(&path)).unwrap();

        let backups: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|file| file.extension().is_some_and(|extension| extension == "bak"))
            .collect();
        let mode = std::fs::metadata(&backups[0]).unwrap().permissions().mode();
        drop(conn);
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!((backups.len(), mode & 0o777), (1, 0o600));
    }
}
