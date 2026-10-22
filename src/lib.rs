//! Unlatch: a small, self-hosted OpenID Connect provider.
//!
//! The program is a library with one public function, [`main`], so that the fuzz targets in
//! `fuzz/` can reach the parsers through the `fuzz` module, which exists only when building with
//! `--cfg fuzzing`. Everything else stays private to the crate.

mod cbor;
mod config;
mod crypto;
mod encoding;
mod form;
#[cfg(fuzzing)]
pub mod fuzz;
mod html;
mod http;
mod identifier;
mod log;
mod secret;
mod store;
mod time;
mod uri;
mod web;

use std::io::Write as _;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use crate::config::Config;
use crate::crypto::MasterKey;
use crate::log::{error, info, warning};
use crate::store::Db;
use crate::web::App;

const USAGE: &str = "\
Usage: unlatch [command]

Commands:
  serve          Run the server (the default). Configured by environment variables;
                 see https://unlatch.dev/docs/configuration/.
  generate-key   Print a new master key for UNLATCH_KEY_FILE.
  version        Print the version.
  help           Show this message.
";

/// Runs the `unlatch` command with the process's arguments.
#[must_use]
pub fn main() -> ExitCode {
    let command = std::env::args_os()
        .nth(1)
        .map(|arg| arg.to_string_lossy().into_owned());
    match command.as_deref() {
        None | Some("serve") => serve(),
        Some("generate-key") => match MasterKey::generate() {
            Ok(key) => print(&format!("{key}\n")),
            Err(e) => {
                error!("{e}");
                ExitCode::FAILURE
            }
        },
        Some("version" | "--version" | "-V") => {
            print(concat!("unlatch ", env!("CARGO_PKG_VERSION"), "\n"))
        }
        Some("help" | "--help" | "-h") => print(USAGE),
        Some(other) => {
            error!("unknown command {other:?}\n\n{USAGE}");
            ExitCode::FAILURE
        }
    }
}

fn print(text: &str) -> ExitCode {
    match std::io::stdout().write_all(text.as_bytes()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}

fn serve() -> ExitCode {
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(e) => {
            error!("{e}");
            return ExitCode::FAILURE;
        }
    };
    log::set_level(config.log_level);
    // Two workers are plenty for sign-ins and keep memory low; password hashing runs on the
    // blocking pool and the database on its own thread.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build();
    let result = match runtime {
        Ok(runtime) => runtime.block_on(run(config)),
        Err(e) => Err(format!("can't start the async runtime: {e}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            error!("{e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(config: Config) -> Result<(), String> {
    let db = Db::open(&config.database).map_err(|e| e.to_string())?;
    let listener = http::bind(config.listen).await.map_err(|e| e.to_string())?;
    let tls = config.tls.clone().map(http::tls::acceptor).transpose()?;
    let app = Arc::new(App::new(config, db).await.map_err(|e| e.to_string())?);
    if let Some(link) = web::setup::prepare(&app).await.map_err(|e| e.to_string())? {
        warning!("there are no accounts yet; create the first administrator at {link}");
    }
    tokio::spawn(housekeeping(Arc::clone(&app)));
    info!(
        "listening on {} as {}",
        app.config.listen,
        app.config.issuer.as_str()
    );
    http::serve(app, listener, tls).await;
    Ok(())
}

/// Audit entries are kept this long; they contain IP addresses, which are personal data.
const AUDIT_RETENTION: i64 = 180 * 24 * 60 * 60;

/// Deletes expired sessions, codes and links, and old audit entries, once an hour, and rotates
/// signing keys when they are due, checked once a day.
async fn housekeeping(app: Arc<App>) {
    let mut hourly = tokio::time::interval(Duration::from_hours(1));
    let mut hours: u32 = 0;
    loop {
        hourly.tick().await;
        hours = hours.wrapping_add(1);
        if hours.is_multiple_of(24)
            && let Err(e) = app.refresh_keys().await
        {
            error!("rotating signing keys failed: {e}");
        }
        let now = time::now();
        let result = app
            .db
            .run(move |conn| store::delete_expired(conn, now, AUDIT_RETENTION))
            .await;
        if let Err(e) = result {
            error!("deleting expired data failed: {e}");
        }
    }
}
