//! Unlatch: a small, self-hosted OpenID Connect provider.
#![expect(
    dead_code,
    unused_imports,
    reason = "parts used by the sign-in and protocol endpoints of later stages"
)]

mod config;
mod crypto;
mod encoding;
mod form;
mod html;
mod http;
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
                 see docs/configuration.md.
  generate-key   Print a new master key for UNLATCH_KEY_FILE.
  help           Show this message.
";

fn main() -> ExitCode {
    let command = std::env::args().nth(1);
    match command.as_deref() {
        None | Some("serve") => serve(),
        Some("generate-key") => match MasterKey::generate() {
            Ok(key) => print(&format!("{key}\n")),
            Err(e) => {
                error!("{e}");
                ExitCode::FAILURE
            }
        },
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
    http::serve(app, listener).await;
    Ok(())
}

/// Audit entries are kept this long; they contain IP addresses, which are personal data.
const AUDIT_RETENTION: i64 = 180 * 24 * 60 * 60;

/// Deletes expired sessions, codes and links, and old audit entries, once an hour.
async fn housekeeping(app: Arc<App>) {
    let mut hourly = tokio::time::interval(Duration::from_hours(1));
    loop {
        hourly.tick().await;
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
