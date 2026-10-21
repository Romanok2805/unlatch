//! Telling applications that a session ended (OpenID Connect Back-Channel Logout 1.0).

use std::sync::Arc;

use serde::Serialize;

use super::super::App;
use super::tokens::subject;
use crate::crypto::{Algorithm, random_bytes};
use crate::encoding::base64url;
use crate::http::client::Plain;
use crate::log::warning;
use crate::store::sessions::LogoutTarget;
use crate::time;

/// A logout token is only good for this long.
const LIFETIME: i64 = 2 * 60;

#[derive(Serialize)]
struct LogoutClaims<'a> {
    iss: &'a str,
    aud: &'a str,
    iat: i64,
    exp: i64,
    jti: String,
    sub: String,
    sid: &'a str,
    events: Events,
}

#[derive(Serialize)]
struct Events {
    #[serde(rename = "http://schemas.openid.net/event/backchannel-logout")]
    logout: Empty,
}

#[derive(Serialize)]
struct Empty {}

/// Sends each application a signed logout token. The requests run in the background, so an
/// application that is slow or offline doesn't hold up the user; failures are logged.
pub(crate) fn notify(app: &App, targets: Vec<LogoutTarget>) {
    let now = time::now();
    let ring = app.key_ring();
    let Some(key) = ring.current(Algorithm::Rs256, now) else {
        return;
    };
    for target in targets {
        let Ok(jti) = random_bytes::<16>() else {
            continue;
        };
        let claims = LogoutClaims {
            iss: app.config.issuer.as_str(),
            aud: &target.client_id,
            iat: now,
            exp: now.saturating_add(LIFETIME),
            jti: base64url(&jti),
            sub: subject(app, target.user),
            sid: &target.sid,
            events: Events { logout: Empty {} },
        };
        let Ok(token) = key.sign_jwt("logout+jwt", &claims) else {
            continue;
        };
        let client = Arc::clone(&app.client);
        tokio::spawn(async move {
            let result = client
                .post_form_status(&target.uri, Plain::Anywhere, &[("logout_token", &token)])
                .await;
            match result {
                Ok(status) if status.is_success() => {}
                Ok(status) => warning!("back-channel logout to {} answered {status}", target.uri),
                Err(e) => warning!("back-channel logout to {} failed: {e}", target.uri),
            }
        });
    }
}
