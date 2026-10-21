//! Discovery (OpenID Connect Discovery 1.0) and the public keys.

use hyper::header;
use serde::Serialize;

use super::super::App;
use super::SCOPES;
use crate::crypto::{Algorithm, Jwk};
use crate::http::Response;

#[derive(Serialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the fields are fixed by OpenID Connect Discovery"
)]
struct Metadata<'a> {
    issuer: &'a str,
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
    end_session_endpoint: String,
    revocation_endpoint: String,
    introspection_endpoint: String,
    scopes_supported: [&'static str; 5],
    response_types_supported: [&'static str; 1],
    response_modes_supported: [&'static str; 1],
    grant_types_supported: [&'static str; 3],
    subject_types_supported: [&'static str; 1],
    id_token_signing_alg_values_supported: Vec<&'static str>,
    token_endpoint_auth_methods_supported: [&'static str; 3],
    revocation_endpoint_auth_methods_supported: [&'static str; 3],
    introspection_endpoint_auth_methods_supported: [&'static str; 2],
    code_challenge_methods_supported: [&'static str; 1],
    claims_supported: [&'static str; 13],
    authorization_response_iss_parameter_supported: bool,
    backchannel_logout_supported: bool,
    backchannel_logout_session_supported: bool,
    request_parameter_supported: bool,
    request_uri_parameter_supported: bool,
    claims_parameter_supported: bool,
}

/// `GET /.well-known/openid-configuration`
pub(crate) fn discovery(app: &App) -> Response {
    let issuer = &app.config.issuer;
    let metadata = Metadata {
        issuer: issuer.as_str(),
        authorization_endpoint: issuer.url("/authorize"),
        token_endpoint: issuer.url("/token"),
        userinfo_endpoint: issuer.url("/userinfo"),
        jwks_uri: issuer.url("/jwks"),
        end_session_endpoint: issuer.url("/end-session"),
        revocation_endpoint: issuer.url("/revoke"),
        introspection_endpoint: issuer.url("/introspect"),
        scopes_supported: SCOPES,
        response_types_supported: ["code"],
        response_modes_supported: ["query"],
        grant_types_supported: ["authorization_code", "refresh_token", "client_credentials"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: Algorithm::ALL
            .into_iter()
            .map(Algorithm::name)
            .collect(),
        token_endpoint_auth_methods_supported: [
            "client_secret_basic",
            "client_secret_post",
            "none",
        ],
        revocation_endpoint_auth_methods_supported: [
            "client_secret_basic",
            "client_secret_post",
            "none",
        ],
        introspection_endpoint_auth_methods_supported: [
            "client_secret_basic",
            "client_secret_post",
        ],
        code_challenge_methods_supported: ["S256"],
        claims_supported: [
            "iss",
            "sub",
            "aud",
            "exp",
            "iat",
            "auth_time",
            "nonce",
            "amr",
            "sid",
            "name",
            "preferred_username",
            "email",
            "groups",
        ],
        authorization_response_iss_parameter_supported: true,
        backchannel_logout_supported: true,
        backchannel_logout_session_supported: true,
        request_parameter_supported: false,
        request_uri_parameter_supported: false,
        claims_parameter_supported: false,
    };
    public(Response::json(&metadata))
}

/// `GET /jwks`
pub(crate) fn jwks(app: &App) -> Response {
    #[derive(Serialize)]
    struct Set {
        keys: Vec<Jwk>,
    }
    public(Response::json(&Set {
        keys: app.key_ring().jwks(),
    }))
}

/// Public metadata may be read by browser code on any site and cached briefly.
fn public(response: Response) -> Response {
    response
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .header(header::CACHE_CONTROL, "public, max-age=300")
        .header(
            header::HeaderName::from_static("cross-origin-resource-policy"),
            "cross-origin",
        )
}
