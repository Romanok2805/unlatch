//! Outgoing requests: to sign-in providers, and to applications for back-channel logout.
//!
//! Redirects are not followed, every step has a timeout and responses are limited in size, so a
//! slow or hostile server can't hold Unlatch up or fill its memory.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt as _, Full, Limited};
use hyper::body::Bytes;
use hyper::header::{self, HeaderValue};
use hyper::{Method, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use serde::de::DeserializeOwned;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::encoding::base64;
use crate::form::{encode, encode_pairs};

const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE: usize = 1024 * 1024;

/// Which addresses may be reached without TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Plain {
    /// Only this machine, for trying things out. Sign-in providers are on the internet.
    Loopback,
    /// Any address. Applications on a home network often have no certificate, and a logout
    /// notice is worth little to an eavesdropper.
    Anywhere,
}

#[derive(Debug)]
pub(crate) enum ClientError {
    Url,
    Connect(std::io::Error),
    Tls(std::io::Error),
    Http(hyper::Error),
    Timeout,
    Status(StatusCode),
    TooLarge,
    Json(serde_json::Error),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Url => f.write_str("the address isn't an https URL we may contact"),
            Self::Connect(e) => write!(f, "connecting failed: {e}"),
            Self::Tls(e) => write!(f, "TLS failed: {e}"),
            Self::Http(e) => write!(f, "HTTP failed: {e}"),
            Self::Timeout => f.write_str("the server took too long"),
            Self::Status(status) => write!(f, "the server answered {status}"),
            Self::TooLarge => f.write_str("the response was too large or broken"),
            Self::Json(e) => write!(f, "the response isn't the expected JSON: {e}"),
        }
    }
}

pub(crate) struct Client {
    tls: TlsConnector,
}

struct Target {
    tls: bool,
    host: String,
    port: u16,
    path_and_query: String,
}

impl Client {
    pub(crate) fn new() -> Result<Self, rustls::Error> {
        let roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            tls: TlsConnector::from(Arc::new(config)),
        })
    }

    pub(crate) async fn get_json<T: DeserializeOwned>(
        &self,
        url: &str,
        plain: Plain,
        bearer: Option<&str>,
    ) -> Result<T, ClientError> {
        let target = parse(url, plain).ok_or(ClientError::Url)?;
        let mut request = request(&target, Method::GET, Bytes::new())?;
        if let Some(token) = bearer {
            let value =
                HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| ClientError::Url)?;
            request.headers_mut().insert(header::AUTHORIZATION, value);
        }
        let (status, body) = self.send(&target, request).await?;
        json(status, &body)
    }

    /// Posts a form, authenticating with `client_secret_basic` if credentials are given.
    pub(crate) async fn post_form<T: DeserializeOwned>(
        &self,
        url: &str,
        plain: Plain,
        form: &[(&str, &str)],
        basic: Option<(&str, &str)>,
    ) -> Result<T, ClientError> {
        let (status, body) = self.post(url, plain, form, basic).await?;
        json(status, &body)
    }

    /// Posts a form and returns only the status.
    pub(crate) async fn post_form_status(
        &self,
        url: &str,
        plain: Plain,
        form: &[(&str, &str)],
    ) -> Result<StatusCode, ClientError> {
        self.post(url, plain, form, None)
            .await
            .map(|(status, _)| status)
    }

    async fn post(
        &self,
        url: &str,
        plain: Plain,
        form: &[(&str, &str)],
        basic: Option<(&str, &str)>,
    ) -> Result<(StatusCode, Bytes), ClientError> {
        let target = parse(url, plain).ok_or(ClientError::Url)?;
        let body = Bytes::from(encode_pairs(form.iter().copied()));
        let mut request = request(&target, Method::POST, body)?;
        let headers = request.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        if let Some((id, secret)) = basic {
            // RFC 6749 section 2.3.1: both parts form-encoded, then base64 with padding.
            let mut credentials = base64(format!("{}:{}", encode(id), encode(secret)).as_bytes());
            while !credentials.len().is_multiple_of(4) {
                credentials.push('=');
            }
            let value = HeaderValue::from_str(&format!("Basic {credentials}"))
                .map_err(|_| ClientError::Url)?;
            headers.insert(header::AUTHORIZATION, value);
        }
        self.send(&target, request).await
    }

    async fn send(
        &self,
        target: &Target,
        request: hyper::Request<Full<Bytes>>,
    ) -> Result<(StatusCode, Bytes), ClientError> {
        let host = target.host.trim_start_matches('[').trim_end_matches(']');
        let stream = tokio::time::timeout(TIMEOUT, TcpStream::connect((host, target.port)))
            .await
            .map_err(|_| ClientError::Timeout)?
            .map_err(ClientError::Connect)?;
        if !target.tls {
            return exchange(TokioIo::new(stream), request).await;
        }
        let name = ServerName::try_from(host.to_owned()).map_err(|_| ClientError::Url)?;
        let stream = tokio::time::timeout(TIMEOUT, self.tls.connect(name, stream))
            .await
            .map_err(|_| ClientError::Timeout)?
            .map_err(ClientError::Tls)?;
        exchange(TokioIo::new(stream), request).await
    }
}

async fn exchange<I>(
    io: I,
    request: hyper::Request<Full<Bytes>>,
) -> Result<(StatusCode, Bytes), ClientError>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(ClientError::Http)?;
    // The connection ends with the exchange; its outcome shows up in the response.
    tokio::spawn(async move { drop(connection.await) });
    let response = tokio::time::timeout(TIMEOUT, sender.send_request(request))
        .await
        .map_err(|_| ClientError::Timeout)?
        .map_err(ClientError::Http)?;
    let status = response.status();
    let body = tokio::time::timeout(
        TIMEOUT,
        Limited::new(response.into_body(), MAX_RESPONSE).collect(),
    )
    .await
    .map_err(|_| ClientError::Timeout)?
    .map_err(|_| ClientError::TooLarge)?
    .to_bytes();
    Ok((status, body))
}

fn request(
    target: &Target,
    method: Method,
    body: Bytes,
) -> Result<hyper::Request<Full<Bytes>>, ClientError> {
    let default_port = if target.tls { 443 } else { 80 };
    let host = if target.port == default_port {
        target.host.clone()
    } else {
        format!("{}:{}", target.host, target.port)
    };
    hyper::Request::builder()
        .method(method)
        .uri(&target.path_and_query)
        .header(header::HOST, host)
        .header(
            header::USER_AGENT,
            concat!("unlatch/", env!("CARGO_PKG_VERSION")),
        )
        .header(header::ACCEPT, "application/json")
        .body(Full::new(body))
        .map_err(|_| ClientError::Url)
}

fn json<T: DeserializeOwned>(status: StatusCode, body: &[u8]) -> Result<T, ClientError> {
    if !status.is_success() {
        return Err(ClientError::Status(status));
    }
    serde_json::from_slice(body).map_err(ClientError::Json)
}

/// Whether a URL is one we could send requests to.
pub(crate) fn is_valid_url(url: &str, plain: Plain) -> bool {
    parse(url, plain).is_some()
}

/// Splits `https://host[:port]/path?query`. User names in the authority and fragments are
/// refused; plain http only where `plain` allows it.
fn parse(url: &str, plain: Plain) -> Option<Target> {
    let (tls, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else {
        (false, url.strip_prefix("http://")?)
    };
    if url.contains(['#', ' ', '\\']) || url.chars().any(char::is_control) {
        return None;
    }
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at_checked(end)?;
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !port.contains(']') => (host, port.parse().ok()?),
        _ => (authority, if tls { 443 } else { 80 }),
    };
    let loopback = matches!(host, "127.0.0.1" | "[::1]" | "localhost");
    if !tls && plain == Plain::Loopback && !loopback {
        return None;
    }
    let path_and_query = match path {
        "" => "/".to_owned(),
        path if path.starts_with('?') => format!("/{path}"),
        path => path.to_owned(),
    };
    Some(Target {
        tls,
        host: host.to_owned(),
        port,
        path_and_query,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_parsed_and_plain_http_is_limited() {
        let target = parse(
            "https://accounts.google.com/.well-known/openid-configuration",
            Plain::Loopback,
        )
        .unwrap();
        assert!(target.tls);
        assert_eq!(
            (target.host.as_str(), target.port),
            ("accounts.google.com", 443)
        );
        assert_eq!(target.path_and_query, "/.well-known/openid-configuration");

        let target = parse("http://[::1]:8282?x=1", Plain::Loopback).unwrap();
        assert_eq!(
            (
                target.host.as_str(),
                target.port,
                target.path_and_query.as_str()
            ),
            ("[::1]", 8282, "/?x=1")
        );

        assert!(parse("http://grafana.lan/logout", Plain::Loopback).is_none());
        assert!(parse("http://grafana.lan/logout", Plain::Anywhere).is_some());
        for bad in [
            "ftp://x",
            "https://user@host/",
            "https://host/#x",
            "https://",
            "https://host:99999/",
        ] {
            assert!(parse(bad, Plain::Anywhere).is_none(), "{bad}");
        }
    }
}
