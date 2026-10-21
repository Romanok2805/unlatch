//! HTTP: the server, requests as the rest of Unlatch sees them, and responses.

pub(crate) mod cookie;
mod server;

use std::net::IpAddr;
use std::time::Duration;

use http_body_util::{BodyExt as _, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{self, AsHeaderName, HeaderMap, HeaderName, HeaderValue};
use hyper::{Method, StatusCode};
use serde::Serialize;

pub(crate) use self::server::{bind, serve};
use crate::config::Cidr;
use crate::form::Form;
use crate::html::Html;

/// Form bodies larger than this are refused. The largest form we serve, an application with its
/// redirect URIs, is a few kilobytes.
const MAX_BODY: usize = 64 * 1024;
/// A client that takes longer to send its body is dropped.
const BODY_TIMEOUT: Duration = Duration::from_secs(10);

/// A request whose query and form body have been read and decoded.
pub(crate) struct Request {
    pub(crate) method: Method,
    pub(crate) path: String,
    /// The path with its query string, as the client sent it.
    pub(crate) target: String,
    pub(crate) query: Form,
    pub(crate) form: Form,
    pub(crate) client_ip: IpAddr,
    headers: HeaderMap,
}

impl Request {
    async fn read(
        request: hyper::Request<Incoming>,
        peer: IpAddr,
        trusted_proxies: &[Cidr],
    ) -> Result<Self, StatusCode> {
        let (parts, body) = request.into_parts();
        let query = Form::parse(parts.uri.query().unwrap_or_default())
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        let is_form = parts
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("application/x-www-form-urlencoded"));
        let form = if parts.method == Method::POST && is_form {
            let body = tokio::time::timeout(BODY_TIMEOUT, Limited::new(body, MAX_BODY).collect())
                .await
                .map_err(|_| StatusCode::REQUEST_TIMEOUT)?
                .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?
                .to_bytes();
            let text = std::str::from_utf8(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
            Form::parse(text).map_err(|_| StatusCode::BAD_REQUEST)?
        } else {
            Form::default()
        };
        Ok(Self {
            client_ip: client_ip(peer, &parts.headers, trusted_proxies),
            method: parts.method,
            path: parts.uri.path().to_owned(),
            target: parts
                .uri
                .path_and_query()
                .map_or_else(|| parts.uri.path().to_owned(), ToString::to_string),
            query,
            form,
            headers: parts.headers,
        })
    }

    pub(crate) fn header(&self, name: impl AsHeaderName) -> Option<&str> {
        self.headers.get(name)?.to_str().ok()
    }

    pub(crate) fn cookie(&self, name: &str) -> Option<&str> {
        self.headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(';'))
            .filter_map(|pair| pair.trim().split_once('='))
            .find_map(|(cookie, value)| (cookie == name).then_some(value))
    }
}

/// The client's address. Behind trusted proxies it comes from `X-Forwarded-For`, which lists the
/// client first and each proxy after it: walking back from the nearest hop, the first address
/// we don't trust is the client. Anything before it could have been written by the client.
fn client_ip(peer: IpAddr, headers: &HeaderMap, trusted_proxies: &[Cidr]) -> IpAddr {
    let trusted = |ip: IpAddr| trusted_proxies.iter().any(|range| range.contains(ip));
    let mut client = peer.to_canonical();
    if !trusted(client) {
        return client;
    }
    let hops: Vec<&str> = headers
        .get_all("x-forwarded-for")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .collect();
    for hop in hops.into_iter().rev() {
        let Ok(ip) = hop.parse::<IpAddr>() else { break };
        client = ip.to_canonical();
        if !trusted(client) {
            break;
        }
    }
    client
}

pub(crate) struct Response {
    status: StatusCode,
    headers: Vec<(HeaderName, String)>,
    body: Bytes,
}

impl Response {
    pub(crate) fn new(status: StatusCode, content_type: &str, body: impl Into<Bytes>) -> Self {
        Self {
            status,
            headers: vec![(header::CONTENT_TYPE, content_type.to_owned())],
            body: body.into(),
        }
    }

    pub(crate) fn html(page: Html) -> Self {
        Self::new(
            StatusCode::OK,
            "text/html; charset=utf-8",
            page.into_string(),
        )
    }

    pub(crate) fn json(value: &impl Serialize) -> Self {
        match serde_json::to_vec(value) {
            Ok(body) => Self::new(StatusCode::OK, "application/json", body),
            Err(_) => Self::text(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        }
    }

    pub(crate) fn text(status: StatusCode, text: &'static str) -> Self {
        Self::new(status, "text/plain; charset=utf-8", text)
    }

    /// A `303 See Other`, which makes the browser follow with a GET even after a form post.
    pub(crate) fn redirect(location: impl Into<String>) -> Self {
        Self::new(StatusCode::SEE_OTHER, "text/plain; charset=utf-8", "")
            .header(header::LOCATION, location)
    }

    #[must_use]
    pub(crate) fn status(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }

    #[must_use]
    pub(crate) fn header(mut self, name: HeaderName, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }

    /// Converts to hyper's type and adds the headers every response carries unless it set its
    /// own: no caching, no sniffing, no framing, and a Content Security Policy that only allows
    /// our own scripts and styles.
    fn into_hyper(self, secure: bool) -> hyper::Response<Full<Bytes>> {
        let mut response = hyper::Response::new(Full::new(self.body));
        *response.status_mut() = self.status;
        let headers = response.headers_mut();
        for (name, value) in self.headers {
            let Ok(value) = HeaderValue::from_str(&value) else {
                crate::log::error!("dropped a response with an invalid {name} header");
                let mut failed =
                    hyper::Response::new(Full::new(Bytes::from_static(b"internal error")));
                *failed.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                return failed;
            };
            headers.append(name, value);
        }
        let defaults = [
            (header::CACHE_CONTROL, "no-store"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::REFERRER_POLICY, "no-referrer"),
            (header::X_FRAME_OPTIONS, "DENY"),
            (
                HeaderName::from_static("cross-origin-opener-policy"),
                "same-origin",
            ),
            (
                HeaderName::from_static("cross-origin-resource-policy"),
                "same-origin",
            ),
            // form-action is left out on purpose: browsers apply it to the redirect that follows
            // a form post, which would block sending the user back to the application.
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; \
                 connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; \
                 require-trusted-types-for 'script'; trusted-types 'none'",
            ),
        ];
        for (name, value) in defaults {
            if !headers.contains_key(&name) {
                headers.insert(name, HeaderValue::from_static(value));
            }
        }
        if secure {
            headers.insert(
                header::STRICT_TRANSPORT_SECURITY,
                HeaderValue::from_static("max-age=63072000"),
            );
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarded_addresses_count_only_behind_trusted_proxies() {
        let proxies = [Cidr::parse("10.0.0.0/8").unwrap()];
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("6.6.6.6, 203.0.113.9, 10.0.0.2"),
        );
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();

        // The client wrote 6.6.6.6 itself; 203.0.113.9 is what the trusted proxy saw.
        assert_eq!(
            client_ip(ip("10.0.0.1"), &headers, &proxies),
            ip("203.0.113.9")
        );
        // From an untrusted peer the header is ignored.
        assert_eq!(
            client_ip(ip("198.51.100.7"), &headers, &proxies),
            ip("198.51.100.7")
        );
    }
}
