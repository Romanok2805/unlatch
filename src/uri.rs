//! Redirect URIs of clients.

use std::fmt;

/// Longer than any real redirect URI, short enough to keep logs and tokens small.
const MAX_LENGTH: usize = 2000;

/// Why a redirect URI was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InvalidRedirectUri {
    TooLong,
    Whitespace,
    Fragment,
    NoHost,
    PlainHttp,
    Scheme,
    UserInfo,
    Port,
    Host,
}

impl fmt::Display for InvalidRedirectUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLong => "the address is too long",
            Self::Whitespace => "the address contains spaces or control characters",
            Self::Fragment => "the address has a fragment",
            Self::NoHost => "the address has no host",
            Self::PlainHttp => "plain http is only allowed for 127.0.0.1 and [::1]",
            Self::Scheme => "use https, or a reverse domain scheme such as com.example.app:/path",
            Self::UserInfo => "the host contains a user name or escapes",
            Self::Port => "the port isn't a number",
            Self::Host => "the host must be lowercase letters, digits, dots and dashes",
        })
    }
}

/// A redirect URI registered for a client.
///
/// Allowed are `https` URIs, `http` on a loopback IP address for apps running on the user's own
/// machine (RFC 8252, section 7.3), and private-use schemes such as `com.example.app:/done` for
/// mobile apps (section 7.1). Fragments, user names in the authority and anything that needs
/// normalising are rejected, so the registered string is the only spelling that matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RedirectUri(String);

impl RedirectUri {
    pub(crate) fn parse(text: &str) -> Result<Self, InvalidRedirectUri> {
        if text.len() > MAX_LENGTH {
            return Err(InvalidRedirectUri::TooLong);
        }
        if text.bytes().any(|b| b <= b' ' || b == 0x7f || b == b'\\') {
            return Err(InvalidRedirectUri::Whitespace);
        }
        if text.contains('#') {
            return Err(InvalidRedirectUri::Fragment);
        }
        let (scheme, rest) = text.split_once(':').ok_or(InvalidRedirectUri::Scheme)?;
        match scheme {
            "https" => {
                let authority = authority(rest)?;
                if authority.host.is_empty() {
                    return Err(InvalidRedirectUri::NoHost);
                }
            }
            "http" => {
                if !authority(rest)?.is_loopback() {
                    return Err(InvalidRedirectUri::PlainHttp);
                }
            }
            _ => {
                let valid = scheme.contains('.')
                    && scheme.starts_with(|c: char| c.is_ascii_lowercase())
                    && scheme
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "+-.".contains(c));
                if !valid || !rest.starts_with('/') || rest.starts_with("//") {
                    return Err(InvalidRedirectUri::Scheme);
                }
            }
        }
        Ok(Self(text.to_owned()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether a redirect URI sent in a request is this one. The comparison is exact, except that
    /// the port of a loopback address may differ, because native apps listen on whatever port
    /// the system gives them.
    pub(crate) fn matches(&self, requested: &str) -> bool {
        if self.0 == requested {
            return true;
        }
        let loopback_parts = |uri: &str| {
            let rest = uri.strip_prefix("http:")?;
            let authority = authority(rest).ok()?;
            authority.is_loopback().then(|| {
                (
                    authority.host.to_owned(),
                    authority.path_and_query.to_owned(),
                )
            })
        };
        match (loopback_parts(&self.0), loopback_parts(requested)) {
            (Some(registered), Some(requested)) => registered == requested,
            _ => false,
        }
    }
}

struct Authority<'a> {
    host: &'a str,
    path_and_query: &'a str,
}

impl Authority<'_> {
    fn is_loopback(&self) -> bool {
        matches!(self.host, "127.0.0.1" | "[::1]")
    }
}

/// Splits `//host:port/path?query` into the host and the rest, checking what we rely on.
fn authority(rest: &str) -> Result<Authority<'_>, InvalidRedirectUri> {
    let rest = rest.strip_prefix("//").ok_or(InvalidRedirectUri::NoHost)?;
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (host_and_port, path_and_query) = rest.split_at_checked(end).unwrap_or((rest, ""));
    if host_and_port.contains(['@', '%']) {
        return Err(InvalidRedirectUri::UserInfo);
    }
    // The port starts after the closing bracket of an IPv6 address, or at the first colon.
    let port_start = if host_and_port.starts_with('[') {
        host_and_port
            .find(']')
            .ok_or(InvalidRedirectUri::Host)?
            .saturating_add(1)
    } else {
        host_and_port.find(':').unwrap_or(host_and_port.len())
    };
    let (host, port) = host_and_port
        .split_at_checked(port_start)
        .unwrap_or((host_and_port, ""));
    if let Some(port) = port.strip_prefix(':') {
        if port.parse::<u16>().is_err() {
            return Err(InvalidRedirectUri::Port);
        }
    } else if !port.is_empty() {
        return Err(InvalidRedirectUri::Host);
    }
    let host_chars_valid = host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "-.[]:".contains(c));
    if !host_chars_valid || host.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(InvalidRedirectUri::Host);
    }
    Ok(Authority {
        host,
        path_and_query,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_safe_addresses() {
        for good in [
            "https://grafana.home.lan/login/generic_oauth",
            "https://app.example.com:8443/cb?tenant=a",
            "http://127.0.0.1/callback",
            "http://[::1]:5000/callback",
            "com.example.app:/oauth2redirect",
        ] {
            assert!(RedirectUri::parse(good).is_ok(), "{good}");
        }
        for bad in [
            "http://grafana.home.lan/cb",
            "http://localhost/cb",
            "https://app.example.com/cb#x",
            "https://user@app.example.com/cb",
            "https://app.example.com:abc/cb",
            "https:///cb",
            "https://App.example.com/cb",
            "https://app.example.com/a b",
            "javascript:alert(1)",
            "myapp:/cb",
            "com.example.app://host/cb",
            "relative/path",
        ] {
            assert!(RedirectUri::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn matches_exactly_except_loopback_ports() {
        let https = RedirectUri::parse("https://app.example.com/cb").unwrap();
        assert!(https.matches("https://app.example.com/cb"));
        assert!(!https.matches("https://app.example.com/cb/"));
        assert!(!https.matches("https://app.example.com/cb?x=1"));
        assert!(!https.matches("https://app.example.com:443/cb"));

        let loopback = RedirectUri::parse("http://127.0.0.1/cb").unwrap();
        assert!(loopback.matches("http://127.0.0.1:51004/cb"));
        assert!(!loopback.matches("http://127.0.0.1:51004/other"));
        assert!(!loopback.matches("http://[::1]:51004/cb"));
    }
}
