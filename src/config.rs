//! Configuration, read once from environment variables at start-up.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use crate::crypto::MasterKey;
use crate::http::tls::TlsFiles;
use crate::log::Level;

pub(crate) struct Config {
    pub(crate) issuer: Issuer,
    pub(crate) listen: SocketAddr,
    pub(crate) database: PathBuf,
    pub(crate) master_key: MasterKey,
    pub(crate) trusted_proxies: Vec<Cidr>,
    pub(crate) log_level: Level,
    /// Set to serve TLS without a reverse proxy.
    pub(crate) tls: Option<TlsFiles>,
}

#[derive(Debug)]
pub(crate) struct ConfigError(String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Config {
    pub(crate) fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|name| std::env::var(name).ok().filter(|value| !value.is_empty()))
    }

    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let issuer = get("UNLATCH_ISSUER").ok_or_else(|| {
            ConfigError(
                "set UNLATCH_ISSUER to the address people open, such as https://login.example.com"
                    .into(),
            )
        })?;
        let issuer = Issuer::parse(&issuer)
            .map_err(|reason| ConfigError(format!("UNLATCH_ISSUER {reason}")))?;

        let listen = get("UNLATCH_LISTEN").unwrap_or_else(|| "127.0.0.1:8080".to_owned());
        let listen = listen.parse().map_err(|_| {
            ConfigError(format!(
                "UNLATCH_LISTEN must be an address and port, not {listen:?}"
            ))
        })?;

        let key_file = get("UNLATCH_KEY_FILE").ok_or_else(|| {
            ConfigError(
                "set UNLATCH_KEY_FILE to a key file; create one with `unlatch generate-key`".into(),
            )
        })?;
        let key_text = std::fs::read_to_string(&key_file)
            .map_err(|e| ConfigError(format!("can't read UNLATCH_KEY_FILE {key_file}: {e}")))?;
        let master_key = MasterKey::parse(&key_text).ok_or_else(|| {
            ConfigError(format!(
                "{key_file} doesn't contain a key made by `unlatch generate-key`"
            ))
        })?;

        let trusted_proxies = get("UNLATCH_TRUSTED_PROXIES")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(|entry| {
                Cidr::parse(entry).ok_or_else(|| {
                    ConfigError(format!(
                        "UNLATCH_TRUSTED_PROXIES: {entry:?} isn't an address or network"
                    ))
                })
            })
            .collect::<Result<_, _>>()?;

        let log_level = match get("UNLATCH_LOG") {
            None => Level::Info,
            Some(name) => Level::parse(&name).ok_or_else(|| {
                ConfigError("UNLATCH_LOG must be error, warn, info or debug".into())
            })?,
        };

        let tls = match (get("UNLATCH_TLS_CERT"), get("UNLATCH_TLS_KEY")) {
            (Some(certificate), Some(key)) => Some(TlsFiles {
                certificate: PathBuf::from(certificate),
                key: PathBuf::from(key),
            }),
            (None, None) => None,
            _ => {
                return Err(ConfigError(
                    "set both UNLATCH_TLS_CERT and UNLATCH_TLS_KEY, or neither".into(),
                ));
            }
        };

        Ok(Self {
            issuer,
            listen,
            database: get("UNLATCH_DATABASE")
                .map_or_else(|| PathBuf::from("unlatch.db"), PathBuf::from),
            master_key,
            trusted_proxies,
            log_level,
            tls,
        })
    }
}

/// The address of this server, as clients and browsers see it. Every URL we send is built from
/// it, never from the `Host` header of a request.
pub(crate) struct Issuer {
    origin: String,
    secure: bool,
}

impl Issuer {
    /// Accepts `https://host[:port]`, or plain http on a loopback address for trying Unlatch out.
    /// A path isn't supported: Unlatch expects a host of its own.
    fn parse(text: &str) -> Result<Self, &'static str> {
        let origin = text.strip_suffix('/').unwrap_or(text);
        let (secure, host) = if let Some(host) = origin.strip_prefix("https://") {
            (true, host)
        } else if let Some(host) = origin.strip_prefix("http://") {
            (false, host)
        } else {
            return Err("must start with https://");
        };
        let host_name = if host.starts_with('[') {
            host.find(']')
                .and_then(|end| host.get(..=end))
                .unwrap_or(host)
        } else {
            host.split(':').next().unwrap_or(host)
        };
        if host.is_empty() || host.contains(['/', '?', '#', '@']) {
            return Err("must be just a scheme and host, such as https://login.example.com");
        }
        if !secure && !matches!(host_name, "127.0.0.1" | "[::1]" | "localhost") {
            return Err("must use https; plain http is only allowed on localhost");
        }
        Ok(Self {
            origin: origin.to_owned(),
            secure,
        })
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.origin
    }

    pub(crate) fn url(&self, path: &str) -> String {
        format!("{}{path}", self.origin)
    }

    /// Whether browsers reach us over https, which `Secure` and `__Host-` cookies require.
    pub(crate) fn is_secure(&self) -> bool {
        self.secure
    }
}

/// An address range in CIDR notation, or a single address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cidr {
    network: IpAddr,
    prefix: u32,
}

impl Cidr {
    pub(crate) fn parse(text: &str) -> Option<Self> {
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => (
                address.parse::<IpAddr>().ok()?,
                Some(prefix.parse::<u32>().ok()?),
            ),
            None => (text.parse::<IpAddr>().ok()?, None),
        };
        let bits = if address.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(bits);
        (prefix <= bits).then_some(Self {
            network: address,
            prefix,
        })
    }

    pub(crate) fn contains(&self, address: IpAddr) -> bool {
        match (self.network, address.to_canonical()) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = u32::MAX
                    .checked_shl(32_u32.saturating_sub(self.prefix))
                    .unwrap_or(0);
                u32::from(network) & mask == u32::from(address) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = u128::MAX
                    .checked_shl(128_u32.saturating_sub(self.prefix))
                    .unwrap_or(0);
                u128::from(network) & mask == u128::from(address) & mask
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuer_must_be_https_except_on_localhost() {
        assert_eq!(
            Issuer::parse("https://login.example.com/")
                .unwrap()
                .as_str(),
            "https://login.example.com"
        );
        assert!(Issuer::parse("http://127.0.0.1:8080").is_ok());
        for bad in [
            "http://login.example.com",
            "https://login.example.com/auth",
            "login.example.com",
            "https://",
        ] {
            assert!(Issuer::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn cidr_ranges_match_their_addresses() {
        let private = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(private.contains("10.1.2.3".parse().unwrap()));
        assert!(private.contains("::ffff:10.1.2.3".parse().unwrap()));
        assert!(!private.contains("11.0.0.1".parse().unwrap()));
        assert!(
            Cidr::parse("0.0.0.0/0")
                .unwrap()
                .contains("8.8.8.8".parse().unwrap())
        );
        assert!(
            Cidr::parse("fd00::/8")
                .unwrap()
                .contains("fd12::1".parse().unwrap())
        );
        assert!(Cidr::parse("::1").unwrap().contains("::1".parse().unwrap()));
        assert!(Cidr::parse("10.0.0.0/33").is_none());
    }
}
