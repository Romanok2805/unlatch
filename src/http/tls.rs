//! Serving TLS without a reverse proxy. The certificate is read from PEM files and read again
//! when the files change, so a renewal needs no restart.

use std::path::PathBuf;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, SystemTime};

use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio_rustls::TlsAcceptor;

use crate::log::{info, warning};

/// How often the files are checked for changes.
const CHECK_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub(crate) struct TlsFiles {
    pub(crate) certificate: PathBuf,
    pub(crate) key: PathBuf,
}

#[derive(Debug)]
struct Resolver {
    current: RwLock<Arc<CertifiedKey>>,
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(
            &self.current.read().unwrap_or_else(PoisonError::into_inner),
        ))
    }
}

/// An acceptor for the configured certificate, and a task that reloads it when it changes.
pub(crate) fn acceptor(files: TlsFiles) -> Result<TlsAcceptor, String> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let key = load(&files, &provider)?;
    let resolver = Arc::new(Resolver {
        current: RwLock::new(Arc::new(key)),
    });
    let serving: Arc<dyn ResolvesServerCert> = resolver.clone();
    let mut config = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_cert_resolver(serving);
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    tokio::spawn(watch(files, provider, resolver));
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn load(files: &TlsFiles, provider: &CryptoProvider) -> Result<CertifiedKey, String> {
    let certificate = files.certificate.display();
    let chain = CertificateDer::pem_file_iter(&files.certificate)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .map_err(|e| format!("can't read the certificate {certificate}: {e}"))?;
    if chain.is_empty() {
        return Err(format!("{certificate} contains no certificate"));
    }
    let key = PrivateKeyDer::from_pem_file(&files.key)
        .map_err(|e| format!("can't read the key {}: {e}", files.key.display()))?;
    CertifiedKey::from_der(chain, key, provider)
        .map_err(|e| format!("the key doesn't fit the certificate {certificate}: {e}"))
}

fn modified(files: &TlsFiles) -> Option<(SystemTime, SystemTime)> {
    let time = |path: &PathBuf| {
        std::fs::metadata(path)
            .and_then(|meta| meta.modified())
            .ok()
    };
    Some((time(&files.certificate)?, time(&files.key)?))
}

/// Reloads the certificate when either file changes. A broken new file is reported and the
/// old certificate kept, so a botched renewal doesn't take the server down.
async fn watch(files: TlsFiles, provider: Arc<CryptoProvider>, resolver: Arc<Resolver>) {
    let mut last = modified(&files);
    let mut interval = tokio::time::interval(CHECK_INTERVAL);
    loop {
        interval.tick().await;
        let now = modified(&files);
        if now == last {
            continue;
        }
        match load(&files, &provider) {
            Ok(key) => {
                *resolver
                    .current
                    .write()
                    .unwrap_or_else(PoisonError::into_inner) = Arc::new(key);
                info!("loaded the new certificate {}", files.certificate.display());
                last = now;
            }
            Err(e) => warning!("keeping the old certificate: {e}"),
        }
    }
}
