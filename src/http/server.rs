//! Accepting connections and serving HTTP/1.1 on them.

use std::convert::Infallible;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use super::{Request, Response};
use crate::log::{info, warning};
use crate::web::App;

/// Connections beyond this are closed at once. Each costs a task and a buffer, so this caps the
/// memory that idle or slow clients can tie up.
const MAX_CONNECTIONS: u32 = 1024;
/// Request line and headers must arrive within this, also between requests on a kept-alive
/// connection, so slow clients can't hold connections open.
const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
/// Longer request lines and headers are refused.
const MAX_HEAD: usize = 16 * 1024;
/// How long open connections get to finish when the server stops.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

pub(crate) async fn serve(app: Arc<App>, listener: TcpListener, tls: Option<TlsAcceptor>) {
    let connections = Arc::new(Semaphore::new(
        usize::try_from(MAX_CONNECTIONS).unwrap_or(1),
    ));
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(e) => {
                    // Usually out of file descriptors; pause instead of spinning.
                    warning!("accepting a connection failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
            continue;
        };
        let (app, tls) = (Arc::clone(&app), tls.clone());
        tokio::spawn(async move {
            match tls {
                None => serve_connection(app, TokioIo::new(stream), peer).await,
                Some(acceptor) => {
                    // The handshake gets the same time limit as the headers.
                    if let Ok(Ok(stream)) =
                        tokio::time::timeout(HEADER_TIMEOUT, acceptor.accept(stream)).await
                    {
                        serve_connection(app, TokioIo::new(stream), peer).await;
                    }
                }
            }
            drop(permit);
        });
    }

    info!("stopping; waiting for open connections");
    drop(tokio::time::timeout(SHUTDOWN_GRACE, connections.acquire_many(MAX_CONNECTIONS)).await);
}

async fn serve_connection<I>(app: Arc<App>, io: I, peer: std::net::SocketAddr)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let service = service_fn(move |request| {
        let app = Arc::clone(&app);
        async move { Ok::<_, Infallible>(handle(&app, request, peer.ip()).await) }
    });
    // Errors here are clients going away or breaking the protocol; nothing to act on.
    drop(
        http1::Builder::new()
            .timer(TokioTimer::new())
            .header_read_timeout(HEADER_TIMEOUT)
            .max_buf_size(MAX_HEAD)
            .serve_connection(io, service)
            .await,
    );
}

async fn handle(
    app: &App,
    request: hyper::Request<Incoming>,
    peer: IpAddr,
) -> hyper::Response<Full<Bytes>> {
    let response = match Request::read(request, peer, &app.config.trusted_proxies).await {
        Ok(request) => crate::web::route(app, request).await,
        Err(status) => Response::text(status, status.canonical_reason().unwrap_or("bad request")),
    };
    response.into_hyper(app.config.issuer.is_secure())
}

/// Resolves on Ctrl-C, or on SIGTERM from systemd or Docker.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = terminate.recv() => {}
                    _ = tokio::signal::ctrl_c() => {}
                }
            }
            Err(e) => {
                warning!("can't listen for SIGTERM: {e}");
                wait_for_ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    wait_for_ctrl_c().await;
}

async fn wait_for_ctrl_c() {
    if let Err(e) = tokio::signal::ctrl_c().await {
        warning!("can't listen for Ctrl-C: {e}");
        std::future::pending::<()>().await;
    }
}

/// A listener on the configured address, with a readable error when it's taken.
pub(crate) async fn bind(address: std::net::SocketAddr) -> io::Result<TcpListener> {
    TcpListener::bind(address)
        .await
        .map_err(|e| io::Error::new(e.kind(), format!("can't listen on {address}: {e}")))
}
