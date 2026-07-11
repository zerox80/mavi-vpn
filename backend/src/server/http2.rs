//! Experimental HTTP/2 CONNECT-IP listener.
//!
//! This module only establishes the standards-compliant TCP/TLS/HTTP/2
//! transport boundary. The CONNECT-IP data plane is deliberately not wired to
//! the TUN yet, so a valid CONNECT-IP request receives `501 Not Implemented`.

use anyhow::{Context, Result};
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::ext::Protocol;
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

const CONNECT_IP_PROTOCOL: &str = "connect-ip";
const MAX_CONNECTIONS: usize = 1_000;
type ResponseBody = Full<Bytes>;

/// A bound but not yet running HTTP/2 listener.
pub struct Http2Listener {
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    camouflage: bool,
}

/// Binds the optional TCP listener before the server announces readiness.
///
/// Binding errors are returned to the caller rather than silently disabling a
/// configured transport.
pub async fn bind_http2_listener(
    bind_addr: SocketAddr,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    camouflage: bool,
) -> Result<Http2Listener> {
    let tls_config = build_tls_config(certs, key)?;
    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind HTTP/2 listener on TCP {bind_addr}"))?;

    Ok(Http2Listener {
        listener,
        tls_acceptor: TlsAcceptor::from(Arc::new(tls_config)),
        camouflage,
    })
}

impl Http2Listener {
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener
            .local_addr()
            .context("failed to read HTTP/2 listener address")
    }

    /// Accepts TLS connections and serves HTTP/2 only.
    pub async fn run(self) -> Result<()> {
        let local_addr = self.local_addr()?;
        info!(%local_addr, "HTTP/2 CONNECT-IP beta listener ready on TCP");
        let connection_limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));

        loop {
            let (tcp_stream, peer_addr) = self
                .listener
                .accept()
                .await
                .context("HTTP/2 TCP accept failed")?;
            let Ok(permit) = connection_limit.clone().try_acquire_owned() else {
                warn!(%peer_addr, "HTTP/2 connection limit reached; dropping TCP connection");
                continue;
            };
            let tls_acceptor = self.tls_acceptor.clone();
            let camouflage = self.camouflage;

            tokio::spawn(async move {
                let _permit = permit;
                if let Err(error) = serve_connection(tcp_stream, tls_acceptor, camouflage).await {
                    debug!(%peer_addr, %error, "HTTP/2 connection closed");
                }
            });
        }
    }
}

fn build_tls_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<rustls::ServerConfig> {
    let mut tls_config = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
    .with_no_client_auth()
    .with_single_cert(certs, key)?;
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(tls_config)
}

async fn serve_connection(
    tcp_stream: TcpStream,
    tls_acceptor: TlsAcceptor,
    camouflage: bool,
) -> Result<()> {
    let tls_stream = tls_acceptor
        .accept(tcp_stream)
        .await
        .context("HTTP/2 TLS handshake failed")?;
    if tls_stream.get_ref().1.alpn_protocol() != Some(b"h2") {
        anyhow::bail!("client did not negotiate ALPN h2");
    }

    let mut builder = http2::Builder::new(TokioExecutor::new());
    builder
        .enable_connect_protocol()
        .max_concurrent_streams(16)
        .initial_connection_window_size(4 * 1024 * 1024)
        .initial_stream_window_size(1024 * 1024)
        .keep_alive_interval(Some(Duration::from_secs(15)))
        .keep_alive_timeout(Duration::from_secs(60));
    builder
        .serve_connection(
            TokioIo::new(tls_stream),
            service_fn(move |request| handle_request(request, camouflage)),
        )
        .await
        .context("HTTP/2 connection failed")
}

async fn handle_request(
    request: Request<Incoming>,
    camouflage: bool,
) -> Result<Response<ResponseBody>, Infallible> {
    if is_connect_ip_request(&request) {
        warn!("received HTTP/2 CONNECT-IP request while beta data plane is disabled");
        return Ok(text_response(
            StatusCode::NOT_IMPLEMENTED,
            "HTTP/2 CONNECT-IP beta data plane is not available yet\n",
        ));
    }

    if camouflage {
        return Ok(html_response(
            StatusCode::OK,
            "<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1></body></html>",
        ));
    }

    let status = if request.method() == Method::CONNECT {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::NOT_FOUND
    };
    Ok(text_response(status, "Not Found\n"))
}

fn is_connect_ip_request<B>(request: &Request<B>) -> bool {
    request.method() == Method::CONNECT
        && request
            .extensions()
            .get::<Protocol>()
            .is_some_and(|protocol| protocol.as_str() == CONNECT_IP_PROTOCOL)
}

fn text_response(status: StatusCode, body: &'static str) -> Response<ResponseBody> {
    Response::builder()
        .status(status)
        .header("cache-control", "no-store")
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .expect("fixed HTTP response is valid")
}

fn html_response(status: StatusCode, body: &'static str) -> Response<ResponseBody> {
    Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        .header("server", "nginx")
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .expect("fixed HTTP response is valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Version;

    #[test]
    fn connect_ip_request_is_recognized() {
        let mut request = Request::new(());
        *request.method_mut() = Method::CONNECT;
        *request.version_mut() = Version::HTTP_2;
        request
            .extensions_mut()
            .insert(Protocol::from_static(CONNECT_IP_PROTOCOL));

        assert!(is_connect_ip_request(&request));
    }

    #[test]
    fn non_connect_ip_request_is_not_recognized() {
        let request = Request::new(());
        assert!(!is_connect_ip_request(&request));
    }
}
