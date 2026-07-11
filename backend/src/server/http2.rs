//! RFC 9484 CONNECT-IP over TLS and HTTP/2.
//!
//! HTTP/2 does not have QUIC DATAGRAM frames. RFC 9297 therefore carries each
//! HTTP Datagram in a `DATAGRAM` capsule inside the CONNECT request's DATA
//! frames. This is reliable and ordered (TCP), but otherwise uses exactly the
//! same CONNECT-IP request, assignment capsules, authentication, and TUN path
//! as the HTTP/3 transport.

use anyhow::{Context, Result};
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::ext::Protocol;
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::handlers::auth::{as_token_validator, authenticate_client};
use crate::handlers::h3::build_connect_ip_capsules;
use crate::handlers::tunnel::run_http2_tunnel;
use crate::handlers::utils::IpGuard;
use crate::keycloak::KeycloakValidator;
use crate::state::AppState;

const CONNECT_IP_PROTOCOL: &str = "connect-ip";
const CONNECT_IP_PATH: &str = "/.well-known/masque/ip/*/*/";
const MAX_CONNECTIONS: usize = 1_000;
type ResponseBody = BoxBody<Bytes, Infallible>;

/// A bound HTTP/2 CONNECT-IP listener.
pub struct Http2Listener {
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    state: Arc<AppState>,
    config: Config,
    tx_tun: mpsc::Sender<Bytes>,
    keycloak: Option<Arc<KeycloakValidator>>,
    ipv6_enabled: bool,
}

/// Binds the optional TCP listener before the server announces readiness.
#[allow(clippy::too_many_arguments)]
pub async fn bind_http2_listener(
    bind_addr: SocketAddr,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    state: Arc<AppState>,
    config: Config,
    tx_tun: mpsc::Sender<Bytes>,
    keycloak: Option<Arc<KeycloakValidator>>,
    ipv6_enabled: bool,
) -> Result<Http2Listener> {
    let tls_config = build_tls_config(certs, key)?;
    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind HTTP/2 listener on TCP {bind_addr}"))?;

    Ok(Http2Listener {
        listener,
        tls_acceptor: TlsAcceptor::from(Arc::new(tls_config)),
        state,
        config,
        tx_tun,
        keycloak,
        ipv6_enabled,
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
        info!(%local_addr, "HTTP/2 CONNECT-IP listener ready on TCP");
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
            let state = self.state.clone();
            let config = self.config.clone();
            let tx_tun = self.tx_tun.clone();
            let keycloak = self.keycloak.clone();
            let ipv6_enabled = self.ipv6_enabled;

            tokio::spawn(async move {
                let _permit = permit;
                if let Err(error) = serve_connection(
                    tcp_stream,
                    peer_addr,
                    tls_acceptor,
                    state,
                    config,
                    tx_tun,
                    keycloak,
                    ipv6_enabled,
                )
                .await
                {
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

#[allow(clippy::too_many_arguments)]
async fn serve_connection(
    tcp_stream: TcpStream,
    peer_addr: SocketAddr,
    tls_acceptor: TlsAcceptor,
    state: Arc<AppState>,
    config: Config,
    tx_tun: mpsc::Sender<Bytes>,
    keycloak: Option<Arc<KeycloakValidator>>,
    ipv6_enabled: bool,
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
        .timer(TokioTimer::new())
        .enable_connect_protocol()
        .max_concurrent_streams(16)
        .initial_connection_window_size(4 * 1024 * 1024)
        .initial_stream_window_size(1024 * 1024)
        .keep_alive_interval(Some(Duration::from_secs(15)))
        .keep_alive_timeout(Duration::from_secs(60));
    builder
        .serve_connection(
            TokioIo::new(tls_stream),
            service_fn(move |request| {
                handle_request(
                    request,
                    peer_addr.ip(),
                    state.clone(),
                    config.clone(),
                    tx_tun.clone(),
                    keycloak.clone(),
                    ipv6_enabled,
                )
            }),
        )
        .await
        .context("HTTP/2 connection failed")
}

#[allow(clippy::too_many_arguments)]
async fn handle_request(
    mut request: Request<Incoming>,
    remote_addr: std::net::IpAddr,
    state: Arc<AppState>,
    config: Config,
    tx_tun: mpsc::Sender<Bytes>,
    keycloak: Option<Arc<KeycloakValidator>>,
    ipv6_enabled: bool,
) -> Result<Response<ResponseBody>, Infallible> {
    if !is_connect_ip_request(&request) {
        return Ok(non_connect_response(&request, config.censorship_resistant));
    }

    let token = request
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();

    let (assigned_ip, assigned_ip6, session_auth) = match authenticate_client(
        token,
        remote_addr,
        &state,
        &config,
        as_token_validator(keycloak.as_ref()),
    )
    .await
    {
        Ok(result) => result,
        Err(error) => {
            warn!(%remote_addr, %error, "HTTP/2 CONNECT-IP authentication failed");
            return Ok(if config.censorship_resistant {
                html_response(StatusCode::OK, NGINX_PAGE)
            } else {
                text_response(StatusCode::UNAUTHORIZED, "Unauthorized\n")
            });
        }
    };

    let capsule_stream =
        match build_connect_ip_capsules(&state, &config, assigned_ip, assigned_ip6, ipv6_enabled) {
            Ok(capsules) => capsules,
            Err(error) => {
                warn!(%error, "failed to build HTTP/2 CONNECT-IP configuration capsules");
                return Ok(text_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Server Error\n",
                ));
            }
        };

    let session_expiry = session_auth.as_ref().map(|auth| auth.exp);
    let session_subject = session_auth.map(|auth| auth.sub);
    let on_upgrade = hyper::upgrade::on(&mut request);
    let tunnel_state = state.clone();
    let tunnel_config = config.clone();
    tokio::spawn(async move {
        let _ip_guard = IpGuard {
            state: tunnel_state.clone(),
            ip4: assigned_ip,
            ip6: assigned_ip6,
        };
        if let Err(error) = run_http2_tunnel(
            on_upgrade,
            capsule_stream,
            tunnel_state,
            tx_tun,
            assigned_ip,
            assigned_ip6,
            tunnel_config.mtu,
            session_expiry,
            session_subject,
            keycloak,
            remote_addr,
        )
        .await
        {
            debug!(%error, "HTTP/2 CONNECT-IP tunnel ended");
        }
    });

    info!(%remote_addr, %assigned_ip, "HTTP/2 CONNECT-IP authenticated");
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("capsule-protocol", "?1")
        .header("cache-control", "no-store")
        .body(Empty::<Bytes>::new().boxed())
        .expect("fixed CONNECT-IP response is valid"))
}

fn is_connect_ip_request<B>(request: &Request<B>) -> bool {
    request.method() == Method::CONNECT
        && request.uri().path() == CONNECT_IP_PATH
        && request
            .extensions()
            .get::<Protocol>()
            .is_some_and(|protocol| protocol.as_str() == CONNECT_IP_PROTOCOL)
        && request
            .headers()
            .get("capsule-protocol")
            .is_some_and(|value| value == "?1")
}

const NGINX_PAGE: &str = "<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1></body></html>";

fn non_connect_response(request: &Request<Incoming>, camouflage: bool) -> Response<ResponseBody> {
    if camouflage {
        return html_response(StatusCode::OK, NGINX_PAGE);
    }
    let status = if request.method() == Method::CONNECT {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::NOT_FOUND
    };
    text_response(status, "Not Found\n")
}

fn text_response(status: StatusCode, body: &'static str) -> Response<ResponseBody> {
    Response::builder()
        .status(status)
        .header("cache-control", "no-store")
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from_static(body.as_bytes())).boxed())
        .expect("fixed HTTP response is valid")
}

fn html_response(status: StatusCode, body: &'static str) -> Response<ResponseBody> {
    Response::builder()
        .status(status)
        .header("content-type", "text/html; charset=utf-8")
        .header("server", "nginx")
        .body(Full::new(Bytes::from_static(body.as_bytes())).boxed())
        .expect("fixed HTTP response is valid")
}

#[cfg(test)]
mod tests;
