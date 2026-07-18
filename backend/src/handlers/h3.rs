use anyhow::Result;
use bytes::Bytes;
use http::Response;
use std::sync::Arc;
use tracing::{info, warn};

use crate::config::Config;
use crate::handlers::auth::{as_token_validator, authenticate_client};
use crate::handlers::connection::run_authenticated_tunnel;
use crate::handlers::utils::IpGuard;
use crate::keycloak::KeycloakValidator;
use crate::state::AppState;

pub(crate) use crate::handlers::h3_capsules::build_connect_ip_capsules;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NonConnectIpResponse {
    CamouflageOk,
    NotFound,
}

const CONNECT_IP_PATH: &str = "/.well-known/masque/ip/*/*/";
const CAPSULE_PROTOCOL: &str = "?1";

fn non_connect_ip_response(censorship_resistant: bool) -> NonConnectIpResponse {
    if censorship_resistant {
        NonConnectIpResponse::CamouflageOk
    } else {
        NonConnectIpResponse::NotFound
    }
}

fn is_connect_ip_request<B>(request: &http::Request<B>) -> bool {
    request.method() == http::Method::CONNECT
        && request.uri().path() == CONNECT_IP_PATH
        && request.extensions().get::<h3::ext::Protocol>().copied()
            == Some(h3::ext::Protocol::CONNECT_IP)
        && request
            .headers()
            .get("capsule-protocol")
            .is_some_and(|value| value == CAPSULE_PROTOCOL)
}

async fn send_h3_camouflage_response<S>(
    req_stream: &mut h3::server::RequestStream<S, bytes::Bytes>,
) -> Result<()>
where
    S: h3::quic::BidiStream<bytes::Bytes>,
{
    let response = Response::builder()
        .status(http::StatusCode::OK)
        .header("content-type", "text/html; charset=utf-8")
        .header("server", "nginx")
        .body(())
        .map_err(|e| anyhow::anyhow!("Response build error: {e}"))?;
    let _ = req_stream.send_response(response).await;
    let _ = req_stream
        .send_data(Bytes::from_static(
            b"<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1></body></html>",
        ))
        .await;
    let _ = req_stream.finish().await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub async fn handle_h3_connection(
    connection: quinn::Connection,
    pre_bi: Option<(quinn::SendStream, quinn::RecvStream)>,
    pre_uni: quinn::RecvStream,
    state: Arc<AppState>,
    config: Config,
    tx_tun: tokio::sync::mpsc::Sender<Bytes>,
    keycloak: Option<Arc<KeycloakValidator>>,
    ipv6_enabled: bool,
    sni: Option<String>,
) -> Result<()> {
    let remote_addr = connection.remote_address();
    info!(
        "Detected HTTP/3 L7 client from {} | SNI: {}",
        remote_addr,
        sni.as_deref().unwrap_or("<none>")
    );

    let h3_conn_wrapper = crate::network::h3_quinn::Connection::with_pre_streams(
        connection.clone(),
        pre_bi,
        Some(pre_uni),
    );
    let mut h3_conn = h3::server::builder()
        .enable_datagram(true)
        .enable_extended_connect(true)
        .build(h3_conn_wrapper)
        .await
        .map_err(|e| anyhow::anyhow!("H3 build failed: {e}"))?;

    // Bound the wait for the client's first request so an H3 peer that opens the
    // control stream but never sends a request cannot pin a connection slot until
    // the idle timeout (connection-slot exhaustion DoS).
    let preauth_timeout = crate::handlers::connection::PREAUTH_PHASE_TIMEOUT;
    let resolver = tokio::time::timeout(preauth_timeout, h3_conn.accept())
        .await
        .map_err(|_| anyhow::anyhow!("H3 accept timeout from {remote_addr}"))?
        .map_err(|e| anyhow::anyhow!("H3 accept error: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("Expected H3 request"))?;
    let (req, mut req_stream) = tokio::time::timeout(preauth_timeout, resolver.resolve_request())
        .await
        .map_err(|_| anyhow::anyhow!("H3 resolve timeout from {remote_addr}"))?
        .map_err(|e| anyhow::anyhow!("H3 resolve error: {e}"))?;
    let connect_ip_requested = is_connect_ip_request(&req);
    info!(
        "H3 Request: {} {} (connect-ip={})",
        req.method(),
        req.uri(),
        connect_ip_requested
    );

    if !connect_ip_requested {
        warn!(
            "Rejecting non-connect-ip H3 request from {}: {} {}",
            remote_addr,
            req.method(),
            req.uri()
        );
        match non_connect_ip_response(config.censorship_resistant) {
            NonConnectIpResponse::CamouflageOk => {
                send_h3_camouflage_response(&mut req_stream).await?
            }
            NonConnectIpResponse::NotFound => {
                let response = Response::builder()
                    .status(http::StatusCode::NOT_FOUND)
                    .header("content-type", "text/html; charset=utf-8")
                    .body(())
                    .map_err(|e| anyhow::anyhow!("Response build error: {e}"))?;
                let _ = req_stream.send_response(response).await;
                let _ = req_stream
                    .send_data(Bytes::from_static(
                        b"<!DOCTYPE html><html><body><h1>404 Not Found</h1></body></html>",
                    ))
                    .await;
                let _ = req_stream.finish().await;
            }
        }
        return Ok(());
    }

    let token = req
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("")
        .to_string();

    let auth_result = authenticate_client(
        &token,
        remote_addr.ip(),
        &state,
        &config,
        as_token_validator(keycloak.as_ref()),
    )
    .await;

    let (assigned_ip, assigned_ip6, session_auth) = match auth_result {
        Ok(ips) => ips,
        Err(e) => {
            let error_msg = format!("Unauthorized: {e}");
            warn!("H3 Unauthorized from {}: {}", remote_addr, e);
            if config.censorship_resistant {
                send_h3_camouflage_response(&mut req_stream).await?;
            } else {
                let response = Response::builder()
                    .status(http::StatusCode::UNAUTHORIZED)
                    .body(())
                    .map_err(|e| anyhow::anyhow!("Response build error: {e}"))?;
                let _ = req_stream.send_response(response).await;
                let _ = req_stream.send_data(Bytes::from("Unauthorized")).await;
                let _ = req_stream.finish().await;
            }
            return Err(anyhow::anyhow!("H3 Error: {error_msg}"));
        }
    };

    let session_expiry = session_auth.as_ref().map(|v| v.exp);
    let session_subject = session_auth.map(|v| v.sub);

    let _ip_guard = IpGuard {
        state: state.clone(),
        ip4: assigned_ip,
        ip6: assigned_ip6,
    };

    let capsule_stream =
        build_connect_ip_capsules(&state, &config, assigned_ip, assigned_ip6, ipv6_enabled)?;

    let response = Response::builder()
        .status(http::StatusCode::OK)
        .header("capsule-protocol", CAPSULE_PROTOCOL)
        .header("cache-control", "no-store")
        .body(())
        .map_err(|e| anyhow::anyhow!("Response build error: {e}"))?;
    req_stream
        .send_response(response)
        .await
        .map_err(|e| anyhow::anyhow!("H3 send_response error: {e}"))?;
    req_stream
        .send_data(Bytes::from(capsule_stream))
        .await
        .map_err(|e| anyhow::anyhow!("H3 send_data error: {e}"))?;

    info!(
        "H3 Authenticated {} | SNI: {} -> IPv4: {}, IPv6: {}",
        remote_addr,
        sni.as_deref().unwrap_or("<none>"),
        assigned_ip,
        assigned_ip6
    );

    let connection_arc = Arc::new(connection);

    run_authenticated_tunnel(
        connection_arc,
        state.clone(),
        tx_tun,
        assigned_ip,
        assigned_ip6,
        session_expiry,
        session_subject,
        config.mtu,
        true, // is_h3
        keycloak,
    )
    .await
}

#[cfg(test)]
mod tests;
