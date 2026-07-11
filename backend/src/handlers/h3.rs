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
mod tests {
    use super::*;
    use clap::Parser;
    use shared::masque::{
        decode_address_assign, decode_route_advertisement, read_capsule, CAPSULE_ADDRESS_ASSIGN,
        CAPSULE_MAVI_CONFIG, CAPSULE_ROUTE_ADVERTISEMENT,
    };
    use shared::ControlMessage;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn test_config(args: &[&str]) -> Config {
        let mut argv = vec!["mavi-vpn", "--auth-token", "secret"];
        argv.extend_from_slice(args);
        Config::parse_from(argv)
    }

    fn collect_capsules(mut bytes: &[u8]) -> Vec<(u64, Vec<u8>)> {
        let mut capsules = Vec::new();
        while !bytes.is_empty() {
            let (ctype, payload, consumed) = read_capsule(bytes).expect("complete capsule");
            capsules.push((ctype, payload.to_vec()));
            bytes = &bytes[consumed..];
        }
        capsules
    }

    #[test]
    fn non_connect_ip_response_depends_on_censorship_mode() {
        assert_eq!(
            non_connect_ip_response(true),
            NonConnectIpResponse::CamouflageOk
        );
        assert_eq!(
            non_connect_ip_response(false),
            NonConnectIpResponse::NotFound
        );
    }

    fn connect_ip_request() -> http::Request<()> {
        let mut request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(CONNECT_IP_PATH)
            .header("capsule-protocol", CAPSULE_PROTOCOL)
            .body(())
            .unwrap();
        request
            .extensions_mut()
            .insert(h3::ext::Protocol::CONNECT_IP);
        request
    }

    #[test]
    fn connect_ip_request_requires_method_path_protocol_and_capsule_header() {
        let request = connect_ip_request();
        assert!(is_connect_ip_request(&request));

        let wrong_method = http::Request::builder()
            .method(http::Method::GET)
            .uri(CONNECT_IP_PATH)
            .header("capsule-protocol", CAPSULE_PROTOCOL)
            .body(())
            .unwrap();
        assert!(!is_connect_ip_request(&wrong_method));

        let wrong_path = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri("/.well-known/masque/ip/192.0.2.1/6/")
            .header("capsule-protocol", CAPSULE_PROTOCOL)
            .extension(h3::ext::Protocol::CONNECT_IP)
            .body(())
            .unwrap();
        assert!(!is_connect_ip_request(&wrong_path));

        let missing_protocol = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(CONNECT_IP_PATH)
            .header("capsule-protocol", CAPSULE_PROTOCOL)
            .body(())
            .unwrap();
        assert!(!is_connect_ip_request(&missing_protocol));

        let missing_capsule_protocol = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(CONNECT_IP_PATH)
            .extension(h3::ext::Protocol::CONNECT_IP)
            .body(())
            .unwrap();
        assert!(!is_connect_ip_request(&missing_capsule_protocol));
    }

    #[test]
    fn connect_ip_capsules_include_ipv4_only_assign_route_and_config() {
        let state = AppState::new("10.8.0.0/24").unwrap();
        let config = test_config(&["--whitelist-domains", "one.test,two.test"]);
        let capsules = collect_capsules(
            &build_connect_ip_capsules(
                &state,
                &config,
                Ipv4Addr::new(10, 8, 0, 2),
                Ipv6Addr::LOCALHOST,
                false,
            )
            .unwrap(),
        );

        assert_eq!(
            capsules.iter().map(|(t, _)| *t).collect::<Vec<_>>(),
            vec![
                CAPSULE_ADDRESS_ASSIGN,
                CAPSULE_ROUTE_ADVERTISEMENT,
                CAPSULE_MAVI_CONFIG
            ]
        );

        let assigns = decode_address_assign(&capsules[0].1).unwrap();
        assert_eq!(assigns.len(), 1);
        assert_eq!(assigns[0].ip, IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)));
        assert_eq!(assigns[0].prefix_len, 24);

        let routes = decode_route_advertisement(&capsules[1].1).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].start, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(routes[0].end, IpAddr::V4(Ipv4Addr::BROADCAST));

        let (cfg, _): (ControlMessage, _) =
            bincode::serde::decode_from_slice(&capsules[2].1, bincode::config::standard()).unwrap();
        match cfg {
            ControlMessage::Config {
                assigned_ipv6,
                whitelist_domains,
                ..
            } => {
                assert!(assigned_ipv6.is_none());
                assert_eq!(
                    whitelist_domains,
                    Some(vec!["one.test".to_string(), "two.test".to_string()])
                );
            }
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn connect_ip_capsules_include_dual_stack_and_default_dns_v6() {
        let state = AppState::new("10.8.0.0/24").unwrap();
        let config = test_config(&[]);
        let ip6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        let capsules = collect_capsules(
            &build_connect_ip_capsules(&state, &config, Ipv4Addr::new(10, 8, 0, 2), ip6, true)
                .unwrap(),
        );

        let assigns = decode_address_assign(&capsules[0].1).unwrap();
        assert_eq!(assigns.len(), 2);
        assert!(assigns
            .iter()
            .any(|a| a.ip == IpAddr::V6(ip6) && a.prefix_len == 64));

        let routes = decode_route_advertisement(&capsules[1].1).unwrap();
        assert_eq!(routes.len(), 2);
        assert!(routes
            .iter()
            .any(|r| r.start == IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                && r.end == IpAddr::V6(Ipv6Addr::from([0xff; 16]))));

        let (cfg, _): (ControlMessage, _) =
            bincode::serde::decode_from_slice(&capsules[2].1, bincode::config::standard()).unwrap();
        match cfg {
            ControlMessage::Config {
                assigned_ipv6,
                dns_server_v6,
                netmask_v6,
                ..
            } => {
                assert_eq!(assigned_ipv6, Some(ip6));
                assert_eq!(netmask_v6, Some(64));
                assert_eq!(
                    dns_server_v6,
                    Some(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111))
                );
            }
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn connect_ip_capsules_use_configured_ipv6_prefix() {
        let state = AppState::new_with_ipv6("10.8.0.0/24", "fd12:3456::/80").unwrap();
        let config = test_config(&[]);
        let ip6 = Ipv6Addr::new(0xfd12, 0x3456, 0, 0, 0, 0, 0, 2);
        let capsules = collect_capsules(
            &build_connect_ip_capsules(&state, &config, Ipv4Addr::new(10, 8, 0, 2), ip6, true)
                .unwrap(),
        );

        let assigns = decode_address_assign(&capsules[0].1).unwrap();
        assert!(assigns
            .iter()
            .any(|a| a.ip == IpAddr::V6(ip6) && a.prefix_len == 80));

        let (cfg, _): (ControlMessage, _) =
            bincode::serde::decode_from_slice(&capsules[2].1, bincode::config::standard()).unwrap();
        match cfg {
            ControlMessage::Config { netmask_v6, .. } => {
                assert_eq!(netmask_v6, Some(80));
            }
            other => panic!("expected Config, got {other:?}"),
        }
    }
}
