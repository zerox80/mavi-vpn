use anyhow::Result;
use bytes::Bytes;
use http::Response;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{info, warn};

use shared::masque::{
    self, AssignedAddress, IpAddressRange, CAPSULE_ADDRESS_ASSIGN, CAPSULE_MAVI_CONFIG,
    CAPSULE_ROUTE_ADVERTISEMENT,
};
use shared::ControlMessage;

use crate::config::Config;
use crate::handlers::auth::authenticate_client;
use crate::handlers::connection::build_config_message;
use crate::handlers::tunnel::run_tunnel;
use crate::handlers::utils::{prefix_len_from_mask, IpGuard};
use crate::keycloak::KeycloakValidator;
use crate::state::AppState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NonConnectIpResponse {
    CamouflageOk,
    NotFound,
}

fn non_connect_ip_response(censorship_resistant: bool) -> NonConnectIpResponse {
    if censorship_resistant {
        NonConnectIpResponse::CamouflageOk
    } else {
        NonConnectIpResponse::NotFound
    }
}

#[allow(clippy::too_many_arguments)]
fn build_connect_ip_capsules(
    state: &AppState,
    config: &Config,
    assigned_ip: std::net::Ipv4Addr,
    assigned_ip6: std::net::Ipv6Addr,
    ipv6_enabled: bool,
) -> Result<Vec<u8>> {
    let success_msg = build_config_message(state, config, assigned_ip, assigned_ip6, ipv6_enabled);

    let mut capsule_stream: Vec<u8> = Vec::with_capacity(256);

    let mut address_assigns = vec![AssignedAddress {
        request_id: 0,
        ip: IpAddr::V4(assigned_ip),
        prefix_len: prefix_len_from_mask(state.network.mask()),
    }];
    if ipv6_enabled {
        address_assigns.push(AssignedAddress {
            request_id: 0,
            ip: IpAddr::V6(assigned_ip6),
            prefix_len: 64,
        });
    }
    masque::encode_capsule(
        CAPSULE_ADDRESS_ASSIGN,
        &masque::encode_address_assign(&address_assigns),
        &mut capsule_stream,
    );

    let mut routes = vec![IpAddressRange {
        start: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        end: IpAddr::V4(std::net::Ipv4Addr::BROADCAST),
        ip_protocol: 0,
    }];
    if ipv6_enabled {
        routes.push(IpAddressRange {
            start: IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            end: IpAddr::V6(std::net::Ipv6Addr::from([0xff; 16])),
            ip_protocol: 0,
        });
    }
    masque::encode_capsule(
        CAPSULE_ROUTE_ADVERTISEMENT,
        &masque::encode_route_advertisement(&routes),
        &mut capsule_stream,
    );

    let mavi_config_bytes =
        bincode::serde::encode_to_vec(&success_msg, bincode::config::standard())?;
    masque::encode_capsule(CAPSULE_MAVI_CONFIG, &mavi_config_bytes, &mut capsule_stream);

    Ok(capsule_stream)
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

    let resolver = h3_conn
        .accept()
        .await
        .map_err(|e| anyhow::anyhow!("H3 accept error: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("Expected H3 request"))?;
    let (req, mut req_stream) = resolver
        .resolve_request()
        .await
        .map_err(|e| anyhow::anyhow!("H3 resolve error: {e}"))?;
    let connect_ip_requested =
        req.extensions().get::<h3::ext::Protocol>().copied() == Some(h3::ext::Protocol::CONNECT_IP);
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
            NonConnectIpResponse::CamouflageOk => send_h3_camouflage_response(&mut req_stream).await?,
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
        &state,
        &config,
        keycloak
            .as_deref()
            .map(|kc| kc as &dyn crate::handlers::auth::TokenValidator),
    )
    .await;

    let (assigned_ip, assigned_ip6) = match auth_result {
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

    let _ip_guard = IpGuard {
        state: state.clone(),
        ip4: assigned_ip,
        ip6: assigned_ip6,
    };

    let capsule_stream =
        build_connect_ip_capsules(&state, &config, assigned_ip, assigned_ip6, ipv6_enabled)?;

    let response = Response::builder()
        .status(http::StatusCode::OK)
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

    let (tx_client, rx_client) = tokio::sync::mpsc::channel::<Bytes>(4096);
    state.register_client(assigned_ip, assigned_ip6, tx_client);

    let connection_arc = Arc::new(connection);

    run_tunnel(
        connection_arc,
        rx_client,
        tx_tun,
        assigned_ip,
        assigned_ip6,
        state.gateway_ip(),
        state.gateway_ip_v6(),
        config.mtu,
        true, // is_h3
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
        assert_eq!(non_connect_ip_response(false), NonConnectIpResponse::NotFound);
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
            bincode::serde::decode_from_slice(&capsules[2].1, bincode::config::standard())
                .unwrap();
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
            &build_connect_ip_capsules(
                &state,
                &config,
                Ipv4Addr::new(10, 8, 0, 2),
                ip6,
                true,
            )
            .unwrap(),
        );

        let assigns = decode_address_assign(&capsules[0].1).unwrap();
        assert_eq!(assigns.len(), 2);
        assert!(assigns
            .iter()
            .any(|a| a.ip == IpAddr::V6(ip6) && a.prefix_len == 64));

        let routes = decode_route_advertisement(&capsules[1].1).unwrap();
        assert_eq!(routes.len(), 2);
        assert!(routes.iter().any(|r| r.start == IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            && r.end == IpAddr::V6(Ipv6Addr::from([0xff; 16]))));

        let (cfg, _): (ControlMessage, _) =
            bincode::serde::decode_from_slice(&capsules[2].1, bincode::config::standard())
                .unwrap();
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
}
