use std::net::IpAddr;
use std::sync::Arc;
use anyhow::Result;
use bytes::Bytes;
use http::Response;
use tracing::{info, warn};

use shared::ControlMessage;
use shared::masque::{
    self, AssignedAddress, IpAddressRange, CAPSULE_ADDRESS_ASSIGN, CAPSULE_MAVI_CONFIG,
    CAPSULE_ROUTE_ADVERTISEMENT,
};

use crate::config::Config;
use crate::keycloak::KeycloakValidator;
use crate::state::AppState;
use crate::handlers::auth::authenticate_client;
use crate::handlers::tunnel::run_tunnel;
use crate::handlers::utils::{IpGuard, prefix_len_from_mask};

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

    let h3_conn_wrapper =
        crate::network::h3_quinn::Connection::with_pre_streams(connection.clone(), pre_bi, Some(pre_uni));
    let mut h3_conn = h3::server::builder()
        .enable_datagram(true)
        .enable_extended_connect(true)
        .build(h3_conn_wrapper)
        .await
        .map_err(|e| anyhow::anyhow!("H3 build failed: {}", e))?;

    let resolver = h3_conn.accept().await
        .map_err(|e| anyhow::anyhow!("H3 accept error: {}", e))?
        .ok_or_else(|| anyhow::anyhow!("Expected H3 request"))?;
    let (req, mut req_stream) = resolver.resolve_request().await
        .map_err(|e| anyhow::anyhow!("H3 resolve error: {}", e))?;
    let connect_ip_requested = req
        .extensions()
        .get::<h3::ext::Protocol>()
        .copied()
        == Some(h3::ext::Protocol::CONNECT_IP);
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
        let response = Response::builder()
            .status(http::StatusCode::NOT_FOUND)
            .header("content-type", "text/html; charset=utf-8")
            .body(())
            .map_err(|e| anyhow::anyhow!("Response build error: {}", e))?;
        let _ = req_stream.send_response(response).await;
        let _ = req_stream
            .send_data(Bytes::from_static(
                b"<!DOCTYPE html><html><body><h1>404 Not Found</h1></body></html>",
            ))
            .await;
        let _ = req_stream.finish().await;
        return Ok(());
    }

    let token = req.headers().get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("")
        .to_string();

    let auth_result = authenticate_client(&token, &state, &config, &keycloak).await;

    let (assigned_ip, assigned_ip6) = match auth_result {
        Ok(ips) => ips,
        Err(e) => {
            let error_msg = format!("Unauthorized: {}", e);
            warn!("H3 Unauthorized from {}: {}", remote_addr, e);
            let response = Response::builder()
                .status(http::StatusCode::UNAUTHORIZED)
                .body(())
                .map_err(|e| anyhow::anyhow!("Response build error: {}", e))?;
            let _ = req_stream.send_response(response).await;
            let _ = req_stream.send_data(Bytes::from("Unauthorized")).await;
            let _ = req_stream.finish().await;
            return Err(anyhow::anyhow!("H3 Error: {}", error_msg));
        }
    };

    let _ip_guard = IpGuard { state: state.clone(), ip4: assigned_ip, ip6: assigned_ip6 };

    let success_msg = ControlMessage::Config {
        assigned_ip,
        netmask: state.network.mask(),
        gateway: state.gateway_ip(),
        dns_server: config.dns,
        mtu: config.mtu,
        assigned_ipv6: if ipv6_enabled { Some(assigned_ip6) } else { None },
        netmask_v6: if ipv6_enabled { Some(64) } else { None },
        gateway_v6: if ipv6_enabled { Some(state.gateway_ip_v6()) } else { None },
        dns_server_v6: if ipv6_enabled {
            Some(config.dns_v6.unwrap_or_else(|| std::net::Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)))
        } else { None },
        whitelist_domains: Some(config.whitelist_domains.clone()),
    };
    
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

    let mavi_config_bytes = bincode::serde::encode_to_vec(&success_msg, bincode::config::standard())?;
    masque::encode_capsule(CAPSULE_MAVI_CONFIG, &mavi_config_bytes, &mut capsule_stream);

    let response = Response::builder()
        .status(http::StatusCode::OK)
        .body(())
        .map_err(|e| anyhow::anyhow!("Response build error: {}", e))?;
    req_stream.send_response(response).await
        .map_err(|e| anyhow::anyhow!("H3 send_response error: {}", e))?;
    req_stream.send_data(Bytes::from(capsule_stream)).await
        .map_err(|e| anyhow::anyhow!("H3 send_data error: {}", e))?;

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
    ).await
}
