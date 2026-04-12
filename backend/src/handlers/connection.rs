use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};

use anyhow::Result;
use bytes::Bytes;
use constant_time_eq::constant_time_eq;
use etherparse::{Ipv4HeaderSlice, Ipv6HeaderSlice};
use futures_util::FutureExt;
use http::Response;
use shared::{
    icmp,
    masque::{
        self, AssignedAddress, IpAddressRange, CAPSULE_ADDRESS_ASSIGN, CAPSULE_MAVI_CONFIG,
        CAPSULE_ROUTE_ADVERTISEMENT,
    },
    ControlMessage,
};
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};

use crate::{config::Config, keycloak::KeycloakValidator, state::AppState};

const H3_DETECTION_GRACE: Duration = Duration::from_millis(50);

/// Convert an IPv4 dotted-decimal netmask to a CIDR prefix length in bits.
/// Non-contiguous masks (not realistic on a VPN subnet) fall back to `/32`.
fn prefix_len_from_mask(mask: std::net::Ipv4Addr) -> u8 {
    let bits = u32::from(mask);
    let ones = bits.count_ones() as u8;
    // Require the mask to be contiguous: all ones followed by all zeros.
    if bits.leading_ones() + bits.trailing_zeros() == 32 {
        ones
    } else {
        32
    }
}

pub struct IpGuard {
    pub state: Arc<AppState>,
    pub ip4: Ipv4Addr,
    pub ip6: Ipv6Addr,
}

impl Drop for IpGuard {
    fn drop(&mut self) {
        self.state.release_ips(self.ip4, self.ip6);
        info!("Released IPs for dropped connection: {} / {}", self.ip4, self.ip6);
    }
}

enum InitialStreams {
    Raw {
        send_stream: quinn::SendStream,
        recv_stream: quinn::RecvStream,
    },
    H3 {
        pre_bi: Option<(quinn::SendStream, quinn::RecvStream)>,
        pre_uni: quinn::RecvStream,
    },
}

fn negotiated_alpn(connection: &quinn::Connection) -> Option<Vec<u8>> {
    let handshake_data = connection.handshake_data()?;
    let handshake_data = handshake_data
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .ok()?;
    handshake_data.protocol.clone()
}

async fn detect_initial_streams(connection: &quinn::Connection) -> Result<InitialStreams> {
    match negotiated_alpn(connection).as_deref() {
        Some(protocol) if protocol == b"mavivpn" => {
            let (send_stream, recv_stream) = connection.accept_bi().await?;
            Ok(InitialStreams::Raw {
                send_stream,
                recv_stream,
            })
        }
        _ => {
            tokio::select! {
                biased;
                uni_res = connection.accept_uni() => {
                    Ok(InitialStreams::H3 {
                        pre_bi: None,
                        pre_uni: uni_res?,
                    })
                }
                bi_res = connection.accept_bi() => {
                    let pre_bi = bi_res?;
                    match tokio::time::timeout(H3_DETECTION_GRACE, connection.accept_uni()).await {
                        Ok(Ok(pre_uni)) => Ok(InitialStreams::H3 {
                            pre_bi: Some(pre_bi),
                            pre_uni,
                        }),
                        Ok(Err(err)) => Err(err.into()),
                        Err(_) => {
                            let (send_stream, recv_stream) = pre_bi;
                            Ok(InitialStreams::Raw {
                                send_stream,
                                recv_stream,
                            })
                        }
                    }
                }
            }
        }
    }
}

pub async fn handle_connection(
    conn: quinn::Incoming,
    state: Arc<AppState>,
    config: Config,
    tx_tun: tokio::sync::mpsc::Sender<Bytes>,
    keycloak: Option<Arc<KeycloakValidator>>,
    ipv6_enabled: bool,
) -> Result<()> {
    let connection = conn.await?;
    let remote_addr = connection.remote_address();
    info!("New connection from {}", remote_addr);

    let (pre_bi, pre_uni) = match detect_initial_streams(&connection).await? {
        InitialStreams::Raw {
            send_stream,
            recv_stream,
        } => (Some((send_stream, recv_stream)), None),
        InitialStreams::H3 { pre_bi, pre_uni } => (pre_bi, Some(pre_uni)),
    };

    if let Some(pre_uni) = pre_uni {
        return handle_h3_connection(
            connection,
            pre_bi,
            pre_uni,
            state,
            config,
            tx_tun,
            keycloak,
            ipv6_enabled,
        )
        .await;
    }

    let (mut send_stream, mut recv_stream) = pre_bi.expect("raw detection always includes a bidi stream");
    
    let auth_result: Result<(Ipv4Addr, Ipv6Addr)> = async {
        let buf = tokio::time::timeout(Duration::from_secs(5), async {
            let len = recv_stream.read_u32_le().await? as usize;
            if len > 16384 {
                anyhow::bail!("Auth message too big");
            }

            let mut buf = vec![0u8; len];
            recv_stream.read_exact(&mut buf).await?;
            Ok::<Vec<u8>, anyhow::Error>(buf)
        })
        .await
        .map_err(|_| anyhow::anyhow!("Handshake timeout"))??;
        
        let msg: ControlMessage = bincode::serde::decode_from_slice(&buf, bincode::config::standard())
            .map(|(v, _)| v)
            .map_err(|e| anyhow::anyhow!("Protocol error: {}", e))?;
        
        match msg {
            ControlMessage::Auth { token } => {
                if let Some(kc) = &keycloak {
                    if !kc.validate_token(&token).await? {
                         anyhow::bail!("Access Denied: Invalid Keycloak Token");
                    }
                } else if !constant_time_eq(token.as_bytes(), config.auth_token.as_bytes()) {
                    anyhow::bail!("Access Denied: Invalid Token");
                }

                state.assign_ip_pair()
            }
            _ => anyhow::bail!("Protocol error: Expected Auth"),
        }
    }.await;

    let (assigned_ip, assigned_ip6) = match auth_result {
        Ok(ips) => ips,
        Err(e) => {
            let error_msg = format!("Unauthorized: {}", e);
            if config.censorship_resistant {
                warn!("Unauthorized probe from {}. Emulating HTTP/3. Error: {}", remote_addr, e);
                let _ = emulate_http3(&connection, &mut send_stream).await;
                return Err(anyhow::anyhow!("HTTP/3 probe response sent: {}", e));
            } else {
                let err_payload = ControlMessage::Error { message: error_msg.clone() };
                if let Ok(encoded) = bincode::serde::encode_to_vec(&err_payload, bincode::config::standard()) {
                    let _ = send_stream.write_u32_le(encoded.len() as u32).await;
                    let _ = send_stream.write_all(&encoded).await;
                    let _ = send_stream.finish();
                }
                return Err(anyhow::anyhow!("{}", error_msg));
            }
        }
    };

    let _ip_guard = IpGuard { state: state.clone(), ip4: assigned_ip, ip6: assigned_ip6 };

    let success_msg = ControlMessage::Config {
        assigned_ip,
        netmask: state.network.mask(),
        gateway: state.gateway_ip(),
        dns_server: config.dns,
        mtu: config.mtu as u16,
        assigned_ipv6: if ipv6_enabled { Some(assigned_ip6) } else { None },
        netmask_v6: if ipv6_enabled { Some(64) } else { None },
        gateway_v6: if ipv6_enabled { Some(state.gateway_ip_v6()) } else { None },
        dns_server_v6: if ipv6_enabled {
            // Use Ipv6Addr::new() instead of parsing a string to avoid a potential panic.
            Some(config.dns_v6.unwrap_or_else(|| std::net::Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)))
        } else { None },
        whitelist_domains: Some(config.whitelist_domains.clone()),
    };
    
    let bytes = bincode::serde::encode_to_vec(&success_msg, bincode::config::standard())?;
    send_stream.write_u32_le(bytes.len() as u32).await?;
    send_stream.write_all(&bytes).await?;
    let _ = send_stream.finish();

    info!("Authenticated {} -> IPv4: {}, IPv6: {}", remote_addr, assigned_ip, assigned_ip6);

    let (tx_client, mut rx_client) = tokio::sync::mpsc::channel::<Bytes>(4096);
    state.register_client(assigned_ip, assigned_ip6, tx_client);

    let connection = Arc::new(connection);
    let conn_send = connection.clone();
    let tx_tun_icmp = tx_tun.clone();
    let gv4 = state.gateway_ip();
    let gv6 = state.gateway_ip_v6();
    let tunnel_mtu = config.mtu;
    
    let tun_to_quic = tokio::spawn(async move {
        while let Some(packet) = rx_client.recv().await {
            if let Err(e) = conn_send.send_datagram(packet.clone()) {
                if matches!(e, quinn::SendDatagramError::TooLarge) {
                    if packet.is_empty() {
                        continue;
                    }

                    let ver = packet[0] >> 4;
                    let gw = if ver == 4 {
                        Some(std::net::IpAddr::V4(gv4))
                    } else if ver == 6 {
                        Some(std::net::IpAddr::V6(gv6))
                    } else {
                        None
                    };
                    let reported_mtu = if ver == 6 {
                        tunnel_mtu.max(1280)
                    } else {
                        tunnel_mtu
                    };

                    if let Some(icmp_p) = icmp::generate_packet_too_big(
                        &packet,
                        reported_mtu,
                        gw,
                    ) {
                        let _ = tx_tun_icmp.try_send(Bytes::from(icmp_p));
                    }
                }
            }
        }
    });

    let conn_stats = connection.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let stats = conn_stats.stats();
            info!(
                "[SERVER QUIC STATS] Peer: {} | RTT: {}ms | CWND: {} bytes | Lost Packets: {} | Max Datagram: {}",
                remote_addr,
                stats.path.rtt.as_millis(),
                stats.path.cwnd,
                stats.path.lost_packets,
                conn_stats.max_datagram_size().unwrap_or(0)
            );
            if conn_stats.close_reason().is_some() { break; }
        }
    });

    let res = 'outer_loop: loop {
        let first_packet = match connection.read_datagram().await {
            Ok(data) => data,
            Err(e) => break Err(anyhow::anyhow!("Lost: {}", e)),
        };

        let mut batch = Vec::with_capacity(64);
        batch.push(first_packet);

        for _ in 0..63 {
            if let Some(Ok(p)) = connection.read_datagram().now_or_never() {
                batch.push(p);
            } else {
                break;
            }
        }

        for data in batch {
            if data.is_empty() { continue; }
            let ver = data[0] >> 4;
            let mut valid = false;
            if ver == 4 {
                if let Ok(h) = Ipv4HeaderSlice::from_slice(&data) {
                    if h.source_addr() == assigned_ip { valid = true; }
                }
            } else if ver == 6 {
                if let Ok(h) = Ipv6HeaderSlice::from_slice(&data) {
                    if h.source_addr() == assigned_ip6 { valid = true; }
                }
            }
            
            if valid {
                if tx_tun.send(data).await.is_err() {
                    break 'outer_loop Err(anyhow::anyhow!("TUN closed"));
                }
            } else if tx_tun.is_closed() {
                break 'outer_loop Err(anyhow::anyhow!("TUN closed"));
            }
        }
    };

    tun_to_quic.abort();
    res
}

async fn emulate_http3(conn: &quinn::Connection, stream: &mut quinn::SendStream) -> Result<()> {
    if let Ok(mut ctrl) = conn.open_uni().await {
        let _ = ctrl.write_all(&[0x00, 0x04, 0x00]).await;
        let _ = ctrl.finish();
    }
    let mut resp = vec![0x01, 0x19];
    resp.extend_from_slice(&[0x00, 0x00, 0xd9, 0x5f, 0x4d, 0x84, 0xaa, 0x63, 0x55, 0xe7, 0x5f, 0x1d, 0x87, 0x49, 0x7c, 0xa5, 0x89, 0xd3, 0x4d, 0x1f, 0x54, 0x03, 0x31, 0x37, 0x33]);
    let body = b"<html><body><h1>Welcome</h1></body></html>";
    resp.push(0x00); resp.push(body.len() as u8);
    resp.extend_from_slice(body);
    let _ = stream.write_all(&resp).await;
    let _ = stream.finish();
    tokio::time::sleep(Duration::from_millis(50)).await;
    Ok(())
}

pub async fn handle_h3_connection(
    connection: quinn::Connection,
    pre_bi: Option<(quinn::SendStream, quinn::RecvStream)>,
    pre_uni: quinn::RecvStream,
    state: Arc<AppState>,
    config: Config,
    tx_tun: tokio::sync::mpsc::Sender<Bytes>,
    keycloak: Option<Arc<KeycloakValidator>>,
    ipv6_enabled: bool,
) -> Result<()> {
    let remote_addr = connection.remote_address();
    info!("Detected HTTP/3 L7 client from {}", remote_addr);

    let h3_conn_wrapper =
        crate::network::h3_quinn::Connection::with_pre_streams(connection.clone(), pre_bi, Some(pre_uni));
    let mut h3_conn = h3::server::builder()
        .enable_datagram(true)
        .enable_extended_connect(true)
        .build(h3_conn_wrapper)
        .await
        .map_err(|e| anyhow::anyhow!("H3 build failed: {}", e))?;

    // accept() returns a RequestResolver; call resolve_request() to get (Request, RequestStream)
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

    // Reject anything that is not an extended CONNECT with `:protocol=connect-ip`.
    // Responding with capsules to a plain GET would be an immediate DPI tell, and
    // it would also be a protocol violation (the MAVI_CONFIG/ADDRESS_ASSIGN flow
    // below is only meaningful for a real connect-ip session). We emit a generic
    // 404 + tiny HTML body so the stream looks like an ordinary web server
    // answering for an unknown path, then finish the stream cleanly.
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

    let auth_result: Result<(Ipv4Addr, Ipv6Addr)> = async {
        if let Some(kc) = &keycloak {
            if !kc.validate_token(&token).await? {
                anyhow::bail!("Access Denied: Invalid Keycloak Token");
            }
        } else if !constant_time_eq(token.as_bytes(), config.auth_token.as_bytes()) {
            anyhow::bail!("Access Denied: Invalid Token");
        }
        state.assign_ip_pair()
    }.await;

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
        mtu: config.mtu as u16,
        assigned_ipv6: if ipv6_enabled { Some(assigned_ip6) } else { None },
        netmask_v6: if ipv6_enabled { Some(64) } else { None },
        gateway_v6: if ipv6_enabled { Some(state.gateway_ip_v6()) } else { None },
        dns_server_v6: if ipv6_enabled {
            Some(config.dns_v6.unwrap_or_else(|| std::net::Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)))
        } else { None },
        whitelist_domains: Some(config.whitelist_domains.clone()),
    };
    
    // Build the MASQUE capsule stream. We always emit IETF-standard
    // `ADDRESS_ASSIGN` (0x01) and `ROUTE_ADVERTISEMENT` (0x03) capsules so
    // the wire format matches RFC 9484 byte-for-byte, then append a vendor
    // `MAVI_CONFIG` capsule (0x4D56) carrying the full bincode-encoded
    // `ControlMessage::Config`. Unknown capsules MUST be ignored per RFC 9297,
    // so standard MASQUE clients see only valid connect-ip framing.
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
    // IMPORTANT: the request stream must stay open for the whole connect-ip
    // session so we can push additional capsules later and so the client side
    // does not interpret a FIN as session teardown. Do NOT call req_stream.finish().

    info!("H3 Authenticated {} -> IPv4: {}, IPv6: {}", remote_addr, assigned_ip, assigned_ip6);

    // VPN data plane: connect-ip datagrams on the request stream (RFC 9484 §5).
    // Each datagram is framed as: [Quarter Stream ID varint] [Context ID varint] [IP Packet].
    // For stream ID 0 + Context ID 0 this is a 2-byte 0x00 0x00 prefix.
    let (tx_client, mut rx_client) = tokio::sync::mpsc::channel::<Bytes>(4096);
    state.register_client(assigned_ip, assigned_ip6, tx_client);

    let conn_send = connection.clone();
    let tx_tun_icmp = tx_tun.clone();
    let gv4 = state.gateway_ip();
    let gv6 = state.gateway_ip_v6();
    let tunnel_mtu = config.mtu;

    // TUN -> QUIC (with connect-ip datagram framing)
    let tun_to_quic = tokio::spawn(async move {
        while let Some(packet) = rx_client.recv().await {
            // Prepend [Quarter Stream ID = 0] [Context ID = 0] per RFC 9484 §5
            let mut h3_payload = Vec::with_capacity(packet.len() + masque::DATAGRAM_PREFIX.len());
            h3_payload.extend_from_slice(&masque::DATAGRAM_PREFIX);
            h3_payload.extend_from_slice(&packet);

            if let Err(e) = conn_send.send_datagram(Bytes::from(h3_payload)) {
                if matches!(e, quinn::SendDatagramError::TooLarge) {
                    if packet.is_empty() { continue; }
                    let ver = packet[0] >> 4;
                    let gw = if ver == 4 {
                        Some(std::net::IpAddr::V4(gv4))
                    } else if ver == 6 {
                        Some(std::net::IpAddr::V6(gv6))
                    } else {
                        None
                    };
                    let reported_mtu = if ver == 6 { tunnel_mtu.max(1280) } else { tunnel_mtu };
                    if let Some(icmp_p) = icmp::generate_packet_too_big(&packet, reported_mtu, gw) {
                        let _ = tx_tun_icmp.try_send(Bytes::from(icmp_p));
                    }
                }
            }
        }
    });

    // QUIC -> TUN (strip connect-ip datagram framing)
    let res = 'outer_loop: loop {
        let first_dg = match connection.read_datagram().await {
            Ok(data) => data,
            Err(e) => break Err(anyhow::anyhow!("H3 connection lost: {}", e)),
        };

        let mut batch = Vec::with_capacity(64);
        batch.push(first_dg);
        for _ in 0..63 {
            if let Some(Ok(p)) = connection.read_datagram().now_or_never() {
                batch.push(p);
            } else {
                break;
            }
        }

        for datagram in batch {
            // Strip [Quarter Stream ID] [Context ID] per RFC 9484 §5.
            let inner_len = match masque::unwrap_datagram(&datagram) {
                Some(slice) => slice.len(),
                None => continue,
            };
            if inner_len == 0 { continue; }
            let prefix_len = datagram.len() - inner_len;
            let packet = datagram.slice(prefix_len..);
            if packet.is_empty() { continue; }

            let ver = packet[0] >> 4;
            let mut valid = false;
            if ver == 4 {
                if let Ok(h) = Ipv4HeaderSlice::from_slice(&packet) {
                    if h.source_addr() == assigned_ip { valid = true; }
                }
            } else if ver == 6 {
                if let Ok(h) = Ipv6HeaderSlice::from_slice(&packet) {
                    if h.source_addr() == assigned_ip6 { valid = true; }
                }
            }

            if valid {
                if tx_tun.send(packet).await.is_err() {
                    break 'outer_loop Err(anyhow::anyhow!("TUN closed"));
                }
            } else if tx_tun.is_closed() {
                break 'outer_loop Err(anyhow::anyhow!("TUN closed"));
            }
        }
    };

    tun_to_quic.abort();
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_len_slash_24() {
        assert_eq!(prefix_len_from_mask(Ipv4Addr::new(255, 255, 255, 0)), 24);
    }

    #[test]
    fn prefix_len_slash_16() {
        assert_eq!(prefix_len_from_mask(Ipv4Addr::new(255, 255, 0, 0)), 16);
    }

    #[test]
    fn prefix_len_slash_8() {
        assert_eq!(prefix_len_from_mask(Ipv4Addr::new(255, 0, 0, 0)), 8);
    }

    #[test]
    fn prefix_len_slash_32() {
        assert_eq!(prefix_len_from_mask(Ipv4Addr::new(255, 255, 255, 255)), 32);
    }

    #[test]
    fn prefix_len_slash_0() {
        assert_eq!(prefix_len_from_mask(Ipv4Addr::new(0, 0, 0, 0)), 0);
    }

    #[test]
    fn prefix_len_slash_25() {
        assert_eq!(prefix_len_from_mask(Ipv4Addr::new(255, 255, 255, 128)), 25);
    }

    #[test]
    fn prefix_len_non_contiguous_fallback() {
        // Non-contiguous mask like 255.0.255.0 should fall back to /32
        assert_eq!(prefix_len_from_mask(Ipv4Addr::new(255, 0, 255, 0)), 32);
    }
}
