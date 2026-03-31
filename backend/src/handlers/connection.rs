use anyhow::Result;
use bytes::Bytes;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};
use etherparse::{Ipv4HeaderSlice, Ipv6HeaderSlice};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use shared::ControlMessage;
use shared::icmp;
use futures_util::FutureExt;
use constant_time_eq::constant_time_eq;

use crate::config::Config;
use crate::state::AppState;
use crate::keycloak::KeycloakValidator;

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

    let (mut send_stream, mut recv_stream) = connection.accept_bi().await?;
    
    let auth_result: Result<(Ipv4Addr, Ipv6Addr)> = async {
        let len = tokio::time::timeout(Duration::from_secs(5), recv_stream.read_u32_le())
            .await
            .map_err(|_| anyhow::anyhow!("Handshake timeout"))?? as usize;
        
        if len > 16384 { anyhow::bail!("Auth message too big"); }
        let mut buf = vec![0u8; len];
        recv_stream.read_exact(&mut buf).await?;
        
        let msg: ControlMessage = bincode::serde::decode_from_slice(&buf, bincode::config::standard())
            .map(|(v, _)| v)
            .map_err(|e| anyhow::anyhow!("Protocol error: {}", e))?;
        
        match msg {
            ControlMessage::Auth { token } => {
                if let Some(kc) = &keycloak {
                    if !kc.validate_token(&token).await? {
                         anyhow::bail!("Access Denied: Invalid Keycloak Token");
                    }
                } else {
                    if !constant_time_eq(token.as_bytes(), config.auth_token.as_bytes()) {
                        anyhow::bail!("Access Denied: Invalid Token");
                    }
                }

                let v4 = state.assign_ip()?;
                let v6 = state.assign_ipv6()?;
                Ok((v4, v6))
            }
            _ => anyhow::bail!("Protocol error: Expected Auth"),
        }
    }.await;

    let (assigned_ip, assigned_ip6) = match auth_result {
        Ok(ips) => ips,
        Err(e) => {
            let error_msg = format!("Unauthorized: {}", e);
            let err_payload = ControlMessage::Error { message: error_msg.clone() };
            if let Ok(encoded) = bincode::serde::encode_to_vec(&err_payload, bincode::config::standard()) {
                let _ = send_stream.write_u32_le(encoded.len() as u32).await;
                let _ = send_stream.write_all(&encoded).await;
                let _ = send_stream.finish();
            }

            if config.censorship_resistant {
                warn!("Unauthorized probe from {}. Emulating HTTP/3. Error: {}", remote_addr, e);
                let _ = emulate_http3(&connection, &mut send_stream).await;
                return Err(anyhow::anyhow!("HTTP/3 probe response sent: {}", e));
            } else {
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
        dns_server_v6: if ipv6_enabled { Some("2001:4860:4860::8888".parse().unwrap()) } else { None },
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
    
    let tun_to_quic = tokio::spawn(async move {
        while let Some(packet) = rx_client.recv().await {
            if let Err(e) = conn_send.send_datagram(packet.clone()) {
                if matches!(e, quinn::SendDatagramError::TooLarge) {
                    let mtu = conn_send.max_datagram_size().unwrap_or(1200) as u16;
                    let ver = packet[0] >> 4;
                    let gw = if ver == 4 { std::net::IpAddr::V4(gv4) } else { std::net::IpAddr::V6(gv6) };
                    if let Some(icmp_p) = icmp::generate_packet_too_big(&packet, mtu, Some(gw)) {
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
                    if h.source_addr() == assigned_ip6 || h.source_addr().is_unspecified() { valid = true; }
                }
            }
            if valid {
                if tx_tun.send(data).await.is_err() { break 'outer_loop Err(anyhow::anyhow!("TUN closed")); }
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
