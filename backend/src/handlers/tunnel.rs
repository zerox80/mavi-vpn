use anyhow::Result;
use bytes::Bytes;
use etherparse::{Ipv4HeaderSlice, Ipv6HeaderSlice};
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::info;

use shared::{icmp, masque};

#[derive(Default)]
struct TunnelStats {
    server_to_client_bytes: AtomicU64,
    server_to_client_packets: AtomicU64,
    server_to_client_send_errors: AtomicU64,
    server_to_client_too_large: AtomicU64,
    server_to_client_queue_len: AtomicU64,
    client_to_server_bytes: AtomicU64,
    client_to_server_packets: AtomicU64,
    client_to_server_tun_drops: AtomicU64,
}

fn server_to_client_datagram(framed: Bytes, is_h3: bool) -> Option<(Bytes, Bytes)> {
    if framed.len() < masque::DATAGRAM_PREFIX.len() {
        return None;
    }
    let packet = framed.slice(masque::DATAGRAM_PREFIX.len()..);
    if is_h3 {
        Some((framed, packet))
    } else {
        Some((packet.clone(), packet))
    }
}

fn client_to_server_packet(datagram: Bytes, is_h3: bool) -> Option<Bytes> {
    if datagram.is_empty() {
        return None;
    }
    if !is_h3 {
        return Some(datagram);
    }

    let inner_len = masque::unwrap_datagram(&datagram)?.len();
    if inner_len == 0 {
        return None;
    }
    let prefix_len = datagram.len() - inner_len;
    Some(datagram.slice(prefix_len..))
}

fn packet_source_is_assigned(packet: &[u8], assigned_ip: Ipv4Addr, assigned_ip6: Ipv6Addr) -> bool {
    if packet.is_empty() {
        return false;
    }

    match packet[0] >> 4 {
        4 => Ipv4HeaderSlice::from_slice(packet).is_ok_and(|h| h.source_addr() == assigned_ip),
        6 => Ipv6HeaderSlice::from_slice(packet).is_ok_and(|h| h.source_addr() == assigned_ip6),
        _ => false,
    }
}

fn packet_too_big_response(
    packet: &[u8],
    tunnel_mtu: u16,
    max_datagram: Option<usize>,
    h3_prefix: usize,
    gv4: Ipv4Addr,
    gv6: Ipv6Addr,
) -> Option<Vec<u8>> {
    if packet.is_empty() {
        return None;
    }

    let ver = packet[0] >> 4;
    let gw = if ver == 4 {
        Some(IpAddr::V4(gv4))
    } else if ver == 6 {
        Some(IpAddr::V6(gv6))
    } else {
        None
    };
    // Report the MTU the QUIC datagram path can actually carry (max_datagram
    // minus any H3 prefix), not the configured TUN MTU — otherwise PMTUD never
    // shrinks below the QUIC limit and full-size packets keep getting dropped.
    let reported_mtu = shared::effective_ptb_mtu(tunnel_mtu, max_datagram, h3_prefix, ver == 6);

    icmp::generate_packet_too_big(packet, reported_mtu, gw)
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
#[allow(clippy::cast_precision_loss)]
pub async fn run_tunnel(
    connection: Arc<quinn::Connection>,
    mut rx_client: mpsc::Receiver<Bytes>,
    tx_tun: mpsc::Sender<Bytes>,
    assigned_ip: Ipv4Addr,
    assigned_ip6: Ipv6Addr,
    gv4: Ipv4Addr,
    gv6: Ipv6Addr,
    tunnel_mtu: u16,
    is_h3: bool,
) -> Result<()> {
    let conn_send = connection.clone();
    let tx_tun_icmp = tx_tun.clone();
    let tunnel_stats = Arc::new(TunnelStats::default());
    let send_stats = tunnel_stats.clone();

    let tun_to_quic = tokio::spawn(async move {
        while let Some(framed) = rx_client.recv().await {
            send_stats
                .server_to_client_queue_len
                .store(rx_client.len() as u64, Ordering::Relaxed);

            let Some((datagram_to_send, packet_for_icmp)) =
                server_to_client_datagram(framed, is_h3)
            else {
                continue;
            };

            send_stats
                .server_to_client_bytes
                .fetch_add(packet_for_icmp.len() as u64, Ordering::Relaxed);
            send_stats
                .server_to_client_packets
                .fetch_add(1, Ordering::Relaxed);

            if let Err(e) = conn_send.send_datagram(datagram_to_send) {
                send_stats
                    .server_to_client_send_errors
                    .fetch_add(1, Ordering::Relaxed);
                if matches!(e, quinn::SendDatagramError::TooLarge) {
                    send_stats
                        .server_to_client_too_large
                        .fetch_add(1, Ordering::Relaxed);
                    let h3_prefix = if is_h3 {
                        masque::DATAGRAM_PREFIX.len()
                    } else {
                        0
                    };
                    if let Some(icmp_p) = packet_too_big_response(
                        &packet_for_icmp,
                        tunnel_mtu,
                        conn_send.max_datagram_size(),
                        h3_prefix,
                        gv4,
                        gv6,
                    ) {
                        let _ = tx_tun_icmp.try_send(Bytes::from(icmp_p));
                    }
                }
            }
        }
    });

    let stats_conn = connection.clone();
    let stats = tunnel_stats.clone();
    let stats_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        let mut last_server_to_client_bytes = 0;
        let mut last_client_to_server_bytes = 0;
        let mut sent_udp_bytes_last = 0;
        let mut received_udp_bytes_last = 0;
        loop {
            interval.tick().await;
            let quic = stats_conn.stats();
            let server_to_client_bytes = stats.server_to_client_bytes.load(Ordering::Relaxed);
            let client_to_server_bytes = stats.client_to_server_bytes.load(Ordering::Relaxed);
            let server_to_client_mbps =
                (server_to_client_bytes - last_server_to_client_bytes) as f64 * 8.0 / 5_000_000.0;
            let client_to_server_mbps =
                (client_to_server_bytes - last_client_to_server_bytes) as f64 * 8.0 / 5_000_000.0;
            let egress_mbps = (quic.udp_tx.bytes - sent_udp_bytes_last) as f64 * 8.0 / 5_000_000.0;
            let ingress_mbps =
                (quic.udp_rx.bytes - received_udp_bytes_last) as f64 * 8.0 / 5_000_000.0;
            last_server_to_client_bytes = server_to_client_bytes;
            last_client_to_server_bytes = client_to_server_bytes;
            sent_udp_bytes_last = quic.udp_tx.bytes;
            received_udp_bytes_last = quic.udp_rx.bytes;

            info!(
                "[SERVER TUNNEL STATS] peer_ip={} s2c_app={:.1}mbit c2s_app={:.1}mbit quic_udp_tx={:.1}mbit quic_udp_rx={:.1}mbit rtt={}ms cwnd={} lost_pkts={} lost_bytes={} max_dgram={} dgram_space={} s2c_pkts={} s2c_queue_len={} s2c_send_err={} s2c_too_large={} c2s_pkts={} c2s_tun_drops={}",
                assigned_ip,
                server_to_client_mbps,
                client_to_server_mbps,
                egress_mbps,
                ingress_mbps,
                quic.path.rtt.as_millis(),
                quic.path.cwnd,
                quic.path.lost_packets,
                quic.path.lost_bytes,
                stats_conn.max_datagram_size().unwrap_or(0),
                stats_conn.datagram_send_buffer_space(),
                stats.server_to_client_packets.load(Ordering::Relaxed),
                stats.server_to_client_queue_len.load(Ordering::Relaxed),
                stats.server_to_client_send_errors.load(Ordering::Relaxed),
                stats.server_to_client_too_large.load(Ordering::Relaxed),
                stats.client_to_server_packets.load(Ordering::Relaxed),
                stats.client_to_server_tun_drops.load(Ordering::Relaxed),
            );

            if stats_conn.close_reason().is_some() {
                break;
            }
        }
    });

    let res = loop {
        let datagram = match connection.read_datagram().await {
            Ok(data) => data,
            Err(e) => break Err(anyhow::anyhow!("Connection lost: {e}")),
        };

        let Some(packet) = client_to_server_packet(datagram, is_h3) else {
            continue;
        };

        if packet_source_is_assigned(&packet, assigned_ip, assigned_ip6) {
            tunnel_stats
                .client_to_server_bytes
                .fetch_add(packet.len() as u64, Ordering::Relaxed);
            tunnel_stats
                .client_to_server_packets
                .fetch_add(1, Ordering::Relaxed);
            if let Err(e) = tx_tun.try_send(packet) {
                tunnel_stats
                    .client_to_server_tun_drops
                    .fetch_add(1, Ordering::Relaxed);
                if matches!(e, mpsc::error::TrySendError::Closed(_)) {
                    break Err(anyhow::anyhow!("TUN closed"));
                }
            }
        } else if tx_tun.is_closed() {
            break Err(anyhow::anyhow!("TUN closed"));
        }
    };

    tun_to_quic.abort();
    stats_task.abort();
    res
}

/// Runs a CONNECT-IP tunnel transported by HTTP/2 DATA frames.
///
/// RFC 9297 maps HTTP Datagrams to reliable `DATAGRAM` capsules when the
/// underlying HTTP version cannot carry QUIC datagrams.  The global routing
/// table stays deliberately transport-agnostic: it emits the existing H3
/// context-zero prefix, which is removed here before being put into a capsule.
#[allow(clippy::too_many_arguments)]
pub async fn run_http2_tunnel(
    on_upgrade: OnUpgrade,
    initial_capsules: Vec<u8>,
    state: Arc<crate::state::AppState>,
    tx_tun: mpsc::Sender<Bytes>,
    assigned_ip: Ipv4Addr,
    assigned_ip6: Ipv6Addr,
    tunnel_mtu: u16,
    session_expiry: Option<i64>,
) -> Result<()> {
    const CLIENT_CHANNEL_CAPACITY: usize = 4096;
    let upgraded = on_upgrade
        .await
        .map_err(|error| anyhow::anyhow!("HTTP/2 CONNECT upgrade failed: {error}"))?;
    let (mut request_stream, mut response_stream) = tokio::io::split(TokioIo::new(upgraded));
    response_stream.write_all(&initial_capsules).await?;
    let (tx_client, mut rx_client) = mpsc::channel::<Bytes>(CLIENT_CHANNEL_CAPACITY);
    state.register_client(assigned_ip, assigned_ip6, tx_client);

    let server_to_client = async move {
        while let Some(framed) = rx_client.recv().await {
            let Some((_frame, packet)) = server_to_client_datagram(framed, false) else {
                continue;
            };
            let capsule = masque::encode_connect_ip_datagram_capsule(&packet);
            response_stream.write_all(&capsule).await?;
        }
        Ok(())
    };

    let client_to_server = async move {
        let mut capsule_buf = Vec::new();
        let mut read_buf = [0_u8; 16 * 1024];
        loop {
            let read = request_stream.read(&mut read_buf).await?;
            if read == 0 {
                break;
            }
            capsule_buf.extend_from_slice(&read_buf[..read]);
            if capsule_buf.len() > masque::MAX_CAPSULE_BUF {
                anyhow::bail!("HTTP/2 capsule buffer exceeds limit");
            }

            while let Some((capsule_type, payload, consumed)) = masque::read_capsule(&capsule_buf) {
                if capsule_type == masque::CAPSULE_DATAGRAM {
                    let Some(packet) = masque::decode_connect_ip_datagram_payload(payload) else {
                        anyhow::bail!("malformed HTTP/2 CONNECT-IP DATAGRAM capsule");
                    };
                    // The negotiated TUN MTU is a hard per-packet ceiling;
                    // enforce it before the packet reaches the shared TUN.
                    if packet.len() <= usize::from(tunnel_mtu)
                        && packet_source_is_assigned(packet, assigned_ip, assigned_ip6)
                    {
                        match tx_tun.try_send(Bytes::copy_from_slice(packet)) {
                            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                anyhow::bail!("TUN closed");
                            }
                        }
                    }
                }
                capsule_buf.drain(..consumed);
            }
        }
        if !capsule_buf.is_empty() {
            anyhow::bail!("truncated HTTP/2 capsule at end of request body");
        }
        Ok(())
    };

    let tunnel = async {
        tokio::select! {
            result = server_to_client => result,
            result = client_to_server => result,
        }
    };
    if let Some(deadline) = crate::handlers::connection::session_deadline(session_expiry) {
        tokio::select! {
            result = tunnel => result,
            () = tokio::time::sleep_until(deadline) => Ok(()),
        }
    } else {
        tunnel.await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(20u16).to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p
    }

    fn ipv6_packet(src: Ipv6Addr, dst: Ipv6Addr) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[6] = 17;
        p[7] = 64;
        p[8..24].copy_from_slice(&src.octets());
        p[24..40].copy_from_slice(&dst.octets());
        p
    }

    #[test]
    fn raw_mode_strips_masque_prefix_for_server_to_client() {
        let packet = ipv4_packet(Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(10, 8, 0, 2));
        let framed = Bytes::from(masque::wrap_datagram(&packet));

        let (datagram, packet_for_icmp) = server_to_client_datagram(framed, false).unwrap();

        assert_eq!(datagram.as_ref(), packet.as_slice());
        assert_eq!(packet_for_icmp.as_ref(), packet.as_slice());
    }

    #[test]
    fn h3_mode_preserves_masque_prefix_for_server_to_client() {
        let packet = ipv4_packet(Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(10, 8, 0, 2));
        let framed = Bytes::from(masque::wrap_datagram(&packet));

        let (datagram, packet_for_icmp) = server_to_client_datagram(framed.clone(), true).unwrap();

        assert_eq!(datagram, framed);
        assert_eq!(packet_for_icmp.as_ref(), packet.as_slice());
    }

    #[test]
    fn h3_client_datagrams_unwrap_and_empty_payloads_are_ignored() {
        let packet = ipv4_packet(Ipv4Addr::new(10, 8, 0, 2), Ipv4Addr::new(1, 1, 1, 1));
        let framed = Bytes::from(masque::wrap_datagram(&packet));

        assert_eq!(
            client_to_server_packet(framed, true).unwrap().as_ref(),
            packet.as_slice()
        );
        assert!(
            client_to_server_packet(Bytes::from_static(&masque::DATAGRAM_PREFIX), true).is_none()
        );
        assert!(client_to_server_packet(Bytes::from_static(&[0x40]), true).is_none());
    }

    #[test]
    fn client_source_ip_spoofing_is_rejected() {
        let assigned_v4 = Ipv4Addr::new(10, 8, 0, 2);
        let assigned_v6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);

        assert!(packet_source_is_assigned(
            &ipv4_packet(assigned_v4, Ipv4Addr::new(1, 1, 1, 1)),
            assigned_v4,
            assigned_v6
        ));
        assert!(!packet_source_is_assigned(
            &ipv4_packet(Ipv4Addr::new(10, 8, 0, 99), Ipv4Addr::new(1, 1, 1, 1)),
            assigned_v4,
            assigned_v6
        ));
        assert!(packet_source_is_assigned(
            &ipv6_packet(assigned_v6, Ipv6Addr::LOCALHOST),
            assigned_v4,
            assigned_v6
        ));
    }

    #[test]
    fn invalid_or_truncated_packets_are_dropped() {
        let assigned_v4 = Ipv4Addr::new(10, 8, 0, 2);
        let assigned_v6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);

        assert!(!packet_source_is_assigned(&[], assigned_v4, assigned_v6));
        assert!(!packet_source_is_assigned(
            &[0x45, 0x00],
            assigned_v4,
            assigned_v6
        ));
        assert!(!packet_source_is_assigned(
            &[0x60, 0x00, 0x00],
            assigned_v4,
            assigned_v6
        ));
        assert!(!packet_source_is_assigned(
            &[0x10, 0x00, 0x00],
            assigned_v4,
            assigned_v6
        ));
    }

    #[test]
    fn too_large_path_can_generate_icmp_packet_too_big() {
        let packet = ipv4_packet(Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(10, 8, 0, 2));
        let ptb = packet_too_big_response(
            &packet,
            1280,
            Some(1330),
            0,
            Ipv4Addr::new(10, 8, 0, 1),
            Ipv6Addr::LOCALHOST,
        );

        assert!(ptb.is_some());
        assert!(packet_too_big_response(
            &[],
            1280,
            Some(1330),
            0,
            Ipv4Addr::new(10, 8, 0, 1),
            Ipv6Addr::LOCALHOST
        )
        .is_none());
    }
}
