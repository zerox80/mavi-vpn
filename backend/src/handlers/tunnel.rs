use anyhow::Result;
use bytes::Bytes;
use etherparse::{Ipv4HeaderSlice, Ipv6HeaderSlice};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
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

            let (datagram_to_send, packet_for_icmp) = if is_h3 {
                // In H3 (connect-ip) mode, send the framed datagram directly.
                // The packet payload for ICMP generation is without the masque prefix.
                let packet = framed.slice(masque::DATAGRAM_PREFIX.len()..);
                (framed, packet)
            } else {
                // In raw mode, strip the masque prefix before sending.
                let packet = framed.slice(masque::DATAGRAM_PREFIX.len()..);
                (packet.clone(), packet)
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
                    if packet_for_icmp.is_empty() {
                        continue;
                    }

                    let ver = packet_for_icmp[0] >> 4;
                    let gw = if ver == 4 {
                        Some(IpAddr::V4(gv4))
                    } else if ver == 6 {
                        Some(IpAddr::V6(gv6))
                    } else {
                        None
                    };
                    let reported_mtu = if ver == 6 {
                        tunnel_mtu.max(1280)
                    } else {
                        tunnel_mtu
                    };

                    if let Some(icmp_p) =
                        icmp::generate_packet_too_big(&packet_for_icmp, reported_mtu, gw)
                    {
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
                "[SERVER TUNNEL STATS] s2c_app={:.1}mbit c2s_app={:.1}mbit quic_udp_tx={:.1}mbit quic_udp_rx={:.1}mbit rtt={}ms cwnd={} lost_pkts={} lost_bytes={} max_dgram={} dgram_space={} s2c_pkts={} s2c_queue_len={} s2c_send_err={} s2c_too_large={} c2s_pkts={} c2s_tun_drops={}",
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

        if datagram.is_empty() {
            continue;
        }

        let packet = if is_h3 {
            let inner_len = match masque::unwrap_datagram(&datagram) {
                Some(slice) => slice.len(),
                None => continue,
            };
            if inner_len == 0 {
                continue;
            }
            let prefix_len = datagram.len() - inner_len;
            datagram.slice(prefix_len..)
        } else {
            datagram
        };

        if packet.is_empty() {
            continue;
        }

        let ver = packet[0] >> 4;
        let mut valid = false;
        if ver == 4 {
            if let Ok(h) = Ipv4HeaderSlice::from_slice(&packet) {
                if h.source_addr() == assigned_ip {
                    valid = true;
                }
            }
        } else if ver == 6 {
            if let Ok(h) = Ipv6HeaderSlice::from_slice(&packet) {
                if h.source_addr() == assigned_ip6 {
                    valid = true;
                }
            }
        }

        if valid {
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
