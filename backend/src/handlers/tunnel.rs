use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use anyhow::Result;
use bytes::Bytes;
use etherparse::{Ipv4HeaderSlice, Ipv6HeaderSlice};
use tokio::sync::mpsc;

use shared::{icmp, masque};

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

    let tun_to_quic = tokio::spawn(async move {
        while let Some(framed) = rx_client.recv().await {
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

            if let Err(e) = conn_send.send_datagram(datagram_to_send) {
                if matches!(e, quinn::SendDatagramError::TooLarge) {
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

                    if let Some(icmp_p) = icmp::generate_packet_too_big(
                        &packet_for_icmp,
                        reported_mtu,
                        gw,
                    ) {
                        let _ = tx_tun_icmp.try_send(Bytes::from(icmp_p));
                    }
                }
            }
        }
    });

    let res = loop {
        let datagram = match connection.read_datagram().await {
            Ok(data) => data,
            Err(e) => break Err(anyhow::anyhow!("Connection lost: {}", e)),
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
            if let Err(e) = tx_tun.try_send(packet) {
                if matches!(e, mpsc::error::TrySendError::Closed(_)) {
                    break Err(anyhow::anyhow!("TUN closed"));
                }
            }
        } else if tx_tun.is_closed() {
            break Err(anyhow::anyhow!("TUN closed"));
        }
    };

    tun_to_quic.abort();
    res
}
