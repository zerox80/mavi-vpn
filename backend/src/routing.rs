use crate::state::AppState;
use bytes::Bytes;
use etherparse::{Ipv4HeaderSlice, Ipv6HeaderSlice};
use shared::masque::DATAGRAM_PREFIX;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, warn};

pub fn spawn_tun_writer(
    mut tun_writer: tokio::io::WriteHalf<tun::AsyncDevice>,
    mut rx_tun: tokio::sync::mpsc::Receiver<Bytes>,
) {
    tokio::spawn(async move {
        while let Some(packet) = rx_tun.recv().await {
            if let Err(e) = tun_writer.write_all(&packet).await {
                error!("CRITICAL: Failed to write to TUN: {}. Interface might be down. Terminating task.", e);
                break;
            }
        }
    });
}

pub fn spawn_tun_reader(
    mut tun_reader: tokio::io::ReadHalf<tun::AsyncDevice>,
    state_reader: Arc<AppState>,
) {
    tokio::spawn(async move {
        let mut pool = bytes::BytesMut::with_capacity(4 * 1024 * 1024);
        let mut scratch = vec![0u8; 65536];

        let mut local_peers_v4: std::collections::HashMap<
            std::net::Ipv4Addr,
            tokio::sync::mpsc::Sender<bytes::Bytes>,
        > = std::collections::HashMap::new();
        let mut local_peers_v6: std::collections::HashMap<
            std::net::Ipv6Addr,
            tokio::sync::mpsc::Sender<bytes::Bytes>,
        > = std::collections::HashMap::new();

        let mut last_drop_warn = std::time::Instant::now();
        let mut drop_count = 0u64;

        // Periodic tick used only to flush trailing drop_count warnings when the
        // TUN goes idle. Done via a single long-lived interval instead of a
        // per-packet tokio::time::timeout — the latter would register and cancel
        // a timer-wheel entry for every single packet on the hottest path of
        // the server (TUN → client fanout), adding measurable CPU overhead and
        // tail-latency jitter under load.
        let mut flush_tick = tokio::time::interval(std::time::Duration::from_secs(5));
        flush_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Skip the immediate first tick so we don't log a spurious warning at startup.
        flush_tick.tick().await;

        loop {
            if pool.capacity() < 65536 + DATAGRAM_PREFIX.len() {
                pool.reserve(4 * 1024 * 1024);
            }

            tokio::select! {
                biased;
                res = tun_reader.read(&mut scratch) => {
                    match res {
                        Ok(0) => break,
                        Ok(n) => {
                            pool.extend_from_slice(&DATAGRAM_PREFIX);
                            pool.extend_from_slice(&scratch[..n]);
                            let framed = pool.split().freeze();
                            let packet = framed.slice(DATAGRAM_PREFIX.len()..);

                            if packet.is_empty() { continue; }

                            let version = packet[0] >> 4;
                            if version == 4 {
                                if let Ok(ipv4_header) = Ipv4HeaderSlice::from_slice(&packet) {
                                    let dest_ip = ipv4_header.destination_addr();

                                    let mut remove = false;

                                    // Fast-path: Only 1 hash traversal!
                                    if let Some(tx_client) = local_peers_v4.get(&dest_ip) {
                                        if let Err(e) = tx_client.try_send(framed) {
                                            if let tokio::sync::mpsc::error::TrySendError::Closed(_) = e {
                                                remove = true;
                                            } else {
                                                drop_count += 1;
                                                if drop_count.is_multiple_of(1000) && last_drop_warn.elapsed() >= std::time::Duration::from_secs(5) {
                                                    warn!("Dropped {} packets: client channel(s) full", drop_count);
                                                    drop_count = 0;
                                                    last_drop_warn = std::time::Instant::now();
                                                }
                                            }
                                        }
                                    } else {
                                        let tx_client_opt = state_reader.peers.get(&dest_ip).map(|tx_ref| tx_ref.value().clone());
                                        if let Some(tx_client) = tx_client_opt {
                                            if let Err(e) = tx_client.try_send(framed) {
                                                if let tokio::sync::mpsc::error::TrySendError::Full(_) = e {
                                                    drop_count += 1;
                                                    if drop_count.is_multiple_of(1000) && last_drop_warn.elapsed() >= std::time::Duration::from_secs(5) {
                                                        warn!("Dropped {} packets: client channel(s) full", drop_count);
                                                        drop_count = 0;
                                                        last_drop_warn = std::time::Instant::now();
                                                    }
                                                    local_peers_v4.insert(dest_ip, tx_client);
                                                }
                                            } else {
                                                local_peers_v4.insert(dest_ip, tx_client);
                                            }
                                        }
                                    }

                                    if remove {
                                        local_peers_v4.remove(&dest_ip);
                                    }
                                }
                            } else if version == 6 {
                                if let Ok(ipv6_header) = Ipv6HeaderSlice::from_slice(&packet) {
                                    let dest_ip = ipv6_header.destination_addr();

                                    let mut remove = false;

                                    if let Some(tx_client) = local_peers_v6.get(&dest_ip) {
                                        if let Err(e) = tx_client.try_send(framed) {
                                            if let tokio::sync::mpsc::error::TrySendError::Closed(_) = e {
                                                remove = true;
                                            } else {
                                                drop_count += 1;
                                                if drop_count.is_multiple_of(1000) && last_drop_warn.elapsed() >= std::time::Duration::from_secs(5) {
                                                    warn!("Dropped {} packets: client channel(s) full", drop_count);
                                                    drop_count = 0;
                                                    last_drop_warn = std::time::Instant::now();
                                                }
                                            }
                                        }
                                    } else {
                                        let tx_client_opt = state_reader.peers_v6.get(&dest_ip).map(|tx_ref| tx_ref.value().clone());
                                        if let Some(tx_client) = tx_client_opt {
                                            if let Err(e) = tx_client.try_send(framed) {
                                                if let tokio::sync::mpsc::error::TrySendError::Full(_) = e {
                                                    drop_count += 1;
                                                    if drop_count.is_multiple_of(1000) && last_drop_warn.elapsed() >= std::time::Duration::from_secs(5) {
                                                        warn!("Dropped {} packets: client channel(s) full", drop_count);
                                                        drop_count = 0;
                                                        last_drop_warn = std::time::Instant::now();
                                                    }
                                                    local_peers_v6.insert(dest_ip, tx_client);
                                                }
                                            } else {
                                                local_peers_v6.insert(dest_ip, tx_client);
                                            }
                                        }
                                    }

                                    if remove {
                                        local_peers_v6.remove(&dest_ip);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            error!("CRITICAL: Error reading from TUN: {}. Potential interface crash.", e);
                            break;
                        }
                    }
                }
                _ = flush_tick.tick() => {
                    // Flush any trailing drop counts that didn't hit the 1000-packet threshold.
                    if drop_count > 0 {
                        warn!("Dropped {} packets: client channel(s) full (trailing drops)", drop_count);
                        drop_count = 0;
                        last_drop_warn = std::time::Instant::now();
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;

    fn make_test_ipv4_packet(src: std::net::Ipv4Addr, dst: std::net::Ipv4Addr) -> Vec<u8> {
        let builder = PacketBuilder::ipv4(src.octets(), dst.octets(), 64).udp(12345, 80);
        let payload = b"test";
        let mut buf = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut buf, payload).unwrap();
        buf
    }

    fn make_test_ipv6_packet(src: std::net::Ipv6Addr, dst: std::net::Ipv6Addr) -> Vec<u8> {
        let builder = PacketBuilder::ipv6(src.octets(), dst.octets(), 64).udp(12345, 80);
        let payload = b"test";
        let mut buf = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut buf, payload).unwrap();
        buf
    }

    #[test]
    fn ipv4_packet_parses_correctly() {
        let src = std::net::Ipv4Addr::new(10, 8, 0, 2);
        let dst = std::net::Ipv4Addr::new(93, 184, 216, 34);
        let packet = make_test_ipv4_packet(src, dst);

        let header = Ipv4HeaderSlice::from_slice(&packet).unwrap();
        assert_eq!(header.source_addr(), src);
        assert_eq!(header.destination_addr(), dst);
        assert_eq!(header.version(), 4);
    }

    #[test]
    fn ipv6_packet_parses_correctly() {
        let src = std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        let dst = std::net::Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let packet = make_test_ipv6_packet(src, dst);

        let header = Ipv6HeaderSlice::from_slice(&packet).unwrap();
        assert_eq!(header.source_addr(), src);
        assert_eq!(header.destination_addr(), dst);
    }

    #[test]
    fn datagram_prefix_is_correct() {
        assert_eq!(DATAGRAM_PREFIX, [0x00, 0x00]);
    }

    #[test]
    fn ipv4_version_detection() {
        let packet = make_test_ipv4_packet(
            std::net::Ipv4Addr::new(10, 8, 0, 2),
            std::net::Ipv4Addr::new(1, 1, 1, 1),
        );
        assert_eq!(packet[0] >> 4, 4);
    }

    #[test]
    fn ipv6_version_detection() {
        let packet = make_test_ipv6_packet(
            std::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            std::net::Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
        );
        assert_eq!(packet[0] >> 4, 6);
    }

    #[tokio::test]
    async fn channel_send_receive() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(16);
        let data = Bytes::from_static(b"hello world");
        tx.send(data.clone()).await.unwrap();
        let received = rx.recv().await.unwrap();
        assert_eq!(received, data);
    }

    #[tokio::test]
    async fn channel_try_send_full() {
        let (tx, _rx) = tokio::sync::mpsc::channel::<Bytes>(1);
        let data = Bytes::from_static(b"hello");
        assert!(tx.try_send(data.clone()).is_ok());
        assert!(tx.try_send(data).is_err());
    }
}
