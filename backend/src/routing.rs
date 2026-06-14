use crate::state::{AppState, ClientTx};
use bytes::Bytes;
use dashmap::DashMap;
use etherparse::{Ipv4HeaderSlice, Ipv6HeaderSlice};
use shared::masque::DATAGRAM_PREFIX;
use std::fmt::Display;
use std::hash::Hash;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::error::TrySendError;
use tracing::{error, info, warn};

/// Removes a peer registration only if the entry still holds the exact channel
/// whose closure we observed.
///
/// The TUN reader clones the sender out of the map before `try_send`. By the
/// time it sees `Closed`, the client may already have disconnected *and* a new
/// client may have leased the same virtual IP and registered its own channel
/// (`release_ips` removes the peer before returning the IP to the pool). A blind
/// `peers.remove(&dest_ip)` would then delete the new client's registration and
/// black-hole all server→client traffic for it. `same_channel` guards against
/// that: we only remove the entry when it is still the dead channel.
fn remove_peer_if_same<K>(peers: &DashMap<K, ClientTx>, key: &K, observed: &ClientTx)
where
    K: Hash + Eq,
{
    peers.remove_if(key, |_, tx| tx.same_channel(observed));
}

#[derive(Default, Clone, Copy)]
struct TunReaderStats {
    read_packets: u64,
    read_bytes: u64,
    routed_packets: u64,
    routed_bytes: u64,
    no_peer_v4: u64,
    no_peer_v6: u64,
    invalid_ip: u64,
    channel_full: u64,
    channel_closed: u64,
}

impl TunReaderStats {
    #[allow(clippy::cast_precision_loss)]
    fn log_interval(&self, previous: &mut Self) {
        let read_packets = self.read_packets - previous.read_packets;
        let read_bytes = self.read_bytes - previous.read_bytes;
        let routed_packets = self.routed_packets - previous.routed_packets;
        let routed_bytes = self.routed_bytes - previous.routed_bytes;
        let no_peer_v4 = self.no_peer_v4 - previous.no_peer_v4;
        let no_peer_v6 = self.no_peer_v6 - previous.no_peer_v6;
        let invalid_ip = self.invalid_ip - previous.invalid_ip;
        let channel_full = self.channel_full - previous.channel_full;
        let channel_closed = self.channel_closed - previous.channel_closed;

        info!(
            "[SERVER TUN READER STATS] tun_read={:.1}mbit routed={:.1}mbit tun_read_pkts={} routed_pkts={} no_peer_v4={} no_peer_v6={} invalid_ip={} channel_full={} channel_closed={}",
            read_bytes as f64 * 8.0 / 5_000_000.0,
            routed_bytes as f64 * 8.0 / 5_000_000.0,
            read_packets,
            routed_packets,
            no_peer_v4,
            no_peer_v6,
            invalid_ip,
            channel_full,
            channel_closed,
        );

        // Snapshot the running totals so the next interval reports deltas.
        *previous = *self;
    }
}

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

/// Routes one framed packet to the client registered for `dest_ip`, updating the
/// shared TUN-reader counters for the send outcome.
///
/// Returns `false` when no peer is registered for the address, so the caller can
/// bump the address-family-specific `no_peer` counter. This is the single code
/// path shared by the IPv4 and IPv6 branches of the TUN reader's hot loop.
#[allow(clippy::too_many_arguments)]
fn deliver_to_client<K>(
    peers: &DashMap<K, ClientTx>,
    dest_ip: K,
    framed: Bytes,
    packet_len: u64,
    stats: &mut TunReaderStats,
    drop_count: &mut u64,
    last_drop_warn: &mut std::time::Instant,
) -> bool
where
    K: Hash + Eq + Copy + Display,
{
    let Some(tx_client) = peers.get(&dest_ip).map(|tx_ref| tx_ref.value().clone()) else {
        return false;
    };

    match tx_client.try_send(framed) {
        Ok(()) => {
            stats.routed_packets += 1;
            stats.routed_bytes += packet_len;
        }
        Err(TrySendError::Full(_)) => {
            stats.channel_full += 1;
            record_s2c_channel_drop(drop_count, last_drop_warn, dest_ip);
        }
        Err(TrySendError::Closed(_)) => {
            stats.channel_closed += 1;
            remove_peer_if_same(peers, &dest_ip, &tx_client);
        }
    }
    true
}

fn record_s2c_channel_drop<D: Display>(
    drop_count: &mut u64,
    last_drop_warn: &mut std::time::Instant,
    dest_ip: D,
) {
    *drop_count += 1;
    if drop_count.is_multiple_of(1000)
        && last_drop_warn.elapsed() >= std::time::Duration::from_secs(5)
    {
        warn!(
            "[SERVER TUN READER] dropped S2C packets: client channel full dest={} drops={}",
            dest_ip, *drop_count
        );
        *drop_count = 0;
        *last_drop_warn = std::time::Instant::now();
    }
}

#[allow(clippy::too_many_lines)]
pub fn spawn_tun_reader(
    mut tun_reader: tokio::io::ReadHalf<tun::AsyncDevice>,
    state_reader: Arc<AppState>,
) {
    tokio::spawn(async move {
        let mut pool = bytes::BytesMut::with_capacity(4 * 1024 * 1024);
        let mut scratch = vec![0u8; 65536];

        let mut last_drop_warn = std::time::Instant::now();
        let mut drop_count = 0u64;
        let mut stats = TunReaderStats::default();
        let mut last_logged_stats = TunReaderStats::default();

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
                            stats.read_packets += 1;
                            stats.read_bytes += n as u64;

                            pool.extend_from_slice(&DATAGRAM_PREFIX);
                            pool.extend_from_slice(&scratch[..n]);
                            let framed = pool.split().freeze();
                            let packet = framed.slice(DATAGRAM_PREFIX.len()..);

                            if packet.is_empty() {
                                stats.invalid_ip += 1;
                                continue;
                            }

                            let packet_len = packet.len() as u64;
                            match packet[0] >> 4 {
                                4 => match Ipv4HeaderSlice::from_slice(&packet) {
                                    Ok(header) => {
                                        if !deliver_to_client(
                                            &state_reader.peers,
                                            header.destination_addr(),
                                            framed,
                                            packet_len,
                                            &mut stats,
                                            &mut drop_count,
                                            &mut last_drop_warn,
                                        ) {
                                            stats.no_peer_v4 += 1;
                                        }
                                    }
                                    Err(_) => stats.invalid_ip += 1,
                                },
                                6 => match Ipv6HeaderSlice::from_slice(&packet) {
                                    Ok(header) => {
                                        if !deliver_to_client(
                                            &state_reader.peers_v6,
                                            header.destination_addr(),
                                            framed,
                                            packet_len,
                                            &mut stats,
                                            &mut drop_count,
                                            &mut last_drop_warn,
                                        ) {
                                            stats.no_peer_v6 += 1;
                                        }
                                    }
                                    Err(_) => stats.invalid_ip += 1,
                                },
                                _ => stats.invalid_ip += 1,
                            }
                        }
                        Err(e) => {
                            error!("CRITICAL: Error reading from TUN: {}. Potential interface crash.", e);
                            break;
                        }
                    }
                }
                _ = flush_tick.tick() => {
                    stats.log_interval(&mut last_logged_stats);

                    // Flush any trailing drop counts that didn't hit the 1000-packet threshold.
                    if drop_count > 0 {
                        warn!(
                            "[SERVER TUN READER] dropped S2C packets: client channel full trailing_drops={}",
                            drop_count
                        );
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

    #[tokio::test]
    async fn stale_closed_channel_does_not_evict_reused_ip() {
        // Reproduces H1: client A disconnects and client B leases the same IP.
        // The TUN reader, still holding A's (now closed) sender, must NOT remove
        // B's fresh registration.
        let state = AppState::new("10.8.0.0/24").unwrap();
        let (v4, v6) = state.assign_ip_pair().unwrap();

        // A registers, then its receiver is dropped (channel closed).
        let (tx_a, rx_a) = tokio::sync::mpsc::channel::<Bytes>(1);
        state.register_client(v4, v6, tx_a.clone());
        drop(rx_a);

        // B leases the same IP and overwrites the registration with its channel.
        let (tx_b, _rx_b) = tokio::sync::mpsc::channel::<Bytes>(1);
        state.register_client(v4, v6, tx_b.clone());

        // Reader observed A's closed sender -> must be a no-op for B's entry.
        remove_peer_if_same(&state.peers, &v4, &tx_a);
        remove_peer_if_same(&state.peers_v6, &v6, &tx_a);
        assert!(
            state.peers.contains_key(&v4),
            "B's v4 registration survives"
        );
        assert!(
            state.peers_v6.contains_key(&v6),
            "B's v6 registration survives"
        );

        // Observing B's own sender DOES remove the entry.
        remove_peer_if_same(&state.peers, &v4, &tx_b);
        remove_peer_if_same(&state.peers_v6, &v6, &tx_b);
        assert!(!state.peers.contains_key(&v4));
        assert!(!state.peers_v6.contains_key(&v6));
    }

    #[tokio::test]
    async fn remove_peer_if_same_removes_matching_clone() {
        // A clone of the same sender shares the channel, so it matches.
        let state = AppState::new("10.8.0.0/24").unwrap();
        let (v4, v6) = state.assign_ip_pair().unwrap();
        let (tx, _rx) = tokio::sync::mpsc::channel::<Bytes>(1);
        state.register_client(v4, v6, tx.clone());

        remove_peer_if_same(&state.peers, &v4, &tx);
        assert!(!state.peers.contains_key(&v4));
    }
}
