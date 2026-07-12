//! TUN-to-transport and transport-to-TUN packet forwarding tasks.
//!
//! Keeping the packet-plane tasks separate from the session orchestrator makes
//! ownership and shutdown behavior explicit while preserving transport semantics.

use bytes::Buf;
use shared::{icmp, masque};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::warn;

use crate::tun::AsyncTun;

use super::super::handshake::{SendPacketError, TunnelConnection};

/// Handles for packet-plane tasks and their blocked-receive wakeup.
pub(super) struct PacketPumpTasks {
    tun_to_transport: JoinHandle<()>,
    transport_to_tun: JoinHandle<()>,
    receive_shutdown: tokio::sync::watch::Sender<()>,
}

#[derive(Clone, Copy)]
pub(super) struct PacketPumpConfig {
    pub(super) uses_h3_framing: bool,
    pub(super) tun_mtu: u16,
    pub(super) gateway: Ipv4Addr,
    pub(super) gateway_v6: Option<Ipv6Addr>,
}

impl PacketPumpTasks {
    pub(super) fn spawn(
        tun: Arc<AsyncTun>,
        connection: Arc<TunnelConnection>,
        session_alive: Arc<AtomicBool>,
        running: Arc<AtomicBool>,
        config: PacketPumpConfig,
    ) -> Self {
        let tun_to_transport = spawn_tun_to_transport(
            tun.clone(),
            connection.clone(),
            session_alive.clone(),
            running.clone(),
            config,
        );
        let (receive_shutdown, shutdown_rx) = tokio::sync::watch::channel(());
        let transport_to_tun = spawn_transport_to_tun(
            tun,
            connection,
            session_alive,
            running,
            config.uses_h3_framing,
            shutdown_rx,
        );

        Self {
            tun_to_transport,
            transport_to_tun,
            receive_shutdown,
        }
    }

    /// Wakes a blocked receive task before aborting both packet pumps.
    pub(super) fn stop(self) {
        drop(self.receive_shutdown);
        self.tun_to_transport.abort();
        self.transport_to_tun.abort();
    }
}

fn spawn_tun_to_transport(
    tun: Arc<AsyncTun>,
    connection: Arc<TunnelConnection>,
    session_alive: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
    config: PacketPumpConfig,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut pool = bytes::BytesMut::with_capacity(4 * 1024 * 1024);
        let mut scratch = vec![0_u8; 65_536];
        loop {
            if !running.load(Ordering::Relaxed) || !session_alive.load(Ordering::Relaxed) {
                break;
            }
            if pool.capacity() < scratch.len() + masque::DATAGRAM_PREFIX.len() {
                pool.reserve(4 * 1024 * 1024);
            }
            match tun.read(&mut scratch).await {
                Ok(n) if n > 0 => {
                    let payload =
                        frame_outbound_packet(&mut pool, &scratch[..n], config.uses_h3_framing);
                    match connection.send_packet(payload).await {
                        Ok(()) => {}
                        Err(SendPacketError::TooLarge) => {
                            send_packet_too_big(&tun, &connection, &scratch[..n], config).await;
                        }
                        Err(error) => {
                            warn!("Transport send error: {error}");
                            session_alive.store(false, Ordering::SeqCst);
                            break;
                        }
                    }
                }
                Ok(_) => {}
                Err(error) => {
                    warn!("TUN read error: {error}");
                    session_alive.store(false, Ordering::SeqCst);
                    break;
                }
            }
        }
    })
}

fn frame_outbound_packet(
    pool: &mut bytes::BytesMut,
    packet: &[u8],
    uses_h3_framing: bool,
) -> bytes::Bytes {
    if uses_h3_framing {
        pool.extend_from_slice(&masque::DATAGRAM_PREFIX);
    }
    pool.extend_from_slice(packet);
    pool.split().freeze()
}

async fn send_packet_too_big(
    tun: &AsyncTun,
    connection: &TunnelConnection,
    packet: &[u8],
    config: PacketPumpConfig,
) {
    if let Some(quic) = connection.quic() {
        let version = packet[0] >> 4;
        let source_ip = match version {
            4 => Some(std::net::IpAddr::V4(config.gateway)),
            6 => config.gateway_v6.map(std::net::IpAddr::V6),
            _ => None,
        };
        let framing_overhead = usize::from(config.uses_h3_framing) * masque::DATAGRAM_PREFIX.len();
        let reported_mtu = shared::effective_ptb_mtu(
            config.tun_mtu,
            quic.max_datagram_size(),
            framing_overhead,
            version == 6,
        );
        if let Some(icmp_packet) = icmp::generate_packet_too_big(packet, reported_mtu, source_ip) {
            let _ = tun.write(&icmp_packet).await;
        }
    }
    warn!("QUIC datagram too large; sent ICMP Packet Too Big");
}

fn spawn_transport_to_tun(
    tun: Arc<AsyncTun>,
    connection: Arc<TunnelConnection>,
    session_alive: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
    uses_h3_framing: bool,
    mut shutdown_rx: tokio::sync::watch::Receiver<()>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if !running.load(Ordering::Relaxed) || !session_alive.load(Ordering::Relaxed) {
                break;
            }
            let datagram = tokio::select! {
                biased;
                _ = shutdown_rx.changed() => break,
                result = connection.recv_packet() => result,
            };
            match datagram {
                Ok(mut data) => {
                    if uses_h3_framing && !strip_h3_framing(&mut data) {
                        continue;
                    }
                    if data.is_empty() {
                        continue;
                    }
                    if let Err(error) = tun.write(&data).await {
                        warn!("TUN write error: {error}");
                        session_alive.store(false, Ordering::SeqCst);
                        break;
                    }
                }
                Err(_) => {
                    session_alive.store(false, Ordering::SeqCst);
                    break;
                }
            }
        }
    })
}

fn strip_h3_framing(data: &mut bytes::Bytes) -> bool {
    let Some(inner) = masque::unwrap_datagram(data) else {
        return false;
    };
    if inner.is_empty() {
        return false;
    }
    data.advance(data.len() - inner.len());
    true
}

#[cfg(test)]
mod tests {
    use super::{frame_outbound_packet, strip_h3_framing};
    use shared::masque;

    #[test]
    fn h3_framing_round_trips_an_ip_packet() {
        let packet = [0x45, 0, 0, 20];
        let mut pool = bytes::BytesMut::new();
        let mut framed = frame_outbound_packet(&mut pool, &packet, true);

        assert!(strip_h3_framing(&mut framed));
        assert_eq!(framed.as_ref(), packet);
    }

    #[test]
    fn h3_framing_rejects_empty_or_invalid_payloads() {
        let mut empty = bytes::Bytes::from_static(&masque::DATAGRAM_PREFIX);
        let mut invalid = bytes::Bytes::from_static(b"\x01\x01");

        assert!(!strip_h3_framing(&mut empty));
        assert!(!strip_h3_framing(&mut invalid));
    }
}
