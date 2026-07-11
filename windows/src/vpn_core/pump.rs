//! Packet-pump loops for an active VPN session.
//!
//! A session runs two pumps: [`pump_tun_to_quic`] (TUN -> QUIC, on a dedicated
//! OS thread because WinTUN's receive API is blocking) and [`pump_quic_to_tun`]
//! (QUIC -> TUN, as a Tokio task).

use bytes::{Buf, Bytes};
use shared::{icmp, masque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::handshake::TunnelConnection;
use super::wintun_mod::is_wintun_ring_full;

/// Session-static inputs needed to synthesize ICMP "Packet Too Big" replies.
pub(super) struct PtbContext {
    pub(super) gateway: std::net::Ipv4Addr,
    pub(super) gateway_v6: Option<std::net::Ipv6Addr>,
    pub(super) is_h3_framing: bool,
    pub(super) tun_mtu: u16,
}

/// Pumps packets from the WinTUN adapter into the QUIC connection as datagrams.
///
/// Runs on a dedicated OS thread (WinTUN's receive API is blocking). Exits when
/// either `running` or `alive` is cleared, or the connection is lost. On a
/// `TooLarge` error it emits an ICMP PTB reply back into the TUN so the source
/// host lowers its path MTU.
pub(super) fn pump_tun_to_quic(
    session: &Arc<wintun::Session>,
    connection: &TunnelConnection,
    running: &AtomicBool,
    alive: &AtomicBool,
    ptb: &PtbContext,
) {
    let mut pool = bytes::BytesMut::with_capacity(4 * 1024 * 1024);
    while running.load(Ordering::Relaxed) && alive.load(Ordering::Relaxed) {
        match session.try_receive() {
            Ok(Some(packet)) => {
                let packet_bytes = packet.bytes();
                if pool.capacity() < packet_bytes.len() + masque::DATAGRAM_PREFIX.len() {
                    pool.reserve(4 * 1024 * 1024);
                }
                if ptb.is_h3_framing {
                    pool.extend_from_slice(&masque::DATAGRAM_PREFIX);
                }
                pool.extend_from_slice(packet_bytes);
                let payload = pool.split().freeze();
                match connection {
                    TunnelConnection::Quic(connection) => match connection.send_datagram(payload) {
                        Ok(()) => {}
                        Err(quinn::SendDatagramError::TooLarge) => {
                            send_ptb_reply(session, connection, packet.bytes(), ptb);
                        }
                        Err(quinn::SendDatagramError::ConnectionLost(_)) => break,
                        Err(_) => {}
                    },
                    TunnelConnection::Http2(connection) => {
                        if connection.send_packet_blocking(payload).is_err() {
                            alive.store(false, Ordering::SeqCst);
                            break;
                        }
                    }
                }
            }
            Ok(None) => {
                if let Ok(event) = session.get_read_wait_event() {
                    unsafe {
                        windows_sys::Win32::System::Threading::WaitForSingleObject(event as _, 50);
                    }
                } else {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            Err(_) => {
                alive.store(false, Ordering::SeqCst);
                break;
            }
        }
    }
}

/// Synthesizes an ICMP "Packet Too Big" reply for `packet_bytes` and writes it
/// back into the TUN, so the originating host reduces its path MTU.
fn send_ptb_reply(
    session: &Arc<wintun::Session>,
    connection: &quinn::Connection,
    packet_bytes: &[u8],
    ptb: &PtbContext,
) {
    let Some(&first_byte) = packet_bytes.first() else {
        return;
    };
    let version = first_byte >> 4;
    let source_ip = match version {
        4 => Some(std::net::IpAddr::V4(ptb.gateway)),
        6 => ptb.gateway_v6.map(std::net::IpAddr::V6),
        _ => None,
    };
    let h3_prefix = if ptb.is_h3_framing {
        masque::DATAGRAM_PREFIX.len()
    } else {
        0
    };
    let reported_mtu = shared::effective_ptb_mtu(
        ptb.tun_mtu,
        connection.max_datagram_size(),
        h3_prefix,
        version == 6,
    );
    let Some(icmp_packet) = icmp::generate_packet_too_big(packet_bytes, reported_mtu, source_ip)
    else {
        return;
    };
    let Ok(len) = u16::try_from(icmp_packet.len()) else {
        return;
    };
    if let Ok(mut reply) = session.allocate_send_packet(len) {
        reply.bytes_mut().copy_from_slice(&icmp_packet);
        session.send_packet(reply);
    }
}

/// Pumps datagrams from the QUIC connection into the WinTUN adapter.
///
/// Runs as a Tokio task. Exits when either `running` or `alive` is cleared, or
/// the connection's datagram stream ends. When the WinTUN send ring is full it
/// backpressures by retaining the datagram and yielding before retrying.
pub(super) async fn pump_quic_to_tun(
    session: &Arc<wintun::Session>,
    connection: &TunnelConnection,
    running: &AtomicBool,
    alive: &AtomicBool,
    is_h3_framing: bool,
) {
    let mut pending_datagram: Option<Bytes> = None;
    let mut yield_count = 0u8;
    while running.load(Ordering::Relaxed) && alive.load(Ordering::Relaxed) {
        let data = match pending_datagram.take() {
            Some(data) => data,
            None => {
                let Ok(mut data) = connection.recv_packet().await else {
                    alive.store(false, Ordering::SeqCst);
                    break;
                };
                if is_h3_framing {
                    let inner_len = match masque::unwrap_datagram(&data) {
                        Some(slice) => slice.len(),
                        None => continue,
                    };
                    if inner_len == 0 {
                        continue;
                    }
                    let prefix = data.len() - inner_len;
                    data.advance(prefix);
                }
                data
            }
        };
        if data.is_empty() {
            continue;
        }
        #[allow(clippy::cast_possible_truncation)]
        match session.allocate_send_packet(data.len() as u16) {
            Ok(mut packet) => {
                yield_count = 0;
                packet.bytes_mut().copy_from_slice(&data);
                session.send_packet(packet);
            }
            Err(e) if is_wintun_ring_full(&e) => {
                pending_datagram = Some(data);
                if yield_count < 10 {
                    yield_count += 1;
                    tokio::task::yield_now().await;
                } else {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
            Err(_) => {
                alive.store(false, Ordering::SeqCst);
                break;
            }
        }
    }
}
