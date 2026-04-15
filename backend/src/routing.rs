use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, warn};
use bytes::Bytes;
use crate::state::AppState;
use etherparse::{Ipv4HeaderSlice, Ipv6HeaderSlice};
use shared::masque::DATAGRAM_PREFIX;

pub fn spawn_tun_writer(mut tun_writer: tokio::io::WriteHalf<tun::AsyncDevice>, mut rx_tun: tokio::sync::mpsc::Receiver<Bytes>) {
    tokio::spawn(async move {
        let mut batch: Vec<Bytes> = Vec::with_capacity(64);
        'writer_loop: loop {
            match rx_tun.recv().await {
                Some(packet) => batch.push(packet),
                None => break,
            }
            
            while batch.len() < 64 {
                match rx_tun.try_recv() {
                    Ok(packet) => batch.push(packet),
                    Err(_) => break,
                }
            }
            
            for packet in batch.drain(..) {
                if let Err(e) = tun_writer.write_all(&packet).await {
                    error!("CRITICAL: Failed to write to TUN: {}. Interface might be down. Terminating task.", e);
                    break 'writer_loop;
                }
            }
        }
    });
}

pub fn spawn_tun_reader(mut tun_reader: tokio::io::ReadHalf<tun::AsyncDevice>, state_reader: Arc<AppState>) {
    tokio::spawn(async move {
        const PREFIX_LEN: usize = DATAGRAM_PREFIX.len();
        let mut buf = bytes::BytesMut::with_capacity(2048 + PREFIX_LEN);
        loop {
            if buf.capacity() < 2048 + PREFIX_LEN { buf.reserve(2048 + PREFIX_LEN); }

            // Reserve H3 DATAGRAM_PREFIX headroom before the read so the H3 sender can ship
            // the buffer as-is (no per-packet alloc/memcpy). The non-H3 sender slices past
            // the prefix in O(1) via `Bytes::slice`.
            buf.extend_from_slice(&DATAGRAM_PREFIX);

            match tun_reader.read_buf(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    let framed = buf.split_to(n + PREFIX_LEN).freeze();
                    let packet = framed.slice(PREFIX_LEN..);
                    if packet.is_empty() { continue; }

                    let version = packet[0] >> 4;
                    if version == 4 {
                         if let Ok(ipv4_header) = Ipv4HeaderSlice::from_slice(&packet) {
                            let dest_ip = ipv4_header.destination_addr();
                            if let Some(tx_client) = state_reader.peers.get(&dest_ip) {
                                if tx_client.try_send(framed).is_err() {
                                    warn!("Dropped IPv4 packet for {}: client channel full", dest_ip);
                                }
                            }
                        }
                    } else if version == 6 {
                         if let Ok(ipv6_header) = Ipv6HeaderSlice::from_slice(&packet) {
                            let dest_ip = ipv6_header.destination_addr();
                            if let Some(tx_client) = state_reader.peers_v6.get(&dest_ip) {
                                if tx_client.try_send(framed).is_err() {
                                    warn!("Dropped IPv6 packet for {}: client channel full", dest_ip);
                                }
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
    });
}
