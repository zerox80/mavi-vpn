use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, warn};
use bytes::Bytes;
use crate::state::AppState;
use etherparse::{Ipv4HeaderSlice, Ipv6HeaderSlice};
use shared::masque::DATAGRAM_PREFIX;

pub fn spawn_tun_writer(mut tun_writer: tokio::io::WriteHalf<tun::AsyncDevice>, mut rx_tun: tokio::sync::mpsc::Receiver<Bytes>) {
    tokio::spawn(async move {
        while let Some(packet) = rx_tun.recv().await {
            if let Err(e) = tun_writer.write_all(&packet).await {
                error!("CRITICAL: Failed to write to TUN: {}. Interface might be down. Terminating task.", e);
                break;
            }
        }
    });
}

pub fn spawn_tun_reader(mut tun_reader: tokio::io::ReadHalf<tun::AsyncDevice>, state_reader: Arc<AppState>) {
    tokio::spawn(async move {
        const PREFIX_LEN: usize = DATAGRAM_PREFIX.len();
        let mut buf = vec![0u8; 65536];
        buf[..PREFIX_LEN].copy_from_slice(&DATAGRAM_PREFIX);
        
        let mut local_peers_v4 = std::collections::HashMap::new();
        let mut local_peers_v6 = std::collections::HashMap::new();

        loop {
            match tun_reader.read(&mut buf[PREFIX_LEN..]).await {
                Ok(0) => break,
                Ok(n) => {
                    let framed = Bytes::copy_from_slice(&buf[..PREFIX_LEN + n]);
                    let packet = framed.slice(PREFIX_LEN..);
                    if packet.is_empty() { continue; }

                    let version = packet[0] >> 4;
                    if version == 4 {
                         if let Ok(ipv4_header) = Ipv4HeaderSlice::from_slice(&packet) {
                            let dest_ip = ipv4_header.destination_addr();
                            
                            let mut remove = false;
                            if let std::collections::hash_map::Entry::Vacant(e) = local_peers_v4.entry(dest_ip) {
                                if let Some(tx_ref) = state_reader.peers.get(&dest_ip) {
                                    e.insert(tx_ref.value().clone());
                                }
                            }
                            
                            if let Some(tx_client) = local_peers_v4.get(&dest_ip) {
                                if let Err(e) = tx_client.try_send(framed) {
                                    if let tokio::sync::mpsc::error::TrySendError::Closed(_) = e {
                                        remove = true;
                                    } else {
                                        warn!("Dropped IPv4 packet for {}: client channel full", dest_ip);
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
                            if let std::collections::hash_map::Entry::Vacant(e) = local_peers_v6.entry(dest_ip) {
                                if let Some(tx_ref) = state_reader.peers_v6.get(&dest_ip) {
                                    e.insert(tx_ref.value().clone());
                                }
                            }
                            
                            if let Some(tx_client) = local_peers_v6.get(&dest_ip) {
                                if let Err(e) = tx_client.try_send(framed) {
                                    if let tokio::sync::mpsc::error::TrySendError::Closed(_) = e {
                                        remove = true;
                                    } else {
                                        warn!("Dropped IPv6 packet for {}: client channel full", dest_ip);
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
    });
}
