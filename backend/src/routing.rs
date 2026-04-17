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
        let mut pool = bytes::BytesMut::with_capacity(4 * 1024 * 1024);
        let mut scratch = vec![0u8; 65536];

        let mut local_peers_v4: std::collections::HashMap<std::net::Ipv4Addr, tokio::sync::mpsc::Sender<bytes::Bytes>> = std::collections::HashMap::new();
        let mut local_peers_v6: std::collections::HashMap<std::net::Ipv6Addr, tokio::sync::mpsc::Sender<bytes::Bytes>> = std::collections::HashMap::new();

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
                                                if drop_count % 1000 == 0 && last_drop_warn.elapsed() >= std::time::Duration::from_secs(5) {
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
                                                    if drop_count % 1000 == 0 && last_drop_warn.elapsed() >= std::time::Duration::from_secs(5) {
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
                                                if drop_count % 1000 == 0 && last_drop_warn.elapsed() >= std::time::Duration::from_secs(5) {
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
                                                    if drop_count % 1000 == 0 && last_drop_warn.elapsed() >= std::time::Duration::from_secs(5) {
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
