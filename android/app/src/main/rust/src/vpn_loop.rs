use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use log::{info, error, warn};
use shared::ControlMessage;
use jni::sys::jint;
use bytes::BufMut;
use futures_util::FutureExt;

#[cfg(target_os = "android")]
use std::os::unix::io::{FromRawFd, RawFd, AsRawFd};
#[cfg(target_os = "android")]
use tokio::io::unix::AsyncFd;

#[cfg(not(target_os = "android"))]
pub type RawFd = std::os::raw::c_int;

#[cfg(target_os = "android")]
pub async fn run_vpn_loop(connection: quinn::Connection, fd: jint, stop_flag: Arc<AtomicBool>, config: ControlMessage, mut shutdown_rx: tokio::sync::broadcast::Receiver<()>, http3_framing: bool) {
    let raw_fd = fd as RawFd;

    // Extract Gateway IPs for ICMP signaling
    let (gateway_v4, gateway_v6_opt, tunnel_mtu) = match &config {
        ControlMessage::Config { gateway, gateway_v6, mtu, .. } => (*gateway, *gateway_v6, *mtu),
        _ => (std::net::Ipv4Addr::new(10, 0, 0, 1), None, 1280),
    };
    
    // Duplicated FD to manage its lifecycle independently from Java
    let dup_fd = unsafe { libc::dup(raw_fd) };
    if dup_fd < 0 {
        error!("Could not duplicate FD: {}", std::io::Error::last_os_error());
        return;
    }

    let file = unsafe { std::fs::File::from_raw_fd(dup_fd) };
    
    // Set non-blocking on the DUPLICATED FD
    unsafe {
        let flags = libc::fcntl(dup_fd, libc::F_GETFL);
        libc::fcntl(dup_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
    
    let tun_async_fd = match AsyncFd::new(file) {
        Ok(t) => Arc::new(t),
        Err(e) => { error!("Failed to create AsyncFd: {}", e); return; }
    };

    let connection_arc = Arc::new(connection);
    let (tx_tun, mut rx_tun) = tokio::sync::mpsc::channel::<Vec<u8>>(512);

    info!("Entering concurrent VPN Loop Hub");

    // --- TASK 1: TUN -> QUIC (Outgoing / Upload) ---
    let stop_upload = stop_flag.clone();
    let tun_upload = tun_async_fd.clone();
    let conn_upload = connection_arc.clone();
    let tx_feedback = tx_tun.clone();
    
    let upload_task = tokio::spawn(async move {
        let mut buf = bytes::BytesMut::with_capacity(65536);
        loop {
            if stop_upload.load(Ordering::Relaxed) { break; }
            
            let mut guard = tokio::select! {
                res = tun_upload.readable() => match res { Ok(g) => g, Err(_) => break },
                _ = shutdown_rx.recv() => break,
            };

            let packet = match guard.try_io(|inner| {
                 if buf.capacity() < 2048 {
                     buf.reserve(2048);
                 }
                 let chunk = buf.chunk_mut();
                 let max_len = 2048.min(chunk.len());
                 
                 let n = unsafe { libc::read(inner.as_raw_fd(), chunk.as_mut_ptr() as *mut libc::c_void, max_len) };
                 
                 if n < 0 {
                     let err = std::io::Error::last_os_error();
                     return Err(err);
                 }
                 let n = n as usize;
                 if n == 0 { return Ok(None); } 
                 
                 unsafe { buf.advance_mut(n); }
                 let packet = buf.split_to(n).freeze();
                 Ok(Some(packet))
            }) {
                Ok(Ok(Some(p))) => p,
                Ok(Ok(None)) => break,
                Ok(Err(e)) => {
                    if let Some(raw) = e.raw_os_error() {
                        if raw == libc::EAGAIN || raw == libc::EWOULDBLOCK || raw == libc::EINTR {
                            continue;
                        }
                    }
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        error!("TUN Read Error: {}", e);
                        break;
                    }
                    continue;
                },
                Err(_) => continue, // WouldBlock, let tokio select re-await
            };

            let packet_len = packet.len();
            let packet_bytes = packet.clone(); 

            // In H3 mode, prepend Quarter Stream ID (0x00)
            let payload = if http3_framing {
                let mut h3_payload = bytes::BytesMut::with_capacity(packet.len() + 1);
                h3_payload.put_u8(0x00);
                h3_payload.put(packet);
                h3_payload.freeze()
            } else {
                packet
            };

            // Send to QUIC
            if let Err(e) = conn_upload.send_datagram(payload) {
                match e {
                    quinn::SendDatagramError::ConnectionLost(_) => {
                        error!("QUIC Connection lost during send");
                        stop_upload.store(true, Ordering::SeqCst);
                        break;
                    }
                    quinn::SendDatagramError::TooLarge => {
                        let current_limit = conn_upload.max_datagram_size().unwrap_or(1200);
                        warn!("MTU Limit hit! Packet: {} bytes, Limit: {} bytes", packet_len, current_limit);

                        if packet_bytes.is_empty() {
                            continue;
                        }

                        let version = (packet_bytes[0] >> 4) & 0xF;
                        let gw = if version == 4 {
                            Some(std::net::IpAddr::V4(gateway_v4))
                        } else if version == 6 {
                            gateway_v6_opt.map(std::net::IpAddr::V6)
                        } else {
                            None
                        };
                        let reported_mtu = if version == 6 {
                            tunnel_mtu.max(1280)
                        } else {
                            tunnel_mtu
                        };

                        if let Some(icmp_packet) = shared::icmp::generate_packet_too_big(&packet_bytes, reported_mtu, gw) {
                            let _ = tx_feedback.try_send(icmp_packet);
                        }
                    },
                    _ => {
                        error!("Unexpected SendDatagramError: {:?}", e);
                    }
                }
            }
        }
        info!("Upload task exited.");
    });

    // --- TASK 2: QUIC -> TUN (Incoming / Download) ---
    let stop_download = stop_flag.clone();
    let tun_download = tun_async_fd.clone();
    let conn_download = connection_arc.clone();
    
    let download_task = tokio::spawn(async move {
        loop {
            if stop_download.load(Ordering::Relaxed) { break; }
            
            match conn_download.read_datagram().await {
                Ok(mut first_packet) => {
                    let mut batch = Vec::with_capacity(64);
                    if http3_framing {
                        if first_packet.len() > 1 {
                            batch.push(first_packet.slice(1..));
                        }
                    } else {
                        batch.push(first_packet);
                    }

                    for _ in 0..63 {
                         if let Some(Ok(mut pkt)) = conn_download.read_datagram().now_or_never() {
                             if http3_framing {
                                 if pkt.len() > 1 {
                                     batch.push(pkt.slice(1..));
                                 }
                             } else {
                                 batch.push(pkt);
                             }
                         } else { break; }
                    }

                    let mut batch_idx = 0;
                    while batch_idx < batch.len() {
                        let mut guard = match tun_download.writable().await {
                             Ok(g) => g,
                             Err(_) => break,
                        };
                        
                        let res = guard.try_io(|inner| {
                            while batch_idx < batch.len() {
                                 let packet = &batch[batch_idx];
                                 let n = unsafe { libc::write(inner.as_raw_fd(), packet.as_ptr() as *const libc::c_void, packet.len()) };
                                 if n < 0 {
                                     let err = std::io::Error::last_os_error();
                                     if let Some(raw) = err.raw_os_error() {
                                         if raw == libc::EAGAIN || raw == libc::EWOULDBLOCK {
                                             return Err(err); 
                                         }
                                         if raw == libc::ENOBUFS || raw == libc::EINTR {
                                             // Network internal buffer full or interrupted, just drop the packet immediately
                                             batch_idx += 1;
                                             continue;
                                         }
                                     }
                                     if err.kind() == std::io::ErrorKind::WouldBlock {
                                         return Err(err); 
                                     }
                                     return Err(err);
                                 }
                                 batch_idx += 1;
                            }
                            Ok(())
                        });
                        
                        match res {
                            Ok(Ok(())) => {}, 
                            Ok(Err(e)) => {
                                 if e.kind() == std::io::ErrorKind::WouldBlock {
                                     continue; // Handled by outer while loop re-awaiting
                                 }
                                 error!("TUN Write Error: {}", e);
                                 if let Some(raw) = e.raw_os_error() {
                                     if raw == libc::EBADF {
                                         // Fatal descriptor error
                                         stop_download.store(true, Ordering::SeqCst);
                                     }
                                 }
                                 break; // this drops the rest of the batch, preserving the loop
                            },
                            Err(_) => continue, // WouldBlock: wait for writable again
                        }
                    }
                }
                Err(_) => {
                    stop_download.store(true, Ordering::SeqCst);
                    break;
                }
            }
        }
        info!("Download task exited.");
    });

    // --- TASK 3: ICMP Feedback -> TUN ---
    let stop_icmp = stop_flag.clone();
    let tun_icmp = tun_async_fd.clone();
    let icmp_task = tokio::spawn(async move {
        while let Some(icmp_pkt) = rx_tun.recv().await {
            if stop_icmp.load(Ordering::Relaxed) { break; }
            if let Ok(mut guard) = tun_icmp.writable().await {
                let _ = guard.try_io(|inner| {
                    let _ = unsafe { libc::write(inner.as_raw_fd(), icmp_pkt.as_ptr() as *const libc::c_void, icmp_pkt.len()) };
                    Ok(())
                });
            }
        }
    });

    // --- TASK 4: QUIC STATS LOGGING ---
    let stop_stats = stop_flag.clone();
    let conn_stats = connection_arc.clone();
    let stats_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            if stop_stats.load(Ordering::Relaxed) { break; }
            let stats = conn_stats.stats();
            info!(
                "[QUIC STATS] RTT: {}ms | CWND: {} bytes | Lost Packets: {} | Max Datagram Size: {}",
                stats.path.rtt.as_millis(),
                stats.path.cwnd,
                stats.path.lost_packets,
                conn_stats.max_datagram_size().unwrap_or(0)
            );
        }
    });

    // Wait for any task to terminate
    let res = tokio::select! {
        r = upload_task => { error!("Upload task terminated: {:?}", r); "Upload" },
        r = download_task => { error!("Download task terminated: {:?}", r); "Download" },
        r = icmp_task => { error!("ICMP task terminated: {:?}", r); "ICMP" },
        r = stats_task => { error!("Stats task terminated: {:?}", r); "Stats" },
    };
    
    warn!("VPN Loop Hub shutting down. Trigger: {} task exit", res);
    stop_flag.store(true, Ordering::SeqCst);
    let _ = connection_arc.close(0u32.into(), b"loop_exit");
    
    info!("VPN Loop tasks terminated.");
}

#[cfg(not(target_os = "android"))]
pub async fn run_vpn_loop(_connection: quinn::Connection, _fd: jint, _stop_flag: Arc<AtomicBool>, _config: ControlMessage, _shutdown_rx: tokio::sync::broadcast::Receiver<()>, _http3_framing: bool) {
    error!("VPN Loop not supported on this platform");
}
