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
pub async fn run_vpn_loop(connection: quinn::Connection, fd: jint, stop_flag: Arc<AtomicBool>, config: ControlMessage, mut shutdown_rx: tokio::sync::broadcast::Receiver<()>) {
    let raw_fd = fd as RawFd;

    // Extract Gateway IPs for ICMP signaling
    let (gateway_v4, gateway_v6_opt) = match &config {
        ControlMessage::Config { gateway, gateway_v6, .. } => (*gateway, *gateway_v6),
        _ => (std::net::Ipv4Addr::new(10, 0, 0, 1), None),
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
    let (tx_tun, mut rx_tun) = tokio::sync::mpsc::channel::<Vec<u8>>(256); // Increased capacity

    info!("Entering concurrent VPN Loop Hub");

    // --- TASK 1: TUN -> QUIC (Outgoing / Upload) ---
    let stop_upload = stop_flag.clone();
    let tun_upload = tun_async_fd.clone();
    let conn_upload = connection_arc.clone();
    let tx_feedback = tx_tun.clone();
    
    let upload_task = tokio::spawn(async move {
        let mut read_buf = bytes::BytesMut::with_capacity(128 * 1024);
        loop {
            if stop_upload.load(Ordering::Relaxed) { break; }
            
            let mut readable_guard = tokio::select! {
                res = tun_upload.readable() => match res {
                    Ok(g) => g,
                    Err(_) => break,
                },
                _ = shutdown_rx.recv() => break,
            };
            
            let res = readable_guard.try_io(|inner| {
                let mut packets = Vec::with_capacity(32);
                loop {
                    if read_buf.remaining_mut() < 2048 { read_buf.reserve(2048); }
                    let chunk = read_buf.chunk_mut();
                    let n = unsafe { libc::read(inner.as_raw_fd(), chunk.as_mut_ptr() as *mut libc::c_void, chunk.len()) };
                    
                    if n < 0 {
                        let err = std::io::Error::last_os_error();
                        if err.kind() == std::io::ErrorKind::WouldBlock {
                            if packets.is_empty() {
                                return Err(err); 
                            } else {
                                break;
                            }
                        }
                        return Err(err);
                    }
                    if n == 0 { break; }
                    
                    unsafe { read_buf.advance_mut(n as usize); }
                    packets.push(read_buf.split_to(n as usize).freeze());
                    if packets.len() >= 32 { break; } 
                }
                Ok(packets)
            });

            if let Ok(Ok(packets)) = res {
                for packet in packets {
                    // FIX: Nutze send_datagram_wait().await für echtes TCP-Backpressure,
                    // anstatt Pakete bei vollem Puffer lautlos zu verwerfen.
                    if let Err(e) = conn_upload.send_datagram_wait(packet.clone()).await {
                        match e {
                            quinn::SendDatagramError::ConnectionLost(_) => {
                                error!("QUIC Connection lost during send");
                                stop_upload.store(true, Ordering::SeqCst);
                                break;
                            }
                            quinn::SendDatagramError::TooLarge => {
                                let current_limit = conn_upload.max_datagram_size().unwrap_or(1200);
                                warn!("MTU Limit hit! Packet: {} bytes, Limit: {} bytes", packet.len(), current_limit);
                                
                                let version = (packet[0] >> 4) & 0xF;
                                let gw = if version == 4 { 
                                    std::net::IpAddr::V4(gateway_v4) 
                                } else { 
                                     std::net::IpAddr::V6(gateway_v6_opt.unwrap_or_else(|| "fd00::1".parse().unwrap())) 
                                };
                                let reported_mtu = if version == 6 {
                                    std::cmp::max(current_limit as u16, 1280)
                                } else {
                                    current_limit as u16
                                };

                                if let Some(icmp_packet) = shared::icmp::generate_packet_too_big(&packet, reported_mtu, Some(gw)) {
                                    let _ = tx_feedback.try_send(icmp_packet);
                                }
                            },
                            _ => {
                                error!("Unexpected SendDatagramError: {:?}", e);
                            }
                        }
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
                Ok(first_packet) => {
                    let mut batch = Vec::with_capacity(32);
                    batch.push(first_packet);

                    for _ in 0..31 {
                         if let Some(Ok(pkt)) = conn_download.read_datagram().now_or_never() {
                             batch.push(pkt);
                         } else { break; }
                    }

                    for packet in batch {
                        loop {
                            if stop_download.load(Ordering::Relaxed) { break; }
                            
                            let mut guard = match tun_download.writable().await {
                                Ok(g) => g,
                                Err(_) => break,
                            };

                            let res = guard.try_io(|inner| {
                                let n = unsafe { libc::write(inner.as_raw_fd(), packet.as_ptr() as *const libc::c_void, packet.len()) };
                                if n < 0 {
                                    let err = std::io::Error::last_os_error();
                                    if err.kind() == std::io::ErrorKind::WouldBlock {
                                        return Err(err); 
                                    }
                                    return Err(err); 
                                }
                                Ok(())
                            });

                            match res {
                                Ok(Ok(())) => break, 
                                Ok(Err(e)) => {
                                    error!("Fatal TUN Write error: {}", e);
                                    stop_download.store(true, Ordering::SeqCst);
                                    break;
                                }
                                Err(_would_block) => continue, 
                            }
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
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
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
pub async fn run_vpn_loop(_connection: quinn::Connection, _fd: jint, _stop_flag: Arc<AtomicBool>, _config: ControlMessage, _shutdown_rx: tokio::sync::broadcast::Receiver<()>) {
    error!("VPN Loop not supported on this platform");
}
