use jni::sys::jint;
use log::error;
use shared::ControlMessage;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

#[cfg(target_os = "android")]
use bytes::BufMut;
#[cfg(target_os = "android")]
use futures_util::future::FutureExt;
#[cfg(target_os = "android")]
use log::{info, warn};
#[cfg(target_os = "android")]
use shared::masque;
#[cfg(target_os = "android")]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_os = "android")]
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
#[cfg(target_os = "android")]
use tokio::io::unix::AsyncFd;

#[cfg(target_os = "android")]
struct AndroidTunnelStats {
    tun_to_quic_bytes: AtomicU64,
    tun_to_quic_packets: AtomicU64,
    quic_send_errors: AtomicU64,
    quic_too_large: AtomicU64,
    quic_to_tun_bytes: AtomicU64,
    quic_to_tun_packets: AtomicU64,
    tun_write_bytes: AtomicU64,
    tun_write_packets: AtomicU64,
    tun_write_drops: AtomicU64,
    tun_write_errors: AtomicU64,
    icmp_feedback_packets: AtomicU64,
}

#[cfg(target_os = "android")]
impl AndroidTunnelStats {
    fn new() -> Self {
        Self {
            tun_to_quic_bytes: AtomicU64::new(0),
            tun_to_quic_packets: AtomicU64::new(0),
            quic_send_errors: AtomicU64::new(0),
            quic_too_large: AtomicU64::new(0),
            quic_to_tun_bytes: AtomicU64::new(0),
            quic_to_tun_packets: AtomicU64::new(0),
            tun_write_bytes: AtomicU64::new(0),
            tun_write_packets: AtomicU64::new(0),
            tun_write_drops: AtomicU64::new(0),
            tun_write_errors: AtomicU64::new(0),
            icmp_feedback_packets: AtomicU64::new(0),
        }
    }
}

#[cfg(not(target_os = "android"))]
#[allow(dead_code)]
pub type RawFd = std::os::raw::c_int;

#[cfg(target_os = "android")]
pub async fn run_vpn_loop(
    connection: quinn::Connection,
    fd: jint,
    stop_flag: Arc<AtomicBool>,
    config: ControlMessage,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    http3_framing: bool,
) {
    let raw_fd = fd as RawFd;

    // Extract Gateway IPs for ICMP signaling
    let (gateway_v4, gateway_v6_opt, tunnel_mtu) = match &config {
        ControlMessage::Config {
            gateway,
            gateway_v6,
            mtu,
            ..
        } => (*gateway, *gateway_v6, *mtu),
        _ => (std::net::Ipv4Addr::new(10, 0, 0, 1), None, 1280),
    };

    // Duplicated FD to manage its lifecycle independently from Java
    let dup_fd = unsafe { libc::dup(raw_fd) };
    if dup_fd < 0 {
        error!(
            "Could not duplicate FD: {}",
            std::io::Error::last_os_error()
        );
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
        Err(e) => {
            error!("Failed to create AsyncFd: {}", e);
            return;
        }
    };

    let connection_arc = Arc::new(connection);
    let (tx_tun, mut rx_tun) = tokio::sync::mpsc::channel::<Vec<u8>>(512);
    let stats = Arc::new(AndroidTunnelStats::new());

    info!("Entering concurrent VPN Loop Hub");

    // --- TASK 1: TUN -> QUIC (Outgoing / Upload) ---
    let stop_upload = stop_flag.clone();
    let tun_upload = tun_async_fd.clone();
    let conn_upload = connection_arc.clone();
    let tx_feedback = tx_tun.clone();
    let stats_upload = stats.clone();

    let upload_task = tokio::spawn(async move {
        let mut buf = bytes::BytesMut::with_capacity(65536);
        loop {
            if stop_upload.load(Ordering::Relaxed) {
                break;
            }

            let mut guard = tokio::select! {
                res = tun_upload.readable() => match res { Ok(g) => g, Err(_) => break },
                _ = shutdown_rx.recv() => break,
            };

            let framed = match guard.try_io(|inner| {
                const PREFIX_LEN: usize = masque::DATAGRAM_PREFIX.len();
                if buf.capacity() < 2048 + PREFIX_LEN {
                    buf.reserve(2048 + PREFIX_LEN);
                }

                // Reserve H3 DATAGRAM_PREFIX headroom in-place. H3 mode ships `framed` as-is
                // (zero per-packet alloc); non-H3 mode slices past the prefix in O(1).
                buf.extend_from_slice(&masque::DATAGRAM_PREFIX);

                let chunk = buf.chunk_mut();
                let max_len = 2048.min(chunk.len());

                let n = unsafe {
                    libc::read(
                        inner.as_raw_fd(),
                        chunk.as_mut_ptr() as *mut libc::c_void,
                        max_len,
                    )
                };

                if n < 0 {
                    let err = std::io::Error::last_os_error();
                    buf.truncate(buf.len() - PREFIX_LEN);
                    return Err(err);
                }
                let n = n as usize;
                if n == 0 {
                    buf.truncate(buf.len() - PREFIX_LEN);
                    return Ok(None);
                }

                unsafe {
                    buf.advance_mut(n);
                }
                let framed = buf.split_to(n + PREFIX_LEN).freeze();
                Ok(Some(framed))
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
                }
                Err(_) => continue, // WouldBlock, let tokio select re-await
            };

            // `framed` is [Quarter Stream ID = 0][Context ID = 0][IP packet] per RFC 9484 §5.
            // `packet` is the raw IP payload (O(1) refcount slice, no copy).
            let packet = framed.slice(masque::DATAGRAM_PREFIX.len()..);
            let packet_len = packet.len();
            stats_upload
                .tun_to_quic_bytes
                .fetch_add(packet_len as u64, Ordering::Relaxed);
            stats_upload
                .tun_to_quic_packets
                .fetch_add(1, Ordering::Relaxed);

            let payload = if http3_framing {
                framed
            } else {
                packet.clone()
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
                        stats_upload.quic_too_large.fetch_add(1, Ordering::Relaxed);
                        let current_limit = conn_upload.max_datagram_size().unwrap_or(1200);
                        warn!(
                            "MTU Limit hit! Packet: {} bytes, Limit: {} bytes",
                            packet_len, current_limit
                        );

                        if packet.is_empty() {
                            continue;
                        }

                        let version = (packet[0] >> 4) & 0xF;
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

                        if let Some(icmp_packet) =
                            shared::icmp::generate_packet_too_big(&packet, reported_mtu, gw)
                        {
                            let _ = tx_feedback.try_send(icmp_packet);
                        }
                    }
                    _ => {
                        stats_upload
                            .quic_send_errors
                            .fetch_add(1, Ordering::Relaxed);
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
    let stats_download = stats.clone();

    let download_task = tokio::spawn(async move {
        loop {
            if stop_download.load(Ordering::Relaxed) {
                break;
            }

            match conn_download.read_datagram().await {
                Ok(first_packet) => {
                    let mut batch = Vec::with_capacity(64);
                    if http3_framing {
                        if let Some(inner) = masque::unwrap_datagram(&first_packet) {
                            let prefix = first_packet.len() - inner.len();
                            batch.push(first_packet.slice(prefix..));
                        }
                    } else {
                        batch.push(first_packet);
                    }

                    for _ in 0..63 {
                        if let Some(Ok(pkt)) = conn_download.read_datagram().now_or_never() {
                            if http3_framing {
                                if let Some(inner) = masque::unwrap_datagram(&pkt) {
                                    let prefix = pkt.len() - inner.len();
                                    batch.push(pkt.slice(prefix..));
                                }
                            } else {
                                batch.push(pkt);
                            }
                        } else {
                            break;
                        }
                    }

                    let batch_bytes: usize = batch.iter().map(|pkt| pkt.len()).sum();
                    stats_download
                        .quic_to_tun_bytes
                        .fetch_add(batch_bytes as u64, Ordering::Relaxed);
                    stats_download
                        .quic_to_tun_packets
                        .fetch_add(batch.len() as u64, Ordering::Relaxed);

                    let mut batch_idx = 0;
                    while batch_idx < batch.len() {
                        let mut guard = match tun_download.writable().await {
                            Ok(g) => g,
                            Err(_) => break,
                        };

                        let res = guard.try_io(|inner| {
                            while batch_idx < batch.len() {
                                let packet = &batch[batch_idx];
                                let n = unsafe {
                                    libc::write(
                                        inner.as_raw_fd(),
                                        packet.as_ptr() as *const libc::c_void,
                                        packet.len(),
                                    )
                                };
                                if n < 0 {
                                    let err = std::io::Error::last_os_error();
                                    if let Some(raw) = err.raw_os_error() {
                                        if raw == libc::EAGAIN || raw == libc::EWOULDBLOCK {
                                            stats_download
                                                .tun_write_errors
                                                .fetch_add(1, Ordering::Relaxed);
                                            return Err(err);
                                        }
                                        if raw == libc::ENOBUFS || raw == libc::EINTR {
                                            // Network internal buffer full or interrupted, just drop the packet immediately
                                            stats_download
                                                .tun_write_drops
                                                .fetch_add(1, Ordering::Relaxed);
                                            batch_idx += 1;
                                            continue;
                                        }
                                    }
                                    if err.kind() == std::io::ErrorKind::WouldBlock {
                                        stats_download
                                            .tun_write_errors
                                            .fetch_add(1, Ordering::Relaxed);
                                        return Err(err);
                                    }
                                    stats_download
                                        .tun_write_errors
                                        .fetch_add(1, Ordering::Relaxed);
                                    return Err(err);
                                }
                                stats_download
                                    .tun_write_bytes
                                    .fetch_add(n as u64, Ordering::Relaxed);
                                stats_download
                                    .tun_write_packets
                                    .fetch_add(1, Ordering::Relaxed);
                                batch_idx += 1;
                            }
                            Ok(())
                        });

                        match res {
                            Ok(Ok(())) => {}
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
                            }
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
    let stats_icmp = stats.clone();
    let icmp_task = tokio::spawn(async move {
        while let Some(icmp_pkt) = rx_tun.recv().await {
            if stop_icmp.load(Ordering::Relaxed) {
                break;
            }
            stats_icmp
                .icmp_feedback_packets
                .fetch_add(1, Ordering::Relaxed);
            if let Ok(mut guard) = tun_icmp.writable().await {
                let _ = guard.try_io(|inner| {
                    let _ = unsafe {
                        libc::write(
                            inner.as_raw_fd(),
                            icmp_pkt.as_ptr() as *const libc::c_void,
                            icmp_pkt.len(),
                        )
                    };
                    Ok(())
                });
            }
        }
    });

    // --- TASK 4: QUIC STATS LOGGING ---
    let stop_stats = stop_flag.clone();
    let conn_stats = connection_arc.clone();
    let stats_log = stats.clone();
    let stats_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        let mut last_tun_to_quic_bytes = 0u64;
        let mut last_quic_to_tun_bytes = 0u64;
        let mut last_tun_write_bytes = 0u64;
        let mut last_udp_tx_bytes = 0u64;
        let mut last_udp_rx_bytes = 0u64;
        loop {
            interval.tick().await;
            if stop_stats.load(Ordering::Relaxed) {
                break;
            }
            let stats = conn_stats.stats();
            let tun_to_quic_bytes = stats_log.tun_to_quic_bytes.load(Ordering::Relaxed);
            let quic_to_tun_bytes = stats_log.quic_to_tun_bytes.load(Ordering::Relaxed);
            let tun_write_bytes = stats_log.tun_write_bytes.load(Ordering::Relaxed);
            let udp_tx_bytes = stats.udp_tx.bytes;
            let udp_rx_bytes = stats.udp_rx.bytes;
            let tun_to_quic_mbit =
                (tun_to_quic_bytes - last_tun_to_quic_bytes) as f64 * 8.0 / 5_000_000.0;
            let quic_to_tun_mbit =
                (quic_to_tun_bytes - last_quic_to_tun_bytes) as f64 * 8.0 / 5_000_000.0;
            let tun_write_mbit =
                (tun_write_bytes - last_tun_write_bytes) as f64 * 8.0 / 5_000_000.0;
            let udp_tx_mbit = (udp_tx_bytes - last_udp_tx_bytes) as f64 * 8.0 / 5_000_000.0;
            let udp_rx_mbit = (udp_rx_bytes - last_udp_rx_bytes) as f64 * 8.0 / 5_000_000.0;
            last_tun_to_quic_bytes = tun_to_quic_bytes;
            last_quic_to_tun_bytes = quic_to_tun_bytes;
            last_tun_write_bytes = tun_write_bytes;
            last_udp_tx_bytes = udp_tx_bytes;
            last_udp_rx_bytes = udp_rx_bytes;
            info!(
                "[ANDROID TUNNEL STATS] tun2quic={:.1}mbit quic2tun={:.1}mbit tun_write={:.1}mbit quic_udp_tx={:.1}mbit quic_udp_rx={:.1}mbit rtt={}ms cwnd={} lost_pkts={} lost_bytes={} max_dgram={} dgram_space={} tun2quic_pkts={} quic_send_err={} quic_too_large={} quic2tun_pkts={} tun_write_pkts={} tun_write_drops={} tun_write_err={} icmp_pkts={}",
                tun_to_quic_mbit,
                quic_to_tun_mbit,
                tun_write_mbit,
                udp_tx_mbit,
                udp_rx_mbit,
                stats.path.rtt.as_millis(),
                stats.path.cwnd,
                stats.path.lost_packets,
                stats.path.lost_bytes,
                conn_stats.max_datagram_size().unwrap_or(0),
                conn_stats.datagram_send_buffer_space(),
                stats_log.tun_to_quic_packets.load(Ordering::Relaxed),
                stats_log.quic_send_errors.load(Ordering::Relaxed),
                stats_log.quic_too_large.load(Ordering::Relaxed),
                stats_log.quic_to_tun_packets.load(Ordering::Relaxed),
                stats_log.tun_write_packets.load(Ordering::Relaxed),
                stats_log.tun_write_drops.load(Ordering::Relaxed),
                stats_log.tun_write_errors.load(Ordering::Relaxed),
                stats_log.icmp_feedback_packets.load(Ordering::Relaxed),
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
pub async fn run_vpn_loop(
    _connection: quinn::Connection,
    _fd: jint,
    _stop_flag: Arc<AtomicBool>,
    _config: ControlMessage,
    _shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    _http3_framing: bool,
) {
    error!("VPN Loop not supported on this platform");
}
