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
use log::{debug, info, warn};
#[cfg(target_os = "android")]
use shared::masque;
#[cfg(target_os = "android")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(target_os = "android")]
use std::time::{Duration, Instant};

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

#[cfg(target_os = "android")]
const STATS_FLUSH_PACKET_THRESHOLD: u64 = 256;
#[cfg(target_os = "android")]
const STATS_FLUSH_INTERVAL: Duration = Duration::from_secs(1);
#[cfg(target_os = "android")]
const MAX_TUN_PACKET_SIZE: usize = 2048;

#[cfg(target_os = "android")]
#[derive(Clone, Copy)]
enum VpnLoopTask {
    Upload,
    Download,
    Icmp,
    Stats,
}

#[cfg(target_os = "android")]
impl VpnLoopTask {
    fn as_str(self) -> &'static str {
        match self {
            Self::Upload => "Upload",
            Self::Download => "Download",
            Self::Icmp => "ICMP",
            Self::Stats => "Stats",
        }
    }
}

#[cfg(target_os = "android")]
#[derive(Default)]
struct UploadPendingStats {
    tun_to_quic_bytes: u64,
    tun_to_quic_packets: u64,
    quic_send_errors: u64,
    quic_too_large: u64,
}

#[cfg(target_os = "android")]
impl UploadPendingStats {
    fn has_pending(&self) -> bool {
        self.tun_to_quic_bytes != 0
            || self.tun_to_quic_packets != 0
            || self.quic_send_errors != 0
            || self.quic_too_large != 0
    }

    fn should_flush(&self, last_flush: Instant) -> bool {
        self.has_pending()
            && (self.tun_to_quic_packets >= STATS_FLUSH_PACKET_THRESHOLD
                || self.quic_send_errors != 0
                || self.quic_too_large != 0
                || last_flush.elapsed() >= STATS_FLUSH_INTERVAL)
    }

    fn flush(&mut self, stats: &AndroidTunnelStats) {
        if self.tun_to_quic_bytes != 0 {
            stats
                .tun_to_quic_bytes
                .fetch_add(self.tun_to_quic_bytes, Ordering::Relaxed);
            self.tun_to_quic_bytes = 0;
        }
        if self.tun_to_quic_packets != 0 {
            stats
                .tun_to_quic_packets
                .fetch_add(self.tun_to_quic_packets, Ordering::Relaxed);
            self.tun_to_quic_packets = 0;
        }
        if self.quic_send_errors != 0 {
            stats
                .quic_send_errors
                .fetch_add(self.quic_send_errors, Ordering::Relaxed);
            self.quic_send_errors = 0;
        }
        if self.quic_too_large != 0 {
            stats
                .quic_too_large
                .fetch_add(self.quic_too_large, Ordering::Relaxed);
            self.quic_too_large = 0;
        }
    }
}

#[cfg(target_os = "android")]
#[derive(Default)]
struct DownloadPendingStats {
    quic_to_tun_bytes: u64,
    quic_to_tun_packets: u64,
    tun_write_bytes: u64,
    tun_write_packets: u64,
    tun_write_drops: u64,
    tun_write_errors: u64,
}

#[cfg(target_os = "android")]
impl DownloadPendingStats {
    fn has_pending(&self) -> bool {
        self.quic_to_tun_bytes != 0
            || self.quic_to_tun_packets != 0
            || self.tun_write_bytes != 0
            || self.tun_write_packets != 0
            || self.tun_write_drops != 0
            || self.tun_write_errors != 0
    }

    fn should_flush(&self, last_flush: Instant) -> bool {
        self.has_pending()
            && (self.quic_to_tun_packets >= STATS_FLUSH_PACKET_THRESHOLD
                || self.tun_write_packets >= STATS_FLUSH_PACKET_THRESHOLD
                || self.tun_write_drops != 0
                || self.tun_write_errors != 0
                || last_flush.elapsed() >= STATS_FLUSH_INTERVAL)
    }

    fn flush(&mut self, stats: &AndroidTunnelStats) {
        if self.quic_to_tun_bytes != 0 {
            stats
                .quic_to_tun_bytes
                .fetch_add(self.quic_to_tun_bytes, Ordering::Relaxed);
            self.quic_to_tun_bytes = 0;
        }
        if self.quic_to_tun_packets != 0 {
            stats
                .quic_to_tun_packets
                .fetch_add(self.quic_to_tun_packets, Ordering::Relaxed);
            self.quic_to_tun_packets = 0;
        }
        if self.tun_write_bytes != 0 {
            stats
                .tun_write_bytes
                .fetch_add(self.tun_write_bytes, Ordering::Relaxed);
            self.tun_write_bytes = 0;
        }
        if self.tun_write_packets != 0 {
            stats
                .tun_write_packets
                .fetch_add(self.tun_write_packets, Ordering::Relaxed);
            self.tun_write_packets = 0;
        }
        if self.tun_write_drops != 0 {
            stats
                .tun_write_drops
                .fetch_add(self.tun_write_drops, Ordering::Relaxed);
            self.tun_write_drops = 0;
        }
        if self.tun_write_errors != 0 {
            stats
                .tun_write_errors
                .fetch_add(self.tun_write_errors, Ordering::Relaxed);
            self.tun_write_errors = 0;
        }
    }
}

#[cfg(target_os = "android")]
fn take_delta(current: u64, last: &mut u64) -> u64 {
    let delta = current.saturating_sub(*last);
    *last = current;
    delta
}

#[cfg(target_os = "android")]
fn mbit_per_second(bytes: u64, elapsed_secs: f64) -> f64 {
    if elapsed_secs <= 0.0 {
        return 0.0;
    }
    bytes as f64 * 8.0 / elapsed_secs / 1_000_000.0
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

    let mut tasks = tokio::task::JoinSet::new();

    tasks.spawn(async move {
        const PREFIX_LEN: usize = masque::DATAGRAM_PREFIX.len();
        const MAX_UPLOAD_BATCH: usize = 64;
        let mut buf =
            bytes::BytesMut::with_capacity((MAX_TUN_PACKET_SIZE + PREFIX_LEN) * MAX_UPLOAD_BATCH);
        let mut batch: Vec<bytes::Bytes> = Vec::with_capacity(MAX_UPLOAD_BATCH);
        let mut pending_stats = UploadPendingStats::default();
        let mut last_stats_flush = Instant::now();
        loop {
            if stop_upload.load(Ordering::Relaxed) {
                break;
            }

            let mut guard = tokio::select! {
                res = tun_upload.readable() => match res { Ok(g) => g, Err(_) => break },
                _ = shutdown_rx.recv() => break,
            };

            // Batch-read: drain up to MAX_UPLOAD_BATCH packets from TUN in a
            // single try_io() call. This avoids one readable().await event-loop
            // round-trip per packet, which on Android costs ~10-50µs each due
            // to epoll overhead and poor timer resolution.
            let read_result = guard.try_io(|inner| {
                batch.clear();
                let fd = inner.as_raw_fd();
                loop {
                    if buf.capacity() < MAX_TUN_PACKET_SIZE + PREFIX_LEN {
                        buf.reserve(MAX_TUN_PACKET_SIZE + PREFIX_LEN);
                    }

                    // Reserve H3 DATAGRAM_PREFIX headroom in-place. H3 mode ships
                    // `framed` as-is; non-H3 mode slices past the prefix in O(1).
                    buf.extend_from_slice(&masque::DATAGRAM_PREFIX);

                    let chunk = buf.chunk_mut();
                    let max_len = MAX_TUN_PACKET_SIZE.min(chunk.len());

                    let n = unsafe {
                        libc::read(
                            fd,
                            chunk.as_mut_ptr() as *mut libc::c_void,
                            max_len,
                        )
                    };

                    if n < 0 {
                        let err = std::io::Error::last_os_error();
                        // Undo the prefix we just wrote
                        buf.truncate(buf.len() - PREFIX_LEN);
                        if let Some(raw) = err.raw_os_error() {
                            if raw == libc::EAGAIN || raw == libc::EWOULDBLOCK || raw == libc::EINTR
                            {
                                break; // no more packets right now
                            }
                        }
                        if batch.is_empty() {
                            return Err(err);
                        }
                        break;
                    }
                    let n = n as usize;
                    if n == 0 {
                        buf.truncate(buf.len() - PREFIX_LEN);
                        if batch.is_empty() {
                            return Ok(false); // EOF
                        }
                        break;
                    }

                    unsafe {
                        buf.advance_mut(n);
                    }
                    let framed = buf.split_to(n + PREFIX_LEN).freeze();
                    batch.push(framed);

                    if batch.len() >= MAX_UPLOAD_BATCH {
                        break;
                    }
                }

                if batch.is_empty() {
                    Err(std::io::Error::from_raw_os_error(libc::EAGAIN))
                } else {
                    Ok(true) // true = have packets
                }
            });

            match read_result {
                Ok(Ok(false)) => break, // EOF
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
                Err(_) => continue, // WouldBlock from try_io, re-await
                Ok(Ok(true)) => {}  // have packets to send
            }

            // Send all batched packets as QUIC datagrams.
            for framed in batch.drain(..) {
                // `framed` is [Quarter Stream ID = 0][Context ID = 0][IP packet] per RFC 9484 §5.
                // `packet` is the raw IP payload (O(1) refcount slice, no copy).
                let packet = framed.slice(PREFIX_LEN..);
                let packet_len = packet.len();
                pending_stats.tun_to_quic_bytes += packet_len as u64;
                pending_stats.tun_to_quic_packets += 1;

                let payload = if http3_framing {
                    framed
                } else {
                    packet.clone()
                };

                // VPN traffic prefers freshness under congestion. `send_datagram` lets Quinn
                // evict stale queued datagrams instead of blocking the TUN reader.
                let send_result = conn_upload.send_datagram(payload);

                if let Err(e) = send_result {
                    match e {
                        quinn::SendDatagramError::ConnectionLost(_) => {
                            error!("QUIC Connection lost during send");
                            stop_upload.store(true, Ordering::SeqCst);
                            break;
                        }
                        quinn::SendDatagramError::TooLarge => {
                            pending_stats.quic_too_large += 1;
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
                            pending_stats.quic_send_errors += 1;
                            error!("Unexpected SendDatagramError: {:?}", e);
                        }
                    }
                }
            }

            if pending_stats.should_flush(last_stats_flush) {
                pending_stats.flush(&stats_upload);
                last_stats_flush = Instant::now();
            }
        }
        pending_stats.flush(&stats_upload);
        info!("Upload task exited.");
        VpnLoopTask::Upload
    });

    // --- TASK 2: QUIC -> TUN (Incoming / Download) ---
    let stop_download = stop_flag.clone();
    let tun_download = tun_async_fd.clone();
    let conn_download = connection_arc.clone();
    let stats_download = stats.clone();

    tasks.spawn(async move {
        let mut batch = Vec::with_capacity(64);
        let mut pending_stats = DownloadPendingStats::default();
        let mut last_stats_flush = Instant::now();
        loop {
            if stop_download.load(Ordering::Relaxed) {
                break;
            }

            match conn_download.read_datagram().await {
                Ok(first_packet) => {
                    batch.clear();
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
                    pending_stats.quic_to_tun_bytes += batch_bytes as u64;
                    pending_stats.quic_to_tun_packets += batch.len() as u64;

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
                                            pending_stats.tun_write_errors += 1;
                                            return Err(err);
                                        }
                                        if raw == libc::ENOBUFS || raw == libc::EINTR {
                                            // Network internal buffer full or interrupted, just drop the packet immediately
                                            pending_stats.tun_write_drops += 1;
                                            batch_idx += 1;
                                            continue;
                                        }
                                    }
                                    if err.kind() == std::io::ErrorKind::WouldBlock {
                                        pending_stats.tun_write_errors += 1;
                                        return Err(err);
                                    }
                                    pending_stats.tun_write_errors += 1;
                                    return Err(err);
                                }
                                pending_stats.tun_write_bytes += n as u64;
                                pending_stats.tun_write_packets += 1;
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

                    if pending_stats.should_flush(last_stats_flush) {
                        pending_stats.flush(&stats_download);
                        last_stats_flush = Instant::now();
                    }
                }
                Err(_) => {
                    stop_download.store(true, Ordering::SeqCst);
                    break;
                }
            }
        }
        pending_stats.flush(&stats_download);
        info!("Download task exited.");
        VpnLoopTask::Download
    });

    // --- TASK 3: ICMP Feedback -> TUN ---
    let stop_icmp = stop_flag.clone();
    let tun_icmp = tun_async_fd.clone();
    let stats_icmp = stats.clone();
    tasks.spawn(async move {
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
        VpnLoopTask::Icmp
    });

    // --- TASK 4: QUIC STATS LOGGING ---
    let stop_stats = stop_flag.clone();
    let conn_stats = connection_arc.clone();
    let stats_log = stats.clone();
    tasks.spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_tun_to_quic_bytes = 0u64;
        let mut last_quic_to_tun_bytes = 0u64;
        let mut last_tun_write_bytes = 0u64;
        let mut last_udp_tx_bytes = 0u64;
        let mut last_udp_rx_bytes = 0u64;
        let mut last_tun_to_quic_packets = 0u64;
        let mut last_quic_send_errors = 0u64;
        let mut last_quic_too_large = 0u64;
        let mut last_quic_to_tun_packets = 0u64;
        let mut last_tun_write_packets = 0u64;
        let mut last_tun_write_drops = 0u64;
        let mut last_tun_write_errors = 0u64;
        let mut last_icmp_feedback_packets = 0u64;
        let mut last_lost_packets = 0u64;
        let mut last_lost_bytes = 0u64;
        interval.tick().await;
        let mut last_tick = Instant::now();
        loop {
            interval.tick().await;
            if stop_stats.load(Ordering::Relaxed) {
                break;
            }
            let now = Instant::now();
            let elapsed_secs = now.duration_since(last_tick).as_secs_f64();
            last_tick = now;

            let stats = conn_stats.stats();
            let tun_to_quic_bytes = stats_log.tun_to_quic_bytes.load(Ordering::Relaxed);
            let quic_to_tun_bytes = stats_log.quic_to_tun_bytes.load(Ordering::Relaxed);
            let tun_write_bytes = stats_log.tun_write_bytes.load(Ordering::Relaxed);
            let udp_tx_bytes = stats.udp_tx.bytes;
            let udp_rx_bytes = stats.udp_rx.bytes;
            let tun_to_quic_packets = stats_log.tun_to_quic_packets.load(Ordering::Relaxed);
            let quic_send_errors = stats_log.quic_send_errors.load(Ordering::Relaxed);
            let quic_too_large = stats_log.quic_too_large.load(Ordering::Relaxed);
            let quic_to_tun_packets = stats_log.quic_to_tun_packets.load(Ordering::Relaxed);
            let tun_write_packets = stats_log.tun_write_packets.load(Ordering::Relaxed);
            let tun_write_drops = stats_log.tun_write_drops.load(Ordering::Relaxed);
            let tun_write_errors = stats_log.tun_write_errors.load(Ordering::Relaxed);
            let icmp_feedback_packets = stats_log.icmp_feedback_packets.load(Ordering::Relaxed);

            let tun_to_quic_bytes_delta =
                take_delta(tun_to_quic_bytes, &mut last_tun_to_quic_bytes);
            let quic_to_tun_bytes_delta =
                take_delta(quic_to_tun_bytes, &mut last_quic_to_tun_bytes);
            let tun_write_bytes_delta = take_delta(tun_write_bytes, &mut last_tun_write_bytes);
            let udp_tx_bytes_delta = take_delta(udp_tx_bytes, &mut last_udp_tx_bytes);
            let udp_rx_bytes_delta = take_delta(udp_rx_bytes, &mut last_udp_rx_bytes);
            let tun_to_quic_packets_delta =
                take_delta(tun_to_quic_packets, &mut last_tun_to_quic_packets);
            let quic_send_errors_delta = take_delta(quic_send_errors, &mut last_quic_send_errors);
            let quic_too_large_delta = take_delta(quic_too_large, &mut last_quic_too_large);
            let quic_to_tun_packets_delta =
                take_delta(quic_to_tun_packets, &mut last_quic_to_tun_packets);
            let tun_write_packets_delta =
                take_delta(tun_write_packets, &mut last_tun_write_packets);
            let tun_write_drops_delta = take_delta(tun_write_drops, &mut last_tun_write_drops);
            let tun_write_errors_delta = take_delta(tun_write_errors, &mut last_tun_write_errors);
            let icmp_feedback_packets_delta =
                take_delta(icmp_feedback_packets, &mut last_icmp_feedback_packets);
            let lost_packets_delta = take_delta(stats.path.lost_packets, &mut last_lost_packets);
            let lost_bytes_delta = take_delta(stats.path.lost_bytes, &mut last_lost_bytes);

            let tun_to_quic_mbit = mbit_per_second(tun_to_quic_bytes_delta, elapsed_secs);
            let quic_to_tun_mbit = mbit_per_second(quic_to_tun_bytes_delta, elapsed_secs);
            let tun_write_mbit = mbit_per_second(tun_write_bytes_delta, elapsed_secs);
            let udp_tx_mbit = mbit_per_second(udp_tx_bytes_delta, elapsed_secs);
            let udp_rx_mbit = mbit_per_second(udp_rx_bytes_delta, elapsed_secs);
            let tun_pending_packets = quic_to_tun_packets
                .saturating_sub(tun_write_packets.saturating_add(tun_write_drops));
            let max_dgram = conn_stats.max_datagram_size().unwrap_or(0);
            let dgram_space = conn_stats.datagram_send_buffer_space();
            let diag = if tun_write_drops_delta > 0 || tun_write_errors_delta > 0 {
                "android_tun_backpressure"
            } else if lost_packets_delta > 0 || lost_bytes_delta > 0 {
                "quic_path_loss"
            } else if quic_send_errors_delta > 0 || quic_too_large_delta > 0 {
                "quic_send_issue"
            } else if dgram_space == 0 {
                "quic_send_buffer_full"
            } else if tun_write_mbit + 5.0 < quic_to_tun_mbit {
                "tun_write_lag"
            } else {
                "ok"
            };

            debug!(
                "[ANDROID TUNNEL STATS] window={:.2}s diag={} app_up={:.1}mbit app_down={:.1}mbit tun_write={:.1}mbit udp_tx={:.1}mbit udp_rx={:.1}mbit rtt={}ms cwnd={} max_dgram={} dgram_space={} loss_pkts_delta={} loss_bytes_delta={} loss_pkts_total={} loss_bytes_total={} pkts_up_delta={} pkts_down_delta={} tun_write_pkts_delta={} tun_pending_pkts={} tun_drops_delta={} tun_drops_total={} tun_err_delta={} tun_err_total={} quic_send_err_delta={} quic_send_err_total={} quic_too_large_delta={} quic_too_large_total={} icmp_delta={} icmp_total={}",
                elapsed_secs,
                diag,
                tun_to_quic_mbit,
                quic_to_tun_mbit,
                tun_write_mbit,
                udp_tx_mbit,
                udp_rx_mbit,
                stats.path.rtt.as_millis(),
                stats.path.cwnd,
                max_dgram,
                dgram_space,
                lost_packets_delta,
                lost_bytes_delta,
                stats.path.lost_packets,
                stats.path.lost_bytes,
                tun_to_quic_packets_delta,
                quic_to_tun_packets_delta,
                tun_write_packets_delta,
                tun_pending_packets,
                tun_write_drops_delta,
                tun_write_drops,
                tun_write_errors_delta,
                tun_write_errors,
                quic_send_errors_delta,
                quic_send_errors,
                quic_too_large_delta,
                quic_too_large,
                icmp_feedback_packets_delta,
                icmp_feedback_packets,
            );
        }
        VpnLoopTask::Stats
    });

    // The original sender is only needed to create the upload feedback sender.
    // Dropping it lets the ICMP task finish naturally when upload exits.
    drop(tx_tun);

    // Wait for any task to terminate.
    let res = match tasks.join_next().await {
        Some(Ok(task)) => {
            error!("{} task terminated", task.as_str());
            task.as_str()
        }
        Some(Err(err)) => {
            error!("VPN loop task terminated with join error: {:?}", err);
            "JoinError"
        }
        None => "NoTask",
    };

    warn!("VPN Loop Hub shutting down. Trigger: {} task exit", res);
    stop_flag.store(true, Ordering::SeqCst);
    let _ = connection_arc.close(0u32.into(), b"loop_exit");

    tasks.abort_all();
    while let Some(result) = tasks.join_next().await {
        if let Err(err) = result {
            if !err.is_cancelled() {
                error!("VPN loop task failed during shutdown: {:?}", err);
            }
        }
    }

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
