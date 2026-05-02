use std::sync::atomic::AtomicU64;

pub(super) struct AndroidTunnelStats {
    pub(super) tun_to_quic_bytes: AtomicU64,
    pub(super) tun_to_quic_packets: AtomicU64,
    pub(super) quic_send_errors: AtomicU64,
    pub(super) quic_too_large: AtomicU64,
    pub(super) quic_to_tun_bytes: AtomicU64,
    pub(super) quic_to_tun_packets: AtomicU64,
    pub(super) tun_write_bytes: AtomicU64,
    pub(super) tun_write_packets: AtomicU64,
    pub(super) tun_write_drops: AtomicU64,
    pub(super) tun_write_errors: AtomicU64,
    pub(super) icmp_feedback_packets: AtomicU64,
}

impl AndroidTunnelStats {
    pub(super) fn new() -> Self {
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
