#[cfg(not(target_os = "android"))]
use jni::sys::jint;
#[cfg(not(target_os = "android"))]
use log::error;
#[cfg(not(target_os = "android"))]
use shared::ControlMessage;
#[cfg(not(target_os = "android"))]
use std::sync::atomic::AtomicBool;
#[cfg(not(target_os = "android"))]
use std::sync::Arc;

#[cfg(not(target_os = "android"))]
use crate::connection::TunnelConnection;

#[cfg(target_os = "android")]
mod android;
mod framing;
mod icmp;
#[cfg(target_os = "android")]
mod stats;

#[cfg(target_os = "android")]
pub use self::android::run_vpn_loop;
#[allow(unused_imports)]
pub(crate) use self::framing::{quic_datagram_to_tun_packet, tun_payload_for_quic};
#[allow(unused_imports)]
pub(crate) use self::icmp::packet_too_big_feedback;

#[cfg(not(target_os = "android"))]
#[allow(dead_code)]
pub type RawFd = std::os::raw::c_int;

#[cfg(not(target_os = "android"))]
pub async fn run_vpn_loop(
    _connection: TunnelConnection,
    _fd: jint,
    _stop_flag: Arc<AtomicBool>,
    _config: ControlMessage,
    _shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    _http3_framing: bool,
) {
    error!("VPN Loop not supported on this platform");
}
