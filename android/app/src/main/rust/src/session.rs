use shared::ControlMessage;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

use crate::connection::H3SessionGuard;

pub struct VpnSession {
    pub runtime: tokio::runtime::Runtime,
    pub connection: quinn::Connection,
    pub config: ControlMessage,
    pub http3_framing: bool,
    pub stop_flag: Arc<AtomicBool>,
    /// Freshest access token. Seeded with the handshake token and overwritten by
    /// `NativeLib.updateToken` after the GUI refresh ticker renews it; the in-band
    /// reauth task reads this and presents it to the server over the live
    /// connection so the tunnel survives the original token's expiry.
    pub current_token: Arc<Mutex<String>>,
    pub shutdown_tx: broadcast::Sender<()>,
    // Kept alive for the lifetime of the session. Dropping this sends
    // CONNECTION_CLOSE(H3_NO_ERROR) to the server; only ever drop when the
    // VPN is actually tearing down.
    pub _h3_guard: Option<H3SessionGuard>,
}

impl VpnSession {
    pub fn new(
        runtime: tokio::runtime::Runtime,
        connection: quinn::Connection,
        config: ControlMessage,
        http3_framing: bool,
        token: String,
        h3_guard: Option<H3SessionGuard>,
    ) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        Self {
            runtime,
            connection,
            config,
            http3_framing,
            stop_flag: Arc::new(AtomicBool::new(false)),
            current_token: Arc::new(Mutex::new(token)),
            shutdown_tx,
            _h3_guard: h3_guard,
        }
    }
}
