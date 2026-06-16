use crate::ipc;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex as StdMutex};

pub struct VpnServiceState {
    pub vpn_running: Arc<AtomicBool>,
    pub vpn_connected: Arc<AtomicBool>,
    pub vpn_stopping: Arc<AtomicBool>,
    pub last_error: Arc<StdMutex<Option<String>>>,
    pub assigned_ip: Arc<StdMutex<Option<String>>>,
    /// The access token used for the next (re)handshake. Seeded from the
    /// `Start` config and overwritten by `UpdateToken` so the reconnect loop
    /// always authenticates with the freshest token the GUI has refreshed,
    /// rather than the (possibly expired) one captured when the session began.
    pub current_token: Arc<StdMutex<String>>,
    pub vpn_task: Option<tokio::task::JoinHandle<()>>,
    pub active_config: Option<ipc::Config>,
}

impl VpnServiceState {
    pub fn new() -> Self {
        Self {
            vpn_running: Arc::new(AtomicBool::new(false)),
            vpn_connected: Arc::new(AtomicBool::new(false)),
            vpn_stopping: Arc::new(AtomicBool::new(false)),
            last_error: Arc::new(StdMutex::new(None)),
            assigned_ip: Arc::new(StdMutex::new(None)),
            current_token: Arc::new(StdMutex::new(String::new())),
            vpn_task: None,
            active_config: None,
        }
    }
}
