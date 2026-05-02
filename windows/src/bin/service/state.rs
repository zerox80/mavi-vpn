use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::Mutex;
use crate::ipc;

pub struct VpnServiceState {
    pub vpn_running: Arc<AtomicBool>,
    pub vpn_connected: Arc<AtomicBool>,
    pub vpn_stopping: Arc<AtomicBool>,
    pub last_error: Arc<StdMutex<Option<String>>>,
    pub assigned_ip: Arc<StdMutex<Option<String>>>,
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
            vpn_task: None,
            active_config: None,
        }
    }
}
