use crate::ipc;
use std::sync::atomic::{AtomicBool, Ordering};
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

    pub fn active_task_running(&self) -> bool {
        self.vpn_task
            .as_ref()
            .is_some_and(|task| !task.is_finished())
    }

    pub fn stop_session(&mut self) {
        let task_running = self.active_task_running();
        self.vpn_running.store(false, Ordering::SeqCst);
        self.vpn_connected.store(false, Ordering::SeqCst);
        self.vpn_stopping.store(task_running, Ordering::SeqCst);
        self.active_config = None;
        self.clear_last_error();
        self.clear_assigned_ip();
    }

    pub fn mark_session_starting(&mut self, config: ipc::Config) {
        self.active_config = Some(config.clone());
        self.vpn_running.store(true, Ordering::SeqCst);
        self.vpn_connected.store(false, Ordering::SeqCst);
        self.vpn_stopping.store(false, Ordering::SeqCst);
        self.clear_last_error();
        self.set_current_token(config.token);
    }

    pub fn clear_last_error(&self) {
        if let Ok(mut last_error) = self.last_error.lock() {
            *last_error = None;
        }
    }

    pub fn clear_assigned_ip(&self) {
        if let Ok(mut assigned_ip) = self.assigned_ip.lock() {
            *assigned_ip = None;
        }
    }

    pub fn set_current_token(&self, token: String) {
        if let Ok(mut current_token) = self.current_token.lock() {
            *current_token = token;
        }
    }
}
