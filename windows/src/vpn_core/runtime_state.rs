use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

/// Shared runtime handles for a single VPN service session. Bundles the flags
/// and mutable state used by the connection loop, packet pumps, and the in-band
/// reauth task so they do not have to be passed individually through every
/// layer. The service only owns the current *access* token; the long-lived
/// Keycloak refresh token stays in the user-session GUI, which pushes freshly
/// minted access tokens here via IPC `UpdateToken`.
#[derive(Clone)]
pub(super) struct VpnRuntimeState {
    running: Arc<AtomicBool>,
    connected: Arc<AtomicBool>,
    last_error: Arc<StdMutex<Option<String>>>,
    assigned_ip: Arc<StdMutex<Option<String>>>,
    current_token: Arc<StdMutex<String>>,
}

impl VpnRuntimeState {
    pub(super) fn new(
        running: Arc<AtomicBool>,
        connected: Arc<AtomicBool>,
        last_error: Arc<StdMutex<Option<String>>>,
        assigned_ip: Arc<StdMutex<Option<String>>>,
        current_token: Arc<StdMutex<String>>,
    ) -> Self {
        Self {
            running,
            connected,
            last_error,
            assigned_ip,
            current_token,
        }
    }

    pub(super) fn running(&self) -> &Arc<AtomicBool> {
        &self.running
    }

    pub(super) fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub(super) fn stop_running(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    pub(super) fn set_connected(&self, connected: bool) {
        self.connected.store(connected, Ordering::SeqCst);
    }

    pub(super) fn current_token_or(&self, fallback: &str) -> String {
        self.current_token
            .lock()
            .map(|token| token.clone())
            .unwrap_or_else(|_| fallback.to_string())
    }

    /// Returns a clone of the `current_token` Arc so the in-band reauth task
    /// can read updates the GUI pushes via IPC `UpdateToken`.
    pub(super) fn current_token(&self) -> Arc<StdMutex<String>> {
        self.current_token.clone()
    }

    pub(super) fn set_last_error(&self, error: Option<String>) {
        if let Ok(mut last) = self.last_error.lock() {
            *last = error;
        }
    }

    pub(super) fn clear_last_error(&self) {
        self.set_last_error(None);
    }

    pub(super) fn set_assigned_ip(&self, ip: String) {
        if let Ok(mut assigned_ip) = self.assigned_ip.lock() {
            *assigned_ip = Some(ip);
        }
    }

    pub(super) fn clear_assigned_ip(&self) {
        if let Ok(mut assigned_ip) = self.assigned_ip.lock() {
            *assigned_ip = None;
        }
    }
}
