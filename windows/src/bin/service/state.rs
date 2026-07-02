use crate::ipc;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

pub struct VpnStatusSnapshot {
    pub connected: bool,
    pub stopping: bool,
    pub starting: bool,
    pub last_error: Option<String>,
    pub assigned_ip: Option<String>,
    pub endpoint: Option<String>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct PendingKeycloakRefreshToken {
    pub connection_id: String,
    pub refresh_token: String,
}

impl fmt::Debug for PendingKeycloakRefreshToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingKeycloakRefreshToken")
            .field("connection_id", &self.connection_id)
            .field("refresh_token", &"<redacted>")
            .finish()
    }
}

#[derive(Clone)]
pub struct VpnRuntimeHandles {
    pub running: Arc<AtomicBool>,
    pub connected: Arc<AtomicBool>,
    pub stopping: Arc<AtomicBool>,
    pub last_error: Arc<StdMutex<Option<String>>>,
    pub assigned_ip: Arc<StdMutex<Option<String>>>,
    pub current_token: Arc<StdMutex<String>>,
    pub token_updated: Arc<Notify>,
    pub pending_keycloak_refresh_token: Arc<StdMutex<Option<PendingKeycloakRefreshToken>>>,
}

impl VpnRuntimeHandles {
    pub fn record_task_error_if_running(&self, message: String) {
        if self.running.load(Ordering::SeqCst) {
            if let Ok(mut last_error) = self.last_error.lock() {
                *last_error = Some(message);
            }
        } else if !self.has_keycloak_login_required_error() {
            self.clear_last_error();
        }
    }

    pub fn finish_session_flags(&self) {
        self.running.store(false, Ordering::SeqCst);
        self.connected.store(false, Ordering::SeqCst);
        self.stopping.store(false, Ordering::SeqCst);
    }

    fn clear_last_error(&self) {
        if let Ok(mut last_error) = self.last_error.lock() {
            *last_error = None;
        }
    }

    fn has_keycloak_login_required_error(&self) -> bool {
        self.last_error
            .lock()
            .ok()
            .and_then(|last_error| last_error.clone())
            .is_some_and(|error| error.starts_with(ipc::KEYCLOAK_LOGIN_REQUIRED_PREFIX))
    }

    pub fn set_current_token(&self, token: String) {
        if let Ok(mut current_token) = self.current_token.lock() {
            *current_token = token;
        }
        self.token_updated.notify_waiters();
    }

    pub fn publish_keycloak_refresh_token(&self, update: PendingKeycloakRefreshToken) {
        if let Ok(mut pending) = self.pending_keycloak_refresh_token.lock() {
            *pending = Some(update);
        }
    }
}

pub struct VpnServiceState {
    pub vpn_running: Arc<AtomicBool>,
    pub vpn_connected: Arc<AtomicBool>,
    pub vpn_stopping: Arc<AtomicBool>,
    pub last_error: Arc<StdMutex<Option<String>>>,
    pub assigned_ip: Arc<StdMutex<Option<String>>>,
    /// The access token used for the next (re)handshake. Seeded from the
    /// `Start` config and overwritten by service-side refresh or `UpdateToken`
    /// so the reconnect loop authenticates with a fresh token rather than the
    /// possibly expired one captured when the session began.
    pub current_token: Arc<StdMutex<String>>,
    pub token_updated: Arc<Notify>,
    pub pending_keycloak_refresh_token: Arc<StdMutex<Option<PendingKeycloakRefreshToken>>>,
    pub vpn_task: Option<tokio::task::JoinHandle<()>>,
    pub keycloak_refresh_task: Option<tokio::task::JoinHandle<()>>,
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
            token_updated: Arc::new(Notify::new()),
            pending_keycloak_refresh_token: Arc::new(StdMutex::new(None)),
            vpn_task: None,
            keycloak_refresh_task: None,
            active_config: None,
        }
    }

    pub fn active_task_running(&self) -> bool {
        self.vpn_task
            .as_ref()
            .is_some_and(|task| !task.is_finished())
    }

    pub fn is_running(&self) -> bool {
        self.vpn_running.load(Ordering::SeqCst)
    }

    pub fn is_stopping(&self) -> bool {
        self.vpn_stopping.load(Ordering::SeqCst)
    }

    pub fn status_snapshot(&self) -> VpnStatusSnapshot {
        let connected = self.vpn_connected.load(Ordering::SeqCst);
        let stopping = self.vpn_stopping.load(Ordering::SeqCst);
        let starting = self.vpn_running.load(Ordering::SeqCst) && !connected;
        let last_error = self.last_error.lock().ok().and_then(|error| error.clone());
        let assigned_ip = self
            .assigned_ip
            .lock()
            .ok()
            .and_then(|assigned_ip| assigned_ip.clone());
        let endpoint = self
            .active_config
            .as_ref()
            .map(|config| config.endpoint.clone());

        VpnStatusSnapshot {
            connected,
            stopping,
            starting,
            last_error,
            assigned_ip,
            endpoint,
        }
    }

    pub fn runtime_handles(&self) -> VpnRuntimeHandles {
        VpnRuntimeHandles {
            running: self.vpn_running.clone(),
            connected: self.vpn_connected.clone(),
            stopping: self.vpn_stopping.clone(),
            last_error: self.last_error.clone(),
            assigned_ip: self.assigned_ip.clone(),
            current_token: self.current_token.clone(),
            token_updated: self.token_updated.clone(),
            pending_keycloak_refresh_token: self.pending_keycloak_refresh_token.clone(),
        }
    }

    pub fn set_task(&mut self, task: JoinHandle<()>) {
        self.vpn_task = Some(task);
    }

    pub fn set_keycloak_refresh_task(&mut self, task: JoinHandle<()>) {
        self.keycloak_refresh_task = Some(task);
    }

    pub fn take_task(&mut self) -> Option<JoinHandle<()>> {
        self.vpn_task.take()
    }

    pub fn stop_session(&mut self) {
        let task_running = self.active_task_running();
        self.vpn_running.store(false, Ordering::SeqCst);
        self.vpn_connected.store(false, Ordering::SeqCst);
        self.vpn_stopping.store(task_running, Ordering::SeqCst);
        if let Some(task) = self.keycloak_refresh_task.take() {
            task.abort();
        }
        self.active_config = None;
        self.clear_last_error();
        self.clear_assigned_ip();
        self.clear_pending_keycloak_refresh_token();
        self.set_current_token(String::new());
    }

    pub fn mark_session_starting(&mut self, config: ipc::Config) {
        self.active_config = Some(config.clone());
        self.vpn_running.store(true, Ordering::SeqCst);
        self.vpn_connected.store(false, Ordering::SeqCst);
        self.vpn_stopping.store(false, Ordering::SeqCst);
        self.clear_last_error();
        self.clear_pending_keycloak_refresh_token();
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
        self.token_updated.notify_waiters();
    }

    pub fn take_pending_keycloak_refresh_token(&self) -> Option<PendingKeycloakRefreshToken> {
        self.pending_keycloak_refresh_token
            .lock()
            .ok()
            .and_then(|mut pending| pending.take())
    }

    pub fn clear_pending_keycloak_refresh_token(&self) {
        if let Ok(mut pending) = self.pending_keycloak_refresh_token.lock() {
            *pending = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> ipc::Config {
        ipc::Config {
            endpoint: "127.0.0.1:4433".to_string(),
            token: "token".to_string(),
            cert_pin: "abcd".to_string(),
            censorship_resistant: false,
            http3_framing: false,
            kc_auth: None,
            kc_url: None,
            kc_realm: None,
            kc_client_id: None,
            refresh_token: None,
            ech_config: None,
            vpn_mtu: None,
        }
    }

    #[test]
    fn status_snapshot_reports_starting_session() {
        let mut state = VpnServiceState::new();

        state.mark_session_starting(test_config());
        let snapshot = state.status_snapshot();

        assert!(snapshot.starting);
        assert!(!snapshot.connected);
        assert!(!snapshot.stopping);
        assert_eq!(snapshot.endpoint.as_deref(), Some("127.0.0.1:4433"));
    }

    #[test]
    fn stop_session_clears_error_and_assigned_ip() {
        let mut state = VpnServiceState::new();
        *state.last_error.lock().unwrap() = Some("boom".to_string());
        *state.assigned_ip.lock().unwrap() = Some("10.8.0.2".to_string());

        state.stop_session();
        let snapshot = state.status_snapshot();

        assert!(snapshot.last_error.is_none());
        assert!(snapshot.assigned_ip.is_none());
        assert!(snapshot.endpoint.is_none());
    }
}
