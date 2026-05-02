#[cfg(test)]
mod tests {
    use crate::ipc;
    use crate::handlers::dispatch_request;
    use crate::state::VpnServiceState;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use std::time::Duration;

    fn test_config() -> ipc::Config {
        ipc::Config {
            endpoint: "vpn.example.com:4433".to_string(),
            token: "token".to_string(),
            cert_pin: "deadbeef".to_string(),
            censorship_resistant: false,
            http3_framing: false,
            kc_auth: None,
            kc_url: None,
            kc_realm: None,
            kc_client_id: None,
            ech_config: None,
            vpn_mtu: None,
        }
    }

    fn test_state() -> Arc<Mutex<VpnServiceState>> {
        Arc::new(Mutex::new(VpnServiceState::new()))
    }

    #[tokio::test]
    async fn stop_request_marks_active_task_as_stopping() {
        let state = test_state();
        let sleeper = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(60)).await;
        });
        {
            let mut guard = state.lock().await;
            guard.vpn_running.store(true, Ordering::SeqCst);
            guard.vpn_connected.store(true, Ordering::SeqCst);
            guard.active_config = Some(test_config());
            if let Ok(mut last) = guard.last_error.lock() {
                *last = Some("old error".to_string());
            }
            guard.vpn_task = Some(sleeper);
        }

        assert!(matches!(
            dispatch_request(ipc::IpcRequest::Stop, &state).await,
            ipc::IpcResponse::Ok
        ));

        let task = {
            let mut guard = state.lock().await;
            assert!(!guard.vpn_running.load(Ordering::SeqCst));
            assert!(!guard.vpn_connected.load(Ordering::SeqCst));
            assert!(guard.vpn_stopping.load(Ordering::SeqCst));
            assert!(guard.active_config.is_none());
            assert!(guard.last_error.lock().unwrap().is_none());
            guard.vpn_task.take()
        };
        if let Some(task) = task {
            task.abort();
        }
    }

    #[tokio::test]
    async fn stop_request_without_task_reports_stopped() {
        let state = test_state();
        {
            let mut guard = state.lock().await;
            guard.vpn_running.store(true, Ordering::SeqCst);
            guard.vpn_connected.store(true, Ordering::SeqCst);
            guard.active_config = Some(test_config());
        }

        assert!(matches!(
            dispatch_request(ipc::IpcRequest::Stop, &state).await,
            ipc::IpcResponse::Ok
        ));

        let guard = state.lock().await;
        assert!(!guard.vpn_running.load(Ordering::SeqCst));
        assert!(!guard.vpn_connected.load(Ordering::SeqCst));
        assert!(!guard.vpn_stopping.load(Ordering::SeqCst));
        assert!(guard.active_config.is_none());
        drop(guard);
    }

    #[tokio::test]
    async fn start_request_is_rejected_while_stopping() {
        let state = test_state();
        {
            let guard = state.lock().await;
            guard.vpn_stopping.store(true, Ordering::SeqCst);
        }

        match dispatch_request(ipc::IpcRequest::Start(test_config()), &state).await {
            ipc::IpcResponse::Error(msg) => {
                assert_eq!(msg, "VPN is stopping; retry shortly");
            }
            other => panic!("Expected Error, got {other:?}"),
        }
    }
}
