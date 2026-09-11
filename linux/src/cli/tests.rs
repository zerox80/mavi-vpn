use super::handle_action_response;
use shared::ipc::{IpcResponse, VpnState};

#[test]
fn action_acknowledgement_succeeds() {
    assert!(handle_action_response(Ok(IpcResponse::Ok), "Accepted").is_ok());
}

#[test]
fn daemon_rejections_fail_with_the_original_message() {
    for message in [
        "Unauthorized",
        "VPN already running",
        "Network repair failed",
    ] {
        let error =
            handle_action_response(Ok(IpcResponse::Error(message.into())), "Accepted").unwrap_err();
        assert!(error.to_string().contains(message));
    }
}

#[test]
fn ipc_failures_preserve_the_cause_and_daemon_hint() {
    for message in ["permission denied", "connection refused", "Decode error"] {
        let error = handle_action_response(Err(anyhow::anyhow!(message)), "Accepted").unwrap_err();
        let diagnostic = format!("{error:#}");
        assert!(diagnostic.contains(message));
        assert!(diagnostic.contains("Is the daemon running?"));
    }
}

#[test]
fn unrelated_responses_do_not_acknowledge_an_action() {
    for response in [
        IpcResponse::Status {
            running: false,
            endpoint: None,
            state: VpnState::Stopped,
            last_error: None,
            assigned_ip: None,
        },
        IpcResponse::RefreshTokenUpdate {
            connection_id: None,
            refresh_token: None,
        },
    ] {
        let error = handle_action_response(Ok(response), "Accepted").unwrap_err();
        assert!(error.to_string().contains("Unexpected response"));
    }
}
