use super::*;

#[test]
fn status_response_roundtrips_running_state_and_endpoint() {
    let decoded: ipc::IpcResponse = roundtrip(&ipc::IpcResponse::Status {
        running: true,
        endpoint: Some("vpn.example.com:4433".to_string()),
    });

    match decoded {
        ipc::IpcResponse::Status { running, endpoint } => {
            assert!(running);
            assert_eq!(endpoint.as_deref(), Some("vpn.example.com:4433"));
        }
        other => panic!("expected status response, got {other:?}"),
    }
}
