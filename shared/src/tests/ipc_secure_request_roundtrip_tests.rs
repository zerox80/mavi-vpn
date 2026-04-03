use super::*;

#[test]
fn secure_request_roundtrips_auth_token_and_command() {
    let request = ipc::SecureIpcRequest {
        auth_token: "ipc-secret".to_string(),
        request: ipc::IpcRequest::Start(sample_ipc_config_minimal()),
    };

    let decoded: ipc::SecureIpcRequest = roundtrip(&request);

    assert_eq!(decoded.auth_token, "ipc-secret");
    match decoded.request {
        ipc::IpcRequest::Start(config) => assert_eq!(config.token, "plain-token"),
        other => panic!("expected start request, got {other:?}"),
    }
}
