use super::*;

#[test]
fn start_request_roundtrips_with_nested_config() {
    let decoded: ipc::IpcRequest = roundtrip(&ipc::IpcRequest::Start(sample_ipc_config_full()));

    match decoded {
        ipc::IpcRequest::Start(config) => {
            assert_eq!(config.endpoint, "vpn.example.com:4433");
            assert_eq!(config.kc_client_id.as_deref(), Some("desktop-client"));
        }
        other => panic!("expected start request, got {other:?}"),
    }
}
