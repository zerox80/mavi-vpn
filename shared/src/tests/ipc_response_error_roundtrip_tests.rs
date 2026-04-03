use super::*;

#[test]
fn error_response_roundtrips_with_message() {
    let decoded: ipc::IpcResponse = roundtrip(&ipc::IpcResponse::Error("permission denied".to_string()));

    match decoded {
        ipc::IpcResponse::Error(message) => assert_eq!(message, "permission denied"),
        other => panic!("expected error response, got {other:?}"),
    }
}
