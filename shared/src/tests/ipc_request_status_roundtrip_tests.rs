use super::*;

#[test]
fn status_request_roundtrips() {
    let decoded: ipc::IpcRequest = roundtrip(&ipc::IpcRequest::Status);

    match decoded {
        ipc::IpcRequest::Status => {}
        other => panic!("expected status request, got {other:?}"),
    }
}
