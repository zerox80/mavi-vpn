use super::*;

#[test]
fn stop_request_roundtrips() {
    let decoded: ipc::IpcRequest = roundtrip(&ipc::IpcRequest::Stop);

    match decoded {
        ipc::IpcRequest::Stop => {}
        other => panic!("expected stop request, got {other:?}"),
    }
}
