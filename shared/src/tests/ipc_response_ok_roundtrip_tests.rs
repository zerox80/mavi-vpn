use super::*;

#[test]
fn ok_response_roundtrips() {
    let decoded: ipc::IpcResponse = roundtrip(&ipc::IpcResponse::Ok);

    match decoded {
        ipc::IpcResponse::Ok => {}
        other => panic!("expected ok response, got {other:?}"),
    }
}
