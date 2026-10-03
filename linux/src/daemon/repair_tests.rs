use super::*;

#[tokio::test]
async fn incomplete_cleanup_reaches_the_gui_and_cli_as_an_error() {
    let state = Arc::new(Mutex::new(DaemonState::new()));
    let response = dispatch_request_with_hooks(IpcRequest::RepairNetwork, &state, false, || {
        anyhow::bail!("Unmarked IPv6 blocks remain: run sudo mavi-vpn repair --legacy-ipv6")
    })
    .await;
    let IpcResponse::Error(message) = response else {
        panic!("An incomplete repair must not be acknowledged as successful");
    };
    assert!(message.contains("repair --legacy-ipv6"));
    assert!(message.contains("Network repair incomplete"));
}
