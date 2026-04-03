use super::*;

#[test]
fn local_ipc_address_matches_documented_loopback_socket() {
    assert_eq!(ipc::LOCAL_IPC_ADDR, "127.0.0.1:14433");
}
