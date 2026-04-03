use super::*;

#[test]
#[cfg(unix)]
fn unix_token_path_uses_run_directory() {
    assert_eq!(ipc::ipc_token_path(), std::path::PathBuf::from("/var/run/mavi-vpn.token"));
}
