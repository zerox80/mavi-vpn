//! Local IPC transport paths.
//!
//! The daemon/service and its CLI/GUI clients always run on the same
//! machine, so the transport is OS-native local IPC rather than a network
//! socket: a Unix domain socket on Linux, a Windows Named Pipe on Windows.
//! The auth token (see `ipc_token_path`) is kept as defense-in-depth on top
//! of the transport's own filesystem/ACL access control.

/// Path to the authentication token file used to secure the local IPC
/// transport.
#[cfg(windows)]
#[must_use]
pub fn ipc_token_path() -> std::path::PathBuf {
    std::path::PathBuf::from(r"C:\ProgramData\mavi-vpn\ipc.token")
}

#[cfg(unix)]
#[must_use]
pub fn ipc_token_path() -> std::path::PathBuf {
    std::path::PathBuf::from("/run/mavi-vpn/ipc.token")
}

/// Unix domain socket path for the daemon IPC transport (Linux/Unix only).
/// Lives alongside the auth token so both are covered by the same
/// `/run/mavi-vpn` directory ACL.
#[cfg(unix)]
#[must_use]
pub fn ipc_socket_path() -> std::path::PathBuf {
    std::path::PathBuf::from("/run/mavi-vpn/mavi-vpn.sock")
}

/// Windows named pipe path for the service IPC transport (Windows only).
#[cfg(windows)]
#[must_use]
pub fn ipc_pipe_name() -> &'static str {
    r"\\.\pipe\MaviVPNIpc"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn unix_ipc_token_lives_under_runtime_directory() {
        assert_eq!(
            ipc_token_path(),
            std::path::PathBuf::from("/run/mavi-vpn/ipc.token")
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_ipc_socket_lives_under_runtime_directory() {
        assert_eq!(
            ipc_socket_path(),
            std::path::PathBuf::from("/run/mavi-vpn/mavi-vpn.sock")
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_ipc_socket_and_token_share_parent_directory() {
        assert_eq!(ipc_socket_path().parent(), ipc_token_path().parent());
    }

    #[cfg(windows)]
    #[test]
    fn ipc_pipe_name_has_correct_prefix() {
        assert!(ipc_pipe_name().starts_with(r"\\.\pipe\"));
    }
}
