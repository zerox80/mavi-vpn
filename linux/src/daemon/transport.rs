//! Unix domain socket transport plus the auth-token file that layers
//! defense-in-depth on top of it. Client and daemon always run on the same
//! machine, so a Unix socket (access-controlled via filesystem permissions)
//! replaces the previous TCP-on-loopback transport.

use anyhow::{Context, Result};
use constant_time_eq::constant_time_eq;
use nix::unistd::{chown, Gid, Group};
use shared::ipc::{self, IpcResponse, SecureIpcRequest};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use super::{dispatch_request, DaemonState};

/// Hard limit on how long an IPC client may take to send the length prefix and
/// the request body combined. Prevents a local process from holding the daemon
/// state lock indefinitely by opening a connection and stalling mid-read.
pub(super) const IPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const IPC_CONTROL_GROUP: &str = "mavivpn";
const IPC_TOKEN_ROOT_ONLY_MODE: u32 = 0o600;
const IPC_TOKEN_GROUP_MODE: u32 = 0o640;
/// The socket needs read+write for the group (not just read, like the token
/// file) since IPC traffic flows both directions over it.
const IPC_SOCKET_ROOT_ONLY_MODE: u32 = 0o600;
const IPC_SOCKET_GROUP_MODE: u32 = 0o660;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum IpcTokenAccess {
    RootOnly,
    Group(Gid),
}

impl IpcTokenAccess {
    pub(super) const fn mode(self) -> u32 {
        match self {
            Self::RootOnly => IPC_TOKEN_ROOT_ONLY_MODE,
            Self::Group(_) => IPC_TOKEN_GROUP_MODE,
        }
    }

    pub(super) const fn socket_mode(self) -> u32 {
        match self {
            Self::RootOnly => IPC_SOCKET_ROOT_ONLY_MODE,
            Self::Group(_) => IPC_SOCKET_GROUP_MODE,
        }
    }
}

pub(super) fn resolve_ipc_token_access() -> Result<IpcTokenAccess> {
    match Group::from_name(IPC_CONTROL_GROUP)? {
        Some(group) => Ok(IpcTokenAccess::Group(group.gid)),
        None => {
            warn!(
                "Unix group '{}' does not exist; IPC token and socket will be root-only. \
                 Run the Linux installer or create the group and add trusted users.",
                IPC_CONTROL_GROUP
            );
            Ok(IpcTokenAccess::RootOnly)
        }
    }
}

pub(super) fn write_ipc_token_with_access(
    token_path: &Path,
    auth_token: &str,
    access: IpcTokenAccess,
) -> Result<()> {
    if let Some(parent) = token_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Remove stale world-readable files left by older versions, then create the
    // new token as root-only. Permissions are widened only after chown succeeds.
    match std::fs::remove_file(token_path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }

    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(IPC_TOKEN_ROOT_ONLY_MODE)
        .custom_flags(libc::O_NOFOLLOW)
        .open(token_path)
        .and_then(|mut f| f.write_all(auth_token.as_bytes()))?;

    if let IpcTokenAccess::Group(gid) = access {
        chown(token_path, None, Some(gid))?;
    }

    std::fs::set_permissions(token_path, std::fs::Permissions::from_mode(access.mode()))?;

    match access {
        IpcTokenAccess::RootOnly => warn!(
            "IPC token at {:?} is root-only. Non-root CLI/GUI users must be added to '{}' \
             after running the installer, then log out and back in.",
            token_path, IPC_CONTROL_GROUP
        ),
        IpcTokenAccess::Group(gid) => info!(
            "IPC token permissions hardened at {:?}: mode {:o}, group {}",
            token_path,
            access.mode(),
            gid.as_raw()
        ),
    }

    Ok(())
}

/// Binds the IPC Unix domain socket at `socket_path` and applies the same
/// group-or-root-only access model used for the auth token.
///
/// Removes any stale socket file first: a crashed daemon leaves the path
/// behind, and `bind()` fails with `AddrInUse` on an existing path (socket or
/// otherwise) — this must be handled unconditionally, since `Restart=on-
/// failure` in the systemd unit makes crash-restart-without-reboot a normal
/// case, not a rare edge case (`/run` only clears on an actual reboot).
pub(super) fn bind_ipc_socket_at(
    socket_path: &Path,
    access: IpcTokenAccess,
) -> Result<UnixListener> {
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    match std::fs::remove_file(socket_path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }

    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("failed to bind IPC socket at {socket_path:?}"))?;

    if let IpcTokenAccess::Group(gid) = access {
        chown(socket_path, None, Some(gid))?;
    }
    std::fs::set_permissions(
        socket_path,
        std::fs::Permissions::from_mode(access.socket_mode()),
    )?;

    Ok(listener)
}

pub(super) fn bind_ipc_socket(access: IpcTokenAccess) -> Result<UnixListener> {
    bind_ipc_socket_at(&ipc::ipc_socket_path(), access)
}

/// Reads, authenticates and dispatches a single request from one IPC client
/// connection, then writes the response. Runs on its own task per connection
/// so a stalled peer cannot block the accept loop or other clients.
pub(super) async fn handle_ipc_client(
    socket: UnixStream,
    state: Arc<Mutex<DaemonState>>,
    auth_token: Arc<String>,
) -> Result<()> {
    // Unix sockets have no meaningful remote address; log the peer's
    // credentials instead (pid/uid), which tokio exposes via SO_PEERCRED and
    // is strictly more useful for auditing than the old anonymous
    // "127.0.0.1:PORT" line. This is informational only, not an
    // authorization check — peer_cred()'s uid is never compared against an
    // allowlist. The actual access-control boundary is the constant-time
    // bearer-token comparison below, backed by the socket's file permissions
    // and group ownership (see bind_ipc_socket_at): any process able to read
    // the token file (root, or a member of the socket's owning group) can
    // drive this daemon regardless of its own uid.
    let peer_desc = socket
        .peer_cred()
        .map(|cred| format!("pid={:?} uid={}", cred.pid(), cred.uid()))
        .unwrap_or_else(|_| "<unknown>".to_string());
    info!("IPC client connected: {}", peer_desc);
    let (mut rx, mut tx) = socket.into_split();

    // Bound the entire header+body read with a single timeout so a client that
    // opens a socket and then goes silent cannot hold resources indefinitely.
    let req_msg = tokio::time::timeout(IPC_REQUEST_TIMEOUT, async {
        let mut len_buf = [0u8; 4];
        rx.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > 65536 {
            anyhow::bail!("IPC request too large: {} bytes", len);
        }
        let mut buf = vec![0u8; len];
        rx.read_exact(&mut buf).await?;
        let (msg, _): (SecureIpcRequest, _) =
            bincode::serde::decode_from_slice(&buf, bincode::config::standard())
                .map_err(|e| anyhow::anyhow!("IPC decode error: {}", e))?;
        Ok::<_, anyhow::Error>(msg)
    })
    .await
    .map_err(|_| anyhow::anyhow!("IPC request timeout from {}", peer_desc))??;

    let resp = if !constant_time_eq(req_msg.auth_token.as_bytes(), auth_token.as_bytes()) {
        error!(
            "Rejecting IPC request from {} due to invalid auth token",
            peer_desc
        );
        IpcResponse::Error("Unauthorized: Invalid IPC Token".to_string())
    } else {
        dispatch_request(req_msg.request, &state).await
    };

    let resp_buf = bincode::serde::encode_to_vec(&resp, bincode::config::standard())
        .map_err(|e| anyhow::anyhow!("Failed to serialize IPC response: {}", e))?;

    tokio::time::timeout(IPC_REQUEST_TIMEOUT, async {
        tx.write_u32_le(resp_buf.len() as u32).await?;
        tx.write_all(&resp_buf).await?;
        Ok::<_, std::io::Error>(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("IPC response write timeout to {}", peer_desc))??;

    Ok(())
}

/// Sends a single IPC request to the running daemon over the Unix socket and
/// returns the response.
pub async fn send_request(req: ipc::IpcRequest) -> Result<IpcResponse> {
    let token_path = ipc::ipc_token_path();
    let auth_token = std::fs::read_to_string(&token_path)
        .map_err(|e| ipc_token_read_error(&token_path, e))?
        .trim()
        .to_string();

    let req_msg = SecureIpcRequest {
        auth_token,
        request: req,
    };

    let mut stream = UnixStream::connect(ipc::ipc_socket_path())
        .await
        .context("failed to connect to IPC daemon socket (is the daemon running?)")?;

    let req_buf = bincode::serde::encode_to_vec(&req_msg, bincode::config::standard())?;
    stream.write_u32_le(req_buf.len() as u32).await?;
    stream.write_all(&req_buf).await?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 65536 {
        return Err(anyhow::anyhow!("Response too large"));
    }

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;

    let (resp, _) = bincode::serde::decode_from_slice(&buf, bincode::config::standard())
        .map_err(|e| anyhow::anyhow!("Decode error: {}", e))?;

    Ok(resp)
}

fn ipc_token_read_error(token_path: &Path, error: io::Error) -> anyhow::Error {
    if error.kind() == io::ErrorKind::PermissionDenied {
        anyhow::anyhow!(
            "Failed to read IPC token from {:?}: permission denied. \
             Your user must be in the '{}' group to control the daemon. \
             Run `sudo usermod -aG {} $USER`, log out and back in, then retry.",
            token_path,
            IPC_CONTROL_GROUP,
            IPC_CONTROL_GROUP
        )
    } else {
        anyhow::anyhow!("Failed to read IPC token from {:?}: {}", token_path, error)
    }
}
