use shared::ipc::{IpcRequest, IpcResponse};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Windows returns this OS error when every server-side pipe instance is
/// momentarily connected (`ERROR_PIPE_BUSY`) — unlike TCP's backlog queue, a
/// named pipe client must retry rather than block.
#[cfg(windows)]
const ERROR_PIPE_BUSY: i32 = 231;
#[cfg(windows)]
const PIPE_BUSY_RETRY_ATTEMPTS: u32 = 5;
#[cfg(windows)]
const PIPE_BUSY_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(100);

#[cfg(unix)]
async fn connect() -> Result<tokio::net::UnixStream, String> {
    tokio::net::UnixStream::connect(shared::ipc::ipc_socket_path())
        .await
        .map_err(|e| format!("Service not running: {e}"))
}

/// Opens the IPC named pipe, retrying briefly on `ERROR_PIPE_BUSY`. With
/// `MAX_CONCURRENT_IPC_CLIENTS` server-side instances this should be rare in
/// practice, but the retry is required for correctness rather than assumed
/// away.
#[cfg(windows)]
async fn connect() -> Result<tokio::net::windows::named_pipe::NamedPipeClient, String> {
    use tokio::net::windows::named_pipe::ClientOptions;

    let mut last_busy_err = None;
    for _ in 0..PIPE_BUSY_RETRY_ATTEMPTS {
        match ClientOptions::new().open(shared::ipc::ipc_pipe_name()) {
            Ok(client) => return Ok(client),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                last_busy_err = Some(e);
                tokio::time::sleep(PIPE_BUSY_RETRY_DELAY).await;
            }
            Err(e) => return Err(format!("Service not running: {e}")),
        }
    }
    Err(format!(
        "Mavi VPN service is busy (too many concurrent clients); retry shortly: {}",
        last_busy_err.map_or_else(String::new, |e| e.to_string())
    ))
}

pub(crate) async fn send_ipc_request(req: &IpcRequest) -> Result<IpcResponse, String> {
    let token_path = shared::ipc::ipc_token_path();
    let auth_token = std::fs::read_to_string(&token_path)
        .map_err(|e| ipc_token_read_error(&token_path, e))?
        .trim()
        .to_string();

    let req_msg = shared::ipc::SecureIpcRequest {
        auth_token,
        request: req.clone(),
    };

    let mut stream = connect().await?;

    let encoded = bincode::serde::encode_to_vec(&req_msg, bincode::config::standard())
        .map_err(|e| e.to_string())?;

    #[allow(clippy::cast_possible_truncation)]
    stream
        .write_u32_le(encoded.len() as u32)
        .await
        .map_err(|e| e.to_string())?;
    stream
        .write_all(&encoded)
        .await
        .map_err(|e| e.to_string())?;

    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| e.to_string())?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 {
        return Err("Service sent an empty IPC response".into());
    }
    if len > 65536 {
        return Err("Response too large".into());
    }

    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| e.to_string())?;

    let (resp, _) = bincode::serde::decode_from_slice(&buf, bincode::config::standard())
        .map_err(|e| e.to_string())?;

    Ok(resp)
}

fn ipc_token_read_error(token_path: &std::path::Path, error: std::io::Error) -> String {
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        if cfg!(target_os = "linux") {
            format!(
                "Failed to read IPC token at {}: permission denied. Your user must be in the 'mavivpn' group to control the daemon. Run `sudo usermod -aG mavivpn $USER`, log out and back in, then retry.",
                token_path.display()
            )
        } else if cfg!(target_os = "windows") {
            format!(
                "Failed to read IPC token at {}: permission denied. Your Windows user is not allowed to control the Mavi VPN service. Log in and restart the service so it can grant your desktop session access, or run the GUI as Administrator.",
                token_path.display()
            )
        } else {
            format!(
                "Failed to read IPC token at {}: permission denied.",
                token_path.display()
            )
        }
    } else {
        format!(
            "Failed to read IPC token (is the service running?) at {}: {error}",
            token_path.display()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipc_token_permission_denied_message_is_specific() {
        let message = ipc_token_read_error(
            std::path::Path::new("/tmp/mavi.token"),
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        );

        assert!(message.contains("permission denied"));
        assert!(message.contains("/tmp/mavi.token"));
    }
}
