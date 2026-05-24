use shared::ipc::{IpcRequest, IpcResponse, LOCAL_IPC_ADDR};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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

    let mut stream = TcpStream::connect(LOCAL_IPC_ADDR)
        .await
        .map_err(|e| format!("Service not running: {e}"))?;

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
