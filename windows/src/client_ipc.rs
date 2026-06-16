use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::ipc::{self, IpcRequest, IpcResponse};

const MAX_IPC_RESPONSE_BYTES: usize = 65_536;

pub(crate) async fn send_request_internal(req: IpcRequest) -> Result<IpcResponse> {
    let token_path = ipc::ipc_token_path();
    let auth_token = std::fs::read_to_string(&token_path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                anyhow::anyhow!(
                    "Failed to read IPC token from {}: access denied. Your Windows user is not allowed to control the Mavi VPN service. Log in and restart the service so it can grant your desktop session access, or run the client as Administrator.",
                    token_path.display()
                )
            } else {
                anyhow::anyhow!(
                    "Failed to read IPC token from {}. Is the service running? {e}",
                    token_path.display()
                )
            }
        })?
        .trim()
        .to_string();

    let req_msg = ipc::SecureIpcRequest {
        auth_token,
        request: req,
    };

    let mut client = TcpStream::connect(ipc::LOCAL_IPC_ADDR).await?;
    let req_buf = bincode::serde::encode_to_vec(&req_msg, bincode::config::standard())?;
    #[allow(clippy::cast_possible_truncation)]
    client.write_u32_le(req_buf.len() as u32).await?;
    client.write_all(&req_buf).await?;
    let len = read_response_len(&mut client).await?;
    let mut buf = vec![0u8; len];
    client.read_exact(&mut buf).await?;
    let (resp, _) = bincode::serde::decode_from_slice(&buf, bincode::config::standard())
        .map_err(|e| anyhow::anyhow!("Decode error: {e}"))?;
    Ok(resp)
}

pub(crate) async fn send_request(req: IpcRequest) -> Result<()> {
    let is_start = matches!(req, IpcRequest::Start(_));
    match send_request_internal(req).await {
        Ok(IpcResponse::Ok) => {
            if is_start {
                wait_for_connected().await?;
            } else {
                println!("Action executed successfully.");
            }
        }
        Ok(IpcResponse::Error(msg)) => {
            println!("Service returned an error: {msg}");
        }
        Ok(IpcResponse::Status {
            running,
            endpoint,
            state,
            last_error,
            assigned_ip,
        }) => {
            println!("Status: {}", if running { "RUNNING" } else { "STOPPED" });
            println!("State: {state:?}");
            if let Some(ep) = endpoint {
                println!("Endpoint: {ep}");
            }
            if let Some(ip) = assigned_ip {
                println!("Tunnel IP: {ip}");
            }
            if let Some(err) = last_error {
                println!("Last error: {err}");
            }
        }
        Err(e) => {
            println!("Failed to communicate with service: {e}");
        }
    }
    Ok(())
}

async fn wait_for_connected() -> Result<()> {
    println!("Start accepted. Waiting for tunnel readiness...");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        match send_request_internal(IpcRequest::Status).await {
            Ok(IpcResponse::Status {
                running: true,
                endpoint,
                assigned_ip,
                ..
            }) => {
                println!("VPN is now CONNECTED.");
                if let Some(ep) = endpoint {
                    println!("Endpoint: {ep}");
                }
                if let Some(ip) = assigned_ip {
                    println!("Tunnel IP: {ip}");
                }
                return Ok(());
            }
            Ok(IpcResponse::Status {
                state: ipc::VpnState::Failed,
                last_error,
                ..
            }) => {
                anyhow::bail!(
                    "VPN failed to connect: {}",
                    last_error.as_deref().unwrap_or("unknown error")
                );
            }
            Ok(_) => tokio::time::sleep(std::time::Duration::from_millis(250)).await,
            Err(e) => {
                anyhow::bail!("Failed to read status after start: {e}");
            }
        }
    }
    anyhow::bail!("VPN is still starting. Run status to check progress.")
}

async fn read_response_len(client: &mut TcpStream) -> Result<usize> {
    let mut len_buf = [0u8; 4];
    client.read_exact(&mut len_buf).await?;
    validate_response_len(u32::from_le_bytes(len_buf) as usize)
}

fn validate_response_len(len: usize) -> Result<usize> {
    if len > MAX_IPC_RESPONSE_BYTES {
        anyhow::bail!("Response too large");
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_len_accepts_limit() {
        assert_eq!(
            validate_response_len(MAX_IPC_RESPONSE_BYTES).unwrap(),
            MAX_IPC_RESPONSE_BYTES
        );
    }

    #[test]
    fn response_len_rejects_oversized_payload() {
        assert!(validate_response_len(MAX_IPC_RESPONSE_BYTES + 1).is_err());
    }
}
