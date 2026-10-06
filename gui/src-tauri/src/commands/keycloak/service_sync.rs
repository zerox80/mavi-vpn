use crate::secret_store::{connection_refresh_token_account, SecretStore};
use shared::ipc::{IpcRequest, IpcResponse};
use std::future::Future;

/// Fetching is non-destructive. A write failure, lost reply or cancelled GUI
/// task leaves the service's copy available for a later retry.
pub(super) async fn sync_refresh_token_update<S, R, F>(
    store: &S,
    mut request: R,
) -> Result<bool, String>
where
    S: SecretStore,
    R: FnMut(IpcRequest) -> F,
    F: Future<Output = Result<IpcResponse, String>>,
{
    match request(IpcRequest::TakeRefreshTokenUpdate).await? {
        IpcResponse::RefreshTokenUpdate {
            connection_id: None,
            refresh_token: None,
        } => Ok(false),
        IpcResponse::RefreshTokenUpdate {
            connection_id: Some(connection_id),
            refresh_token: Some(refresh_token),
        } if !connection_id.is_empty() && !refresh_token.trim().is_empty() => {
            store.set_secret(
                &connection_refresh_token_account(&connection_id),
                &refresh_token,
            )?;
            match request(IpcRequest::AcknowledgeRefreshTokenUpdate {
                connection_id,
                refresh_token,
            })
            .await?
            {
                IpcResponse::Ok => Ok(true),
                IpcResponse::Error(error) => Err(error),
                _ => Err("Unexpected response to refresh-token acknowledgement".into()),
            }
        }
        IpcResponse::Error(error) => Err(error),
        _ => Err("Unexpected refresh-token update from service".into()),
    }
}

#[cfg(test)]
mod tests;
