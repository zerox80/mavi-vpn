use anyhow::Result;
use std::{future::Future, sync::Arc};
use tokio::sync::{Notify, OwnedSemaphorePermit};
use tokio::time::Instant;

/// Keep the original deadline and pending permit until config delivery succeeds.
/// The handler retains H3 streams and IP guards across setup and tunnel execution.
pub(super) async fn until_ready(
    connection: &quinn::Connection,
    deadline: Instant,
    pending_permit: OwnedSemaphorePermit,
    setup_complete: Arc<Notify>,
    handler: impl Future<Output = Result<()>>,
) -> Result<()> {
    tokio::pin!(handler);
    tokio::select! {
        // Poll the handler, then its readiness signal, before the timer. Once
        // the handler signals and starts tunnel tasks, even a simultaneously
        // ready deadline must not cancel it and detach those tasks.
        biased;
        result = &mut handler => return result,
        () = setup_complete.notified() => {},
        () = tokio::time::sleep_until(deadline) => {
            connection.close(0_u32.into(), b"pre-authentication timed out");
            anyhow::bail!("QUIC pre-authentication timed out");
        }
    }
    drop(pending_permit);
    handler.await
}
