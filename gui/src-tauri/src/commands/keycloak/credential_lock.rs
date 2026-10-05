//! Serialize credential transactions across GUI processes of the same user.
use std::fs::{File, OpenOptions, TryLockError};
use std::path::Path;
use std::time::Duration;

/// Hold through fetching, keyring persistence and acknowledgement, or through
/// login and handing the new session to the service. Closing the file releases
/// the OS lock, including when a task is cancelled or its process crashes.
pub(crate) struct CredentialLock {
    _file: File,
}

impl CredentialLock {
    pub(crate) async fn acquire(data_dir: &Path) -> Result<Self, String> {
        std::fs::create_dir_all(data_dir)
            .map_err(|e| format!("Could not create credential lock directory: {e}"))?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(data_dir.join("keycloak-credentials.lock"))
            .map_err(|e| format!("Could not open credential lock: {e}"))?;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(Self { _file: file }),
                // Never block a runtime thread or leave a blocking task that
                // could acquire the lock after its caller has been cancelled.
                Err(TryLockError::WouldBlock) => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(TryLockError::Error(error)) => {
                    return Err(format!("Could not lock Keycloak credentials: {error}"));
                }
            }
        }
    }
}

// Do not unlink the lock file: a waiter may already have opened it. Replacing
// its inode would allow that waiter and a new process to hold different locks.

#[cfg(test)]
mod tests;
