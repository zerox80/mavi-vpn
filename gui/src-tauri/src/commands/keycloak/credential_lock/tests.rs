use super::*;
use crate::commands::keycloak::service_sync::sync_refresh_token_update;
use crate::secret_store::SecretStore;
use shared::ipc::{IpcRequest, IpcResponse};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::{Child, Command};
use tokio::time::timeout;

const CHILD_DIR: &str = "MAVI_TEST_CREDENTIAL_LOCK_DIR";

struct FileSecretStore<'a>(&'a Path);

impl SecretStore for FileSecretStore<'_> {
    fn set_secret(&self, _: &str, token: &str) -> Result<(), String> {
        std::fs::write(self.0.join("secret"), token).map_err(|e| e.to_string())
    }

    fn get_secret(&self, _: &str) -> Result<Option<String>, String> {
        unreachable!()
    }

    fn delete_secret(&self, _: &str) -> Result<(), String> {
        unreachable!()
    }
}

// Run in a separate process to exercise the OS lock, not a process-local mutex.
#[tokio::test]
async fn credential_lock_child() {
    let Some(dir) = std::env::var_os(CHILD_DIR) else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let _guard = CredentialLock::acquire(&dir).await.unwrap();
    sync_refresh_token_update(&FileSecretStore(&dir), |request| {
        let response = match request {
            IpcRequest::TakeRefreshTokenUpdate => {
                // Pause with a fetched T1 before persisting/acknowledging it.
                let response = IpcResponse::RefreshTokenUpdate {
                    connection_id: Some("profile".into()),
                    refresh_token: Some("T1".into()),
                };
                std::fs::write(dir.join("ready"), b"fetched T1").unwrap();
                let mut release = String::new();
                std::io::stdin().read_line(&mut release).unwrap();
                assert_eq!(release.trim(), "persist");
                response
            }
            IpcRequest::AcknowledgeRefreshTokenUpdate { .. } => {
                assert_eq!(std::fs::read(dir.join("secret")).unwrap(), b"T1");
                IpcResponse::Ok
            }
            other => panic!("Unexpected request {other:?}"),
        };
        std::future::ready(Ok(response))
    })
    .await
    .unwrap();
}

async fn paused_gui(dir: &Path) -> Child {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "commands::keycloak::credential_lock::tests::credential_lock_child",
        ])
        .env(CHILD_DIR, dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    timeout(Duration::from_secs(10), async {
        while !dir.join("ready").exists() {
            assert!(child.try_wait().unwrap().is_none(), "child exited early");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("child did not acquire the credential lock");
    child
}

#[tokio::test]
async fn another_gui_cannot_write_newer_credentials_while_old_update_is_in_flight() {
    let dir = tempfile::tempdir().unwrap();
    let mut older_gui = paused_gui(dir.path()).await;

    // A second GUI's sync/login cannot reach its read or write until the first
    // GUI completes its entire transaction, even though its fetch has finished.
    assert!(timeout(
        Duration::from_millis(150),
        CredentialLock::acquire(dir.path())
    )
    .await
    .is_err());
    assert!(!dir.path().join("secret").exists());

    older_gui
        .stdin
        .take()
        .unwrap()
        .write_all(b"persist\n")
        .await
        .unwrap();
    assert!(timeout(Duration::from_secs(10), older_gui.wait())
        .await
        .unwrap()
        .unwrap()
        .success());

    let newer_gui = timeout(Duration::from_secs(2), CredentialLock::acquire(dir.path()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(std::fs::read(dir.path().join("secret")).unwrap(), b"T1");
    std::fs::write(dir.path().join("secret"), b"T2").unwrap();
    drop(newer_gui);
    assert_eq!(std::fs::read(dir.path().join("secret")).unwrap(), b"T2");
}

#[tokio::test]
async fn crashed_gui_releases_lock_without_deleting_the_lock_file() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = paused_gui(dir.path()).await;
    child.kill().await.unwrap();
    let guard = timeout(Duration::from_secs(2), CredentialLock::acquire(dir.path()))
        .await
        .unwrap()
        .unwrap();
    drop(guard);
    assert!(dir.path().join("keycloak-credentials.lock").exists());
}

#[tokio::test]
async fn cancelled_waiter_does_not_keep_or_later_acquire_the_lock() {
    let dir = tempfile::tempdir().unwrap();
    let owner = CredentialLock::acquire(dir.path()).await.unwrap();
    assert!(timeout(
        Duration::from_millis(100),
        CredentialLock::acquire(dir.path())
    )
    .await
    .is_err());
    drop(owner);
    let _next = timeout(Duration::from_secs(2), CredentialLock::acquire(dir.path()))
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn inaccessible_lock_fails_instead_of_allowing_unprotected_writes() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("keycloak-credentials.lock")).unwrap();
    assert!(CredentialLock::acquire(dir.path()).await.is_err());
}
