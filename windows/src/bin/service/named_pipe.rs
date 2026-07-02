//! Windows Named Pipe transport for the service IPC channel, replacing TCP
//! loopback. Unlike `TcpListener::accept()`, which is one always-listening
//! socket, a named pipe server needs a fresh *instance* per client: once a
//! client connects to an instance, that instance is "used up" and a new one
//! must be created immediately so the next client is never left waiting on a
//! stalled peer. Concurrent *serving* is still bounded by `ipc_slots`
//! (the same semaphore the previous TCP implementation used), so behavior
//! for callers is unchanged — only the transport primitive differs.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::{Mutex, Semaphore};
use tracing::{error, warn};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

use super::handlers::handle_ipc_client;
use super::state::VpnServiceState;
use super::utils::ipc_pipe_sddl;
use crate::ipc;

/// Owns a self-relative security descriptor allocated by
/// `ConvertStringSecurityDescriptorToSecurityDescriptorW` and frees it with
/// `LocalFree` on drop. `CreateNamedPipeW` only reads the descriptor for the
/// duration of the call, so this only needs to outlive one pipe-creation
/// call, not the pipe instance itself.
struct SecurityDescriptorGuard(*mut c_void);

impl Drop for SecurityDescriptorGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            #[allow(unsafe_code)]
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

#[allow(unsafe_code)]
fn build_security_attributes(
    sddl: &str,
) -> anyhow::Result<(SECURITY_ATTRIBUTES, SecurityDescriptorGuard)> {
    let wide_sddl: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sd_ptr: *mut c_void = std::ptr::null_mut();

    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd_ptr,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        anyhow::bail!(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {}",
            std::io::Error::last_os_error()
        );
    }

    let guard = SecurityDescriptorGuard(sd_ptr);
    let attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd_ptr,
        bInheritHandle: 0,
    };
    Ok((attrs, guard))
}

/// Creates one named pipe server instance at `pipe_name`, secured with
/// `sddl`. `first` must be `true` for exactly the very first instance created
/// before the accept loop starts — Windows requires the first instance of a
/// pipe name to set `FILE_FLAG_FIRST_PIPE_INSTANCE` (rejecting creation if a
/// pipe with that name already exists, which prevents another process from
/// squatting the name); every recycled instance after that must leave it
/// unset.
#[allow(unsafe_code)]
fn create_pipe_instance_at(
    pipe_name: &str,
    first: bool,
    sddl: &str,
) -> anyhow::Result<NamedPipeServer> {
    let (mut attrs, _sd_guard) = build_security_attributes(sddl)?;

    // Safety: `attrs` is a valid, fully-initialized `SECURITY_ATTRIBUTES`
    // whose `lpSecurityDescriptor` is kept alive by `_sd_guard` for the
    // duration of this call (`CreateNamedPipeW` only reads it synchronously).
    let server = unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .in_buffer_size(65536)
            .out_buffer_size(65536)
            .create_with_security_attributes_raw(
                pipe_name,
                std::ptr::addr_of_mut!(attrs).cast::<c_void>(),
            )
    }
    .map_err(|e| anyhow::anyhow!("failed to create IPC named pipe instance: {e}"))?;

    Ok(server)
}

/// Creates one named pipe server instance at the production IPC pipe name,
/// secured with the current console user's ACL (see [`ipc_pipe_sddl`]).
fn create_pipe_instance(first: bool) -> anyhow::Result<NamedPipeServer> {
    create_pipe_instance_at(ipc::ipc_pipe_name(), first, &ipc_pipe_sddl())
}

/// Serves IPC clients over the named pipe until `stop_signal` is set.
///
/// The instance-recycling step (creating the next instance immediately after
/// a client connects, *before* that client's request is handled) is the
/// single most important correctness property here: get the ordering wrong
/// and the pipe effectively serializes all clients, silently defeating the
/// concurrency `ipc_slots` is meant to provide and reintroducing the
/// single-stalled-client DoS the per-connection task model was built to
/// avoid.
pub async fn accept_loop(
    state: Arc<Mutex<VpnServiceState>>,
    auth_token: Arc<String>,
    ipc_slots: Arc<Semaphore>,
    stop_signal: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let mut current = create_pipe_instance(true)?;

    loop {
        if stop_signal.load(Ordering::SeqCst) {
            break;
        }

        tokio::select! {
            () = tokio::time::sleep(Duration::from_millis(500)) => continue,
            connect_res = current.connect() => {
                // Replace `current` with a fresh instance immediately,
                // regardless of the connect outcome, so the pipe name never
                // goes without a listening instance.
                let next = match create_pipe_instance(false) {
                    Ok(p) => p,
                    Err(e) => {
                        error!("Failed to create next IPC pipe instance: {e}. Retrying shortly.");
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        create_pipe_instance(false)
                            .map_err(|e2| anyhow::anyhow!("IPC pipe instance retry also failed: {e2}"))?
                    }
                };
                let connected = std::mem::replace(&mut current, next);

                match connect_res {
                    Ok(()) => {
                        let permit = match ipc_slots.clone().try_acquire_owned() {
                            Ok(permit) => permit,
                            Err(_) => {
                                warn!(
                                    "Rejecting IPC client because the connection limit ({}) is reached",
                                    super::main_loop::MAX_CONCURRENT_IPC_CLIENTS
                                );
                                continue;
                            }
                        };
                        let state = state.clone();
                        let auth_token = auth_token.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(e) = handle_ipc_client(connected, state, auth_token).await {
                                warn!("IPC client handler exited: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Named pipe connect error: {e}");
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Grants Everyone full control — deliberately permissive, since these
    /// tests must succeed regardless of which account runs the test suite
    /// (dev machine, CI runner), unlike the production SDDL from
    /// `ipc_pipe_sddl()` which only grants SYSTEM/Administrators/the console
    /// user (tested separately in `utils::tests`).
    const TEST_SDDL_EVERYONE_FULL_CONTROL: &str = "D:P(A;;GA;;;WD)";

    /// A unique pipe name per call so parallel tests never collide with each
    /// other or with a real Mavi VPN service instance that might be running
    /// on the same dev machine.
    fn unique_test_pipe_name() -> String {
        use std::sync::atomic::AtomicU32;
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        format!(r"\\.\pipe\mavi-vpn-test-{}-{}", std::process::id(), n)
    }

    #[tokio::test]
    async fn create_pipe_instance_succeeds_for_first_and_recycled_instances() {
        let name = unique_test_pipe_name();
        let first = create_pipe_instance_at(&name, true, TEST_SDDL_EVERYONE_FULL_CONTROL)
            .expect("first instance");
        // The first instance is still open (holding FILE_FLAG_FIRST_PIPE_INSTANCE),
        // so a second call without `first` must succeed as a normal recycled
        // instance rather than colliding with it.
        let _second = create_pipe_instance_at(&name, false, TEST_SDDL_EVERYONE_FULL_CONTROL)
            .expect("recycled instance");
        drop(first);
    }

    #[tokio::test]
    async fn second_first_pipe_instance_fails_while_first_is_open() {
        let name = unique_test_pipe_name();
        let _first = create_pipe_instance_at(&name, true, TEST_SDDL_EVERYONE_FULL_CONTROL)
            .expect("first instance");
        let err =
            create_pipe_instance_at(&name, true, TEST_SDDL_EVERYONE_FULL_CONTROL).unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("pipe")
                || err.to_string().to_lowercase().contains("access")
                || err.to_string().to_lowercase().contains("instance"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn client_can_connect_and_exchange_data_with_a_pipe_instance() {
        let name = unique_test_pipe_name();
        let server = create_pipe_instance_at(&name, true, TEST_SDDL_EVERYONE_FULL_CONTROL)
            .expect("create server instance");
        let connect_fut = server.connect();

        // `ClientOptions::open` (`CreateFileW`) succeeds as soon as the
        // server instance exists (`CreateNamedPipeW` already ran above) — the
        // server does not need to have called `ConnectNamedPipe`/`.connect()`
        // yet, so it is safe to open synchronously before awaiting it.
        let client = tokio::net::windows::named_pipe::ClientOptions::new()
            .open(&name)
            .expect("client connects to pipe");

        connect_fut.await.expect("server accepts connection");
        drop(client);
    }
}
