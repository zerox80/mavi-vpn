use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient, ServerOptions};
use windows_sys::Win32::Foundation::ERROR_NO_TOKEN;
use windows_sys::Win32::Storage::FileSystem::SECURITY_ANONYMOUS;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

fn pipe() -> (NamedPipeServer, String) {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    let name = format!(
        r"\\.\pipe\mavi-caller-test-{}-{}",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    );
    let server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(&name)
        .unwrap();
    (server, name)
}

async fn read_client_message(server: &mut NamedPipeServer, client: &mut NamedPipeClient) {
    server.connect().await.unwrap();
    client.write_all(b"request").await.unwrap();
    let mut message = [0; 7];
    server.read_exact(&mut message).await.unwrap();
}

fn assert_not_impersonating() {
    let mut token = null_mut();
    // SAFETY: a valid thread pseudo-handle and writable output pointer.
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) };
    if opened != 0 {
        drop(TokenHandle(token));
        panic!("IPC identity lookup left the thread impersonating");
    }
    // SAFETY: read the error from the immediately preceding Windows call.
    assert_eq!(unsafe { GetLastError() }, ERROR_NO_TOKEN);
}

#[tokio::test]
async fn identification_client_resolves_its_user_and_restores_service_identity() {
    assert_not_impersonating();
    let mut token = null_mut();
    // SAFETY: a valid process pseudo-handle and writable output pointer.
    assert_ne!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) },
        0
    );
    let token = TokenHandle(token);
    let expected_sid = token_user_sid(token.0).unwrap();
    let (mut server, name) = pipe();
    // This uses Tokio's default SECURITY_IDENTIFICATION, as do the GUI and CLI.
    let mut client = ClientOptions::new().open(name).unwrap();
    read_client_message(&mut server, &mut client).await;

    assert_eq!(client_user_sid(&server).unwrap(), expected_sid);
    assert_not_impersonating();
}

#[tokio::test]
async fn anonymous_client_fails_closed_and_restores_service_identity() {
    let (mut server, name) = pipe();
    let mut client = ClientOptions::new()
        .security_qos_flags(SECURITY_ANONYMOUS)
        .open(name)
        .unwrap();
    read_client_message(&mut server, &mut client).await;

    assert!(client_user_sid(&server).is_err());
    assert_not_impersonating();
}

#[tokio::test]
async fn unconnected_pipe_has_no_caller_identity() {
    let (server, _) = pipe();
    assert!(client_user_sid(&server).is_err());
    assert_not_impersonating();
}
