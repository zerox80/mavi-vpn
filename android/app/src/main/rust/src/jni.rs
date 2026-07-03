// JNI inherently requires `unsafe` (raw env pointers, #[no_mangle] exports,
// session handles round-tripped through jlong). Same precedent as the Windows
// service entry point, which also allows unsafe_code at module level.
#![allow(unsafe_code)]

use android_logger::Config;
use jni::objects::{JClass, JObject, JString};
use jni::sys::{jint, jlong};
use jni::{AttachGuard, Env, EnvUnowned, JValue};
use log::{error, info};
use std::sync::atomic::Ordering;
use std::sync::{Mutex, Once, OnceLock};

use crate::connection::connect_and_handshake;
use crate::session::VpnSession;
use crate::vpn_loop::run_vpn_loop;

const INIT_RETRYABLE_FAILURE: jlong = 0;
const INIT_FATAL_AUTH: jlong = -1;
const INIT_FATAL_CERT: jlong = -2;
const INIT_FATAL_CONFIG: jlong = -3;

fn last_init_error() -> &'static Mutex<String> {
    static LAST_INIT_ERROR: OnceLock<Mutex<String>> = OnceLock::new();
    LAST_INIT_ERROR.get_or_init(|| Mutex::new(String::new()))
}

fn set_last_init_error(message: &str) {
    let mut last = last_init_error()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    last.clear();
    last.push_str(message);
}

fn clear_last_init_error() {
    let mut last = last_init_error()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    last.clear();
}

fn classify_init_error(message: &str) -> jlong {
    // Matching is case-insensitive (unlike the desktop reconnect loops) since
    // JNI error strings pass through several layers that may change casing.
    let msg = message.to_ascii_lowercase();
    let contains_marker = |marker: &str| msg.contains(&marker.to_ascii_lowercase());
    if msg.contains("invalid certificate pin")
        || msg.contains("pin mismatch")
        || msg.contains("certificate pin mismatch")
    {
        return INIT_FATAL_CERT;
    }
    if msg.contains("server error: unauthorized")
        || contains_marker(shared::session_errors::MARKER_AUTH_FAILED)
        || msg.contains("access denied")
        || msg.contains("invalid keycloak token")
        || msg.contains("invalid token")
    {
        return INIT_FATAL_AUTH;
    }
    if msg.contains("endpoint host missing")
        || msg.contains("invalid address")
        || contains_marker(shared::session_errors::MARKER_MTU_MISMATCH)
        || contains_marker(shared::session_errors::MARKER_UNSUPPORTED_MTU)
    {
        return INIT_FATAL_CONFIG;
    }
    INIT_RETRYABLE_FAILURE
}

fn validated_vpn_mtu(vpn_mtu: jint) -> Result<Option<u16>, String> {
    if vpn_mtu <= 0 {
        return Ok(None);
    }

    let mtu = u16::try_from(vpn_mtu).map_err(|_| format!("Unsupported VPN MTU: {vpn_mtu}"))?;
    if (shared::MIN_TUN_MTU..=shared::MAX_TUN_MTU).contains(&mtu) {
        Ok(Some(mtu))
    } else {
        Err(format!("Unsupported VPN MTU: {vpn_mtu}"))
    }
}

#[allow(improper_ctypes_definitions)]
#[no_mangle]
#[allow(clippy::too_many_lines)]
pub extern "system" fn Java_com_mavi_vpn_nativelib_NativeLib_init<'local>(
    env_unowned: EnvUnowned<'local>,
    _this: JObject<'local>,
    service: JObject<'local>,
    token: JString<'local>,
    endpoint: JString<'local>,
    cert_pin: JString<'local>,
    censorship_resistant: jni::sys::jboolean,
    http3_framing: jni::sys::jboolean,
    ech_config: JString<'local>,
    vpn_mtu: jint,
) -> jlong {
    let mut guard = unsafe { AttachGuard::from_unowned(env_unowned.as_raw()) };
    let env = guard.borrow_env_mut();
    clear_last_init_error();

    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            static LOGGER_INIT: Once = Once::new();
            LOGGER_INIT.call_once(|| {
                android_logger::init_once(
                    Config::default()
                        .with_tag("MaviVPN")
                        .with_max_level(log::LevelFilter::Info),
                );
                let _ = rustls::crypto::ring::default_provider().install_default();
            });

            info!("JNI init called. CR Mode: {censorship_resistant}");

            let get_string = |env: &mut Env, jstr: &JString| -> Option<String> {
                #[allow(deprecated)]
                match env.get_string(jstr) {
                    Ok(s) => Some(s.into()),
                    Err(e) => {
                        error!("Failed to get string from JNI: {e}");
                        None
                    }
                }
            };

            let Some(token) = get_string(env, &token) else {
                set_last_init_error("Failed to read VPN token from JNI");
                return INIT_FATAL_CONFIG;
            };
            let Some(endpoint) = get_string(env, &endpoint) else {
                set_last_init_error("Failed to read VPN endpoint from JNI");
                return INIT_FATAL_CONFIG;
            };
            let Some(cert_pin_str) = get_string(env, &cert_pin) else {
                set_last_init_error("Failed to read certificate pin from JNI");
                return INIT_FATAL_CONFIG;
            };

            // Optional: hex-encoded ECHConfigList. Empty string → no ECH override.
            let ech_config_hex: Option<String> =
                get_string(env, &ech_config).filter(|s| !s.is_empty());

            if cert_pin_str.is_empty() {
                let message = "Certificate PIN is empty. Connection aborted.";
                error!("{message}");
                set_last_init_error(message);
                return INIT_FATAL_CERT;
            }

            // Validate the MTU before allocating any sockets or the runtime so an
            // out-of-range value fails fast instead of after expensive setup.
            let vpn_mtu_opt = match validated_vpn_mtu(vpn_mtu) {
                Ok(vpn_mtu) => vpn_mtu,
                Err(message) => {
                    error!("{message}");
                    set_last_init_error(&message);
                    return INIT_FATAL_CONFIG;
                }
            };

            let socket2_sock = match socket2::Socket::new(
                socket2::Domain::IPV6,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            ) {
                Ok(sock) => sock,
                Err(e) => {
                    let message = format!("Failed to create UDP socket: {e}");
                    error!("{message}");
                    set_last_init_error(&message);
                    return INIT_RETRYABLE_FAILURE;
                }
            };

            if let Err(e) = socket2_sock.set_only_v6(false) {
                let message = format!("Failed to enable dual-stack UDP socket: {e}");
                error!("{message}");
                set_last_init_error(&message);
                return INIT_RETRYABLE_FAILURE;
            }
            if let Err(e) = socket2_sock.bind(&socket2::SockAddr::from(
                std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0),
            )) {
                let message = format!("Failed to bind UDP socket: {e}");
                error!("{message}");
                set_last_init_error(&message);
                return INIT_RETRYABLE_FAILURE;
            }
            let _ = socket2_sock.set_recv_buffer_size(4 * 1024 * 1024);
            let _ = socket2_sock.set_send_buffer_size(4 * 1024 * 1024);

            #[cfg(target_os = "android")]
            unsafe {
                use std::os::unix::io::AsRawFd;
                let fd = socket2_sock.as_raw_fd();
                let val: libc::c_int = 0;

                let _ = libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_MTU_DISCOVER,
                    &val as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&val) as libc::socklen_t,
                );
                let _ = libc::setsockopt(
                    fd,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_MTU_DISCOVER,
                    &val as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&val) as libc::socklen_t,
                );
            }

            let socket = std::net::UdpSocket::from(socket2_sock);

            #[cfg(target_os = "android")]
            let sock_fd = {
                use std::os::unix::io::AsRawFd;
                socket.as_raw_fd()
            };
            #[cfg(not(target_os = "android"))]
            let sock_fd = 0;

            let protected = env
                .call_method(
                    &service,
                    jni::jni_str!("protect"),
                    jni::jni_sig!("(I)Z"),
                    &[JValue::Int(sock_fd as jint)],
                )
                .and_then(jni::JValueOwned::z)
                .unwrap_or(false);

            if !protected {
                let message = "Failed to protect VPN socket!";
                error!("{message}");
                set_last_init_error(message);
                return INIT_RETRYABLE_FAILURE;
            }

            let _ = socket.set_nonblocking(true);

            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let message = format!("Failed to create runtime: {e}");
                    error!("{message}");
                    set_last_init_error(&message);
                    return INIT_RETRYABLE_FAILURE;
                }
            };

            let effective_http3_framing =
                crate::connection::effective_http3_framing(censorship_resistant, http3_framing);

            // Keep a copy of the access token to seed the session's reauth cell;
            // the handshake call below consumes `token`.
            let session_token = token.clone();
            let result = rt.block_on(async {
                connect_and_handshake(
                    socket,
                    token,
                    endpoint,
                    cert_pin_str,
                    censorship_resistant,
                    effective_http3_framing,
                    ech_config_hex,
                    vpn_mtu_opt,
                )
                .await
            });

            match result {
                Ok((connection, config, h3_guard)) => {
                    clear_last_init_error();
                    let session = VpnSession::new(
                        rt,
                        connection,
                        config,
                        effective_http3_framing,
                        session_token,
                        h3_guard,
                    );
                    Box::into_raw(Box::new(session)) as jlong
                }
                Err(e) => {
                    let message = e.to_string();
                    error!("Handshake failed: {message}");
                    set_last_init_error(&message);
                    classify_init_error(&message)
                }
            }
        }));

    result.unwrap_or_else(|_| {
        set_last_init_error("Unexpected panic in native init");
        INIT_RETRYABLE_FAILURE
    })
}

#[allow(improper_ctypes_definitions)]
#[no_mangle]
/// Returns the last error message that occurred during initialization.
///
/// # Panics
/// Panics if the JNI environment fails to create a new string.
pub extern "system" fn Java_com_mavi_vpn_nativelib_NativeLib_getLastInitError<'local>(
    env_unowned: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jni::sys::jstring {
    let mut guard = unsafe { AttachGuard::from_unowned(env_unowned.as_raw()) };
    let env = guard.borrow_env_mut();
    let message = last_init_error()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    env.new_string(message)
        .unwrap_or_else(|_| env.new_string("").unwrap())
        .into_raw()
}

#[allow(improper_ctypes_definitions)]
#[no_mangle]
/// Returns the VPN configuration as a JSON string.
///
/// # Panics
/// Panics if the JNI environment fails to create a new string.
pub extern "system" fn Java_com_mavi_vpn_nativelib_NativeLib_getConfig<'local>(
    env_unowned: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jni::sys::jstring {
    let mut guard = unsafe { AttachGuard::from_unowned(env_unowned.as_raw()) };
    let env = guard.borrow_env_mut();

    if (-3..=0).contains(&handle) {
        return env.new_string("{}").unwrap().into_raw();
    }

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let session = unsafe { &*(handle as *const VpnSession) };
        let json = serde_json::to_string(&session.config).unwrap_or_else(|_| "{}".to_string());
        env.new_string(json)
            .unwrap_or_else(|_| env.new_string("{}").unwrap())
            .into_raw()
    }));

    result.unwrap_or_else(|_| env.new_string("{}").unwrap().into_raw())
}

#[allow(improper_ctypes_definitions)]
#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_nativelib_NativeLib_startLoop<'local>(
    mut _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    tun_fd: jint,
) {
    if (-3..=0).contains(&handle) {
        return;
    }
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let session = unsafe { &mut *(handle as *mut VpnSession) };
        let stop_flag = session.stop_flag.clone();
        let conn = session.connection.clone();
        let config = session.config.clone();
        let http3_framing = session.http3_framing;
        let shutdown_rx = session.shutdown_tx.subscribe();

        // In-band Keycloak reauth: present GUI-refreshed tokens over the live
        // connection so the tunnel survives the original token's expiry.
        let reauth_conn = session.connection.clone();
        let reauth_token = session.current_token.clone();
        let reauth_stop = session.stop_flag.clone();

        session.runtime.block_on(async move {
            let reauth_handle = tokio::spawn(crate::connection::run_reauth_task(
                reauth_conn,
                reauth_token,
                reauth_stop,
            ));
            run_vpn_loop(conn, tun_fd, stop_flag, config, shutdown_rx, http3_framing).await;
            reauth_handle.abort();
        });
    }));
}

#[allow(improper_ctypes_definitions)]
#[no_mangle]
/// Replaces the session's current access token. Called by the Keycloak refresh
/// ticker after a silent renewal so the in-band reauth task can present the fresh
/// token to the server over the live connection (no reconnect).
pub extern "system" fn Java_com_mavi_vpn_nativelib_NativeLib_updateToken<'local>(
    env_unowned: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    token: JString<'local>,
) {
    if (-3..=0).contains(&handle) {
        return;
    }
    let mut guard = unsafe { AttachGuard::from_unowned(env_unowned.as_raw()) };
    let env = guard.borrow_env_mut();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        #[allow(deprecated)]
        let Ok(token_str) = env.get_string(&token) else {
            error!("updateToken: failed to read token from JNI");
            return;
        };
        let token_string: String = token_str.into();
        let session = unsafe { &*(handle as *const VpnSession) };
        if let Ok(mut current) = session.current_token.lock() {
            *current = token_string;
        }
    }));
}

#[allow(improper_ctypes_definitions)]
#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_nativelib_NativeLib_stop<'local>(
    mut _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
) {
    if (-3..=0).contains(&handle) {
        return;
    }
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let session = unsafe { &*(handle as *const VpnSession) };
        session.stop_flag.store(true, Ordering::SeqCst);
        let _ = session.shutdown_tx.send(());
        session.connection.close(0u32.into(), b"user_disconnect");
    }));
}

#[allow(improper_ctypes_definitions)]
#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_nativelib_NativeLib_free<'local>(
    mut _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
) {
    if (-3..=0).contains(&handle) {
        return;
    }
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
        let _ = Box::from_raw(handle as *mut VpnSession);
    }));
}

#[allow(improper_ctypes_definitions)]
#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_nativelib_NativeLib_networkChanged<'local>(
    mut _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
) {
    if (-3..=0).contains(&handle) {
        return;
    }
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let session = unsafe { &*(handle as *const VpnSession) };
        let _ = session
            .connection
            .send_datagram(bytes::Bytes::from_static(&[0]));
    }));
}

#[cfg(test)]
mod tests;
