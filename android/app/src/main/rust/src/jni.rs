use android_logger::Config;
use jni::objects::{JClass, JObject, JString};
use jni::sys::{jint, jlong};
use jni::{AttachGuard, Env, EnvUnowned, JValue};
use log::{error, info};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, Once, OnceLock};

use crate::connection::connect_and_handshake;
use crate::session::VpnSession;
use crate::vpn_loop::run_vpn_loop;

const INIT_RETRYABLE_FAILURE: jlong = 0;
const INIT_FATAL_AUTH: jlong = -1;
const INIT_FATAL_CERT: jlong = -2;
const INIT_FATAL_CONFIG: jlong = -3;
const ANDROID_TOKIO_WORKER_THREADS: usize = 2;

fn android_runtime() -> Result<Arc<tokio::runtime::Runtime>, String> {
    static ANDROID_RUNTIME: OnceLock<Result<Arc<tokio::runtime::Runtime>, String>> =
        OnceLock::new();

    ANDROID_RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .thread_name("mavivpn-android")
                .worker_threads(ANDROID_TOKIO_WORKER_THREADS)
                .enable_all()
                .build()
                .map(Arc::new)
                .map_err(|e| format!("Failed to create runtime: {}", e))
        })
        .clone()
}

fn last_init_error() -> &'static Mutex<String> {
    static LAST_INIT_ERROR: OnceLock<Mutex<String>> = OnceLock::new();
    LAST_INIT_ERROR.get_or_init(|| Mutex::new(String::new()))
}

fn set_last_init_error(message: &str) {
    let mut last = last_init_error().lock().unwrap_or_else(|e| e.into_inner());
    last.clear();
    last.push_str(message);
}

fn clear_last_init_error() {
    let mut last = last_init_error().lock().unwrap_or_else(|e| e.into_inner());
    last.clear();
}

fn classify_init_error(message: &str) -> jlong {
    let msg = message.to_ascii_lowercase();
    if msg.contains("invalid certificate pin")
        || msg.contains("pin mismatch")
        || msg.contains("certificate pin mismatch")
    {
        return INIT_FATAL_CERT;
    }
    if msg.contains("server error: unauthorized")
        || msg.contains("access denied")
        || msg.contains("invalid keycloak token")
        || msg.contains("invalid token")
    {
        return INIT_FATAL_AUTH;
    }
    if msg.contains("endpoint host missing") || msg.contains("invalid address") {
        return INIT_FATAL_CONFIG;
    }
    INIT_RETRYABLE_FAILURE
}

#[allow(improper_ctypes_definitions)]
#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_native_1lib_NativeLib_init<'local>(
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
    enable_logging: jni::sys::jboolean,
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
                        .with_max_level(log::LevelFilter::Trace),
                );
                let _ = rustls::crypto::ring::default_provider().install_default();
            });

            if enable_logging as u8 != 0 {
                log::set_max_level(log::LevelFilter::Trace);
            } else {
                log::set_max_level(log::LevelFilter::Off);
            }

            info!("JNI init called. CR Mode: {}", censorship_resistant);

            let get_string = |env: &mut Env, jstr: &JString| -> Option<String> {
                #[allow(deprecated)]
                match env.get_string(jstr) {
                    Ok(s) => Some(s.into()),
                    Err(e) => {
                        error!("Failed to get string from JNI: {}", e);
                        None
                    }
                }
            };

            let token = match get_string(env, &token) {
                Some(s) => s,
                None => {
                    set_last_init_error("Failed to read VPN token from JNI");
                    return INIT_FATAL_CONFIG;
                }
            };
            let endpoint = match get_string(env, &endpoint) {
                Some(s) => s,
                None => {
                    set_last_init_error("Failed to read VPN endpoint from JNI");
                    return INIT_FATAL_CONFIG;
                }
            };
            let cert_pin_str = match get_string(env, &cert_pin) {
                Some(s) => s,
                None => {
                    set_last_init_error("Failed to read certificate pin from JNI");
                    return INIT_FATAL_CONFIG;
                }
            };

            // Optional: hex-encoded ECHConfigList. Empty string → no ECH override.
            let ech_config_hex: Option<String> =
                get_string(env, &ech_config).filter(|s| !s.is_empty());

            if cert_pin_str.is_empty() {
                let message = "Certificate PIN is empty. Connection aborted.";
                error!("{}", message);
                set_last_init_error(message);
                return INIT_FATAL_CERT;
            }

            let socket2_sock = match socket2::Socket::new(
                socket2::Domain::IPV6,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            ) {
                Ok(sock) => sock,
                Err(e) => {
                    let message = format!("Failed to create UDP socket: {}", e);
                    error!("{}", message);
                    set_last_init_error(&message);
                    return INIT_RETRYABLE_FAILURE;
                }
            };

            if let Err(e) = socket2_sock.set_only_v6(false) {
                let message = format!("Failed to enable dual-stack UDP socket: {}", e);
                error!("{}", message);
                set_last_init_error(&message);
                return INIT_RETRYABLE_FAILURE;
            }
            if let Err(e) = socket2_sock.bind(&socket2::SockAddr::from(
                std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0),
            )) {
                let message = format!("Failed to bind UDP socket: {}", e);
                error!("{}", message);
                set_last_init_error(&message);
                return INIT_RETRYABLE_FAILURE;
            }
            let _ = socket2_sock.set_recv_buffer_size(8 * 1024 * 1024);
            let _ = socket2_sock.set_send_buffer_size(8 * 1024 * 1024);

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
                .and_then(|val| val.z())
                .unwrap_or(false);

            if !protected {
                let message = "Failed to protect VPN socket!";
                error!("{}", message);
                set_last_init_error(message);
                return INIT_RETRYABLE_FAILURE;
            }

            let _ = socket.set_nonblocking(true);

            let rt = match android_runtime() {
                Ok(rt) => rt,
                Err(message) => {
                    error!("{}", message);
                    set_last_init_error(&message);
                    return INIT_RETRYABLE_FAILURE;
                }
            };

            let vpn_mtu_opt = if vpn_mtu > 0 {
                Some(vpn_mtu as u16)
            } else {
                None
            };

            let result = rt.block_on(async {
                connect_and_handshake(
                    socket,
                    token,
                    endpoint,
                    cert_pin_str,
                    censorship_resistant,
                    http3_framing,
                    ech_config_hex,
                    vpn_mtu_opt,
                )
                .await
            });

            match result {
                Ok((connection, config, h3_guard)) => {
                    clear_last_init_error();
                    let session = VpnSession::new(rt, connection, config, http3_framing, h3_guard);
                    Box::into_raw(Box::new(session)) as jlong
                }
                Err(e) => {
                    let message = e.to_string();
                    error!("Handshake failed: {}", message);
                    set_last_init_error(&message);
                    classify_init_error(&message)
                }
            }
        }));

    match result {
        Ok(handle) => handle,
        Err(_) => {
            set_last_init_error("Unexpected panic in native init");
            INIT_RETRYABLE_FAILURE
        }
    }
}

#[allow(improper_ctypes_definitions)]
#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_native_1lib_NativeLib_getLastInitError<'local>(
    env_unowned: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jni::sys::jstring {
    let mut guard = unsafe { AttachGuard::from_unowned(env_unowned.as_raw()) };
    let env = guard.borrow_env_mut();
    let message = last_init_error()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    env.new_string(message)
        .unwrap_or_else(|_| env.new_string("").unwrap())
        .into_raw()
}

#[allow(improper_ctypes_definitions)]
#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_native_1lib_NativeLib_getConfig<'local>(
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

    match result {
        Ok(s) => s,
        Err(_) => env.new_string("{}").unwrap().into_raw(),
    }
}

#[allow(improper_ctypes_definitions)]
#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_native_1lib_NativeLib_startLoop<'local>(
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
        session.runtime.block_on(async {
            run_vpn_loop(conn, tun_fd, stop_flag, config, shutdown_rx, http3_framing).await;
        });
    }));
}

#[allow(improper_ctypes_definitions)]
#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_native_1lib_NativeLib_stop<'local>(
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
pub extern "system" fn Java_com_mavi_vpn_native_1lib_NativeLib_free<'local>(
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
pub extern "system" fn Java_com_mavi_vpn_native_1lib_NativeLib_networkChanged<'local>(
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
mod tests {
    use super::*;

    #[test]
    fn classify_cert_pin_mismatch() {
        assert_eq!(
            classify_init_error("invalid certificate pin"),
            INIT_FATAL_CERT
        );
        assert_eq!(classify_init_error("pin mismatch"), INIT_FATAL_CERT);
        assert_eq!(
            classify_init_error("certificate pin mismatch"),
            INIT_FATAL_CERT
        );
    }

    #[test]
    fn classify_auth_errors() {
        assert_eq!(
            classify_init_error("server error: Unauthorized"),
            INIT_FATAL_AUTH
        );
        assert_eq!(classify_init_error("Access Denied"), INIT_FATAL_AUTH);
        assert_eq!(
            classify_init_error("Invalid Keycloak Token"),
            INIT_FATAL_AUTH
        );
        assert_eq!(classify_init_error("Invalid Token"), INIT_FATAL_AUTH);
    }

    #[test]
    fn classify_config_errors() {
        assert_eq!(
            classify_init_error("endpoint host missing"),
            INIT_FATAL_CONFIG
        );
        assert_eq!(classify_init_error("invalid address"), INIT_FATAL_CONFIG);
    }

    #[test]
    fn classify_unknown_returns_retryable() {
        assert_eq!(
            classify_init_error("connection timed out"),
            INIT_RETRYABLE_FAILURE
        );
        assert_eq!(
            classify_init_error("network unreachable"),
            INIT_RETRYABLE_FAILURE
        );
    }

    #[test]
    fn classify_case_insensitive() {
        assert_eq!(
            classify_init_error("INVALID CERTIFICATE PIN"),
            INIT_FATAL_CERT
        );
        assert_eq!(classify_init_error("ACCESS DENIED"), INIT_FATAL_AUTH);
    }

    #[test]
    fn retryable_failure_is_zero() {
        assert_eq!(INIT_RETRYABLE_FAILURE, 0);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn fatal_errors_are_negative() {
        assert!(INIT_FATAL_AUTH < 0);
        assert!(INIT_FATAL_CERT < 0);
        assert!(INIT_FATAL_CONFIG < 0);
    }
}
