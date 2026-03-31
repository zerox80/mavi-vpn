use jni::objects::{JClass, JString, JObject};
use jni::{JValue, Env, AttachGuard, EnvUnowned};
use jni::sys::{jint, jlong};
use log::{info, error};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::Once;
use android_logger::Config;

use crate::session::VpnSession;
use crate::connection::connect_and_handshake;
use crate::vpn_loop::run_vpn_loop;

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
) -> jlong {
    let mut guard = unsafe { AttachGuard::from_unowned(env_unowned.as_raw()) };
    let mut env = guard.borrow_env_mut();
    
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        static LOGGER_INIT: Once = Once::new();
        LOGGER_INIT.call_once(|| {
            android_logger::init_once(
                Config::default()
                    .with_tag("MaviVPN")
                    .with_max_level(log::LevelFilter::Info)
            );
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    
    info!("JNI init called. CR Mode: {}", censorship_resistant);
    
    let get_string = |env: &mut Env, jstr: &JString| -> Option<String> {
         match env.get_string(jstr) {
             Ok(s) => Some(s.into()),
             Err(e) => {
                 error!("Failed to get string from JNI: {}", e);
                 None
             }
         }
    };

    let token = match get_string(&mut env, &token) { Some(s) => s, None => { return 0; } };
    let endpoint = match get_string(&mut env, &endpoint) { Some(s) => s, None => { return 0; } };
    let cert_pin_str = match get_string(&mut env, &cert_pin) { Some(s) => s, None => { return 0; } };

    if cert_pin_str.is_empty() {
        error!("Certificate PIN is empty. Connection aborted.");
        return 0;
    }

    let socket2_sock = match socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    ) {
        Ok(sock) => sock,
        Err(e) => {
            error!("Failed to bind UDP socket: {}", e);
            return 0;
        }
    };

    if let Err(e) = socket2_sock.set_only_v6(false) {
        error!("Failed to enable dual-stack UDP socket: {}", e);
        return 0;
    }
    if let Err(e) = socket2_sock.bind(&socket2::SockAddr::from(std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0))) {
        error!("Failed to bind UDP socket: {}", e);
        return 0;
    }
    let _ = socket2_sock.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = socket2_sock.set_send_buffer_size(4 * 1024 * 1024);

    #[cfg(target_os = "android")]
    unsafe {
        use std::os::unix::io::AsRawFd;
        let fd = socket2_sock.as_raw_fd();
        let val: libc::c_int = 0; 

        let _ = libc::setsockopt(fd, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER, &val as *const _ as *const libc::c_void, std::mem::size_of_val(&val) as libc::socklen_t);
        let _ = libc::setsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER, &val as *const _ as *const libc::c_void, std::mem::size_of_val(&val) as libc::socklen_t);
    }

    let socket = std::net::UdpSocket::from(socket2_sock);

    #[cfg(target_os = "android")]
    let sock_fd = { use std::os::unix::io::AsRawFd; socket.as_raw_fd() };
    #[cfg(not(target_os = "android"))]
    let sock_fd = 0; 
    
    let protected = env.call_method(
        &service, 
        jni::jni_str!("protect"), 
        jni::jni_sig!("(I)Z"), 
        &[JValue::Int(sock_fd as jint)]
    ).and_then(|val| val.z()).unwrap_or(false);
    
    if !protected {
        error!("Failed to protect VPN socket!");
        return 0;
    }
    
    let _ = socket.set_nonblocking(true);

    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            error!("Failed to create runtime: {}", e);
            return 0;
        }
    };

    let result = rt.block_on(async {
        connect_and_handshake(socket, token, endpoint, cert_pin_str, censorship_resistant).await
    });

    match result {
        Ok((connection, config)) => {
            let session = VpnSession::new(rt, connection, config);
            Box::into_raw(Box::new(session)) as jlong
        },
        Err(e) => {
            error!("Handshake failed: {}", e);
            0
        }
    }
    }));

    match result {
        Ok(handle) => handle,
        Err(_) => 0
    }
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
    
    if handle == 0 { return env.new_string("{}").unwrap().into_raw(); }
    
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let session = unsafe { &*(handle as *const VpnSession) };
        let json = serde_json::to_string(&session.config).unwrap_or_else(|_| "{}".to_string());
        env.new_string(json).unwrap_or_else(|_| env.new_string("{}").unwrap()).into_raw()
    }));
    
    match result {
        Ok(s) => s,
        Err(_) => env.new_string("{}").unwrap().into_raw()
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
    if handle == 0 { return; }
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let session = unsafe { &mut *(handle as *mut VpnSession) };
        let stop_flag = session.stop_flag.clone();
        let conn = session.connection.clone();
        let config = session.config.clone();
        let shutdown_rx = session.shutdown_tx.subscribe();
        session.runtime.block_on(async {
            run_vpn_loop(conn, tun_fd, stop_flag, config, shutdown_rx).await;
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
    if handle == 0 { return; }
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
    if handle == 0 { return; }
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        unsafe { let _ = Box::from_raw(handle as *mut VpnSession); }
    }));
}

#[allow(improper_ctypes_definitions)]
#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_native_1lib_NativeLib_networkChanged<'local>(
    mut _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
) {
    if handle == 0 { return; }
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let session = unsafe { &*(handle as *const VpnSession) };
        let conn = session.connection.clone();
        session.runtime.spawn(async move {
            for _ in 0..5 {
                let _ = conn.send_datagram(bytes::Bytes::from_static(&[0]));
                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            }
        });
    }));
}
