use jni::objects::{JClass, JString, JObject};
use jni::{JValue, Env, AttachGuard, EnvUnowned};
use jni::sys::{jint, jlong};
use log::{info, error, warn};
use std::sync::Arc;
use shared::ControlMessage;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Once;
use android_logger::Config;

mod crypto;
mod connection;
mod vpn_loop;

use crate::connection::connect_and_handshake;
use crate::vpn_loop::run_vpn_loop;

struct VpnSession {
    runtime: tokio::runtime::Runtime,
    connection: quinn::Connection,
    config: ControlMessage,
    stop_flag: Arc<AtomicBool>,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
}

#[allow(improper_ctypes_definitions)]
#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_MaviVpnService_init<'local>(
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
    
    #[allow(deprecated)]
    let get_string = |env: &mut Env, jstr: &JString| -> Option<String> {
         match env.get_string(jstr) {
             Ok(s) => Some(s.into()),
             Err(e) => {
                 error!("Failed to get string from JNI: {}", e);
                 None
             }
         }
    };

    let token = match get_string(&mut env, &token) { Some(s) => s, None => { error!("Token is null/invalid"); return 0; } };
    let endpoint = match get_string(&mut env, &endpoint) { Some(s) => s, None => { error!("Endpoint is null/invalid"); return 0; } };
    let cert_pin_str = match get_string(&mut env, &cert_pin) { Some(s) => s, None => { error!("CertPin is null/invalid"); return 0; } };

    if cert_pin_str.is_empty() {
        error!("Certificate PIN is empty. Connection aborted.");
        return 0;
    }

    use std::net::ToSocketAddrs;
    let addr = match endpoint.to_socket_addrs() {
        Ok(mut addrs) => addrs.next(),
        Err(e) => {
            error!("Failed to resolve endpoint {}: {}", endpoint, e);
            return 0;
        }
    };
    
    let target_addr = match addr {
        Some(a) => a,
        None => {
            error!("No address found for endpoint {}", endpoint);
            return 0;
        }
    };

    let bind_addr = if target_addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = match std::net::UdpSocket::bind(bind_addr) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to bind UDP socket to {}: {}", bind_addr, e);
            return 0;
        }
    };
    
    let socket2_sock = socket2::Socket::from(socket);
    let buffer_candidates = [4 * 1024 * 1024, 2 * 1024 * 1024, 1024 * 1024];
    
    for size in buffer_candidates {
        if let Err(e) = socket2_sock.set_recv_buffer_size(size) {
                warn!("Could not set receive buffer to {}: {}", size, e);
        } else {
                info!("Socket receive buffer: {}", size);
                break;
        }
    }

    #[cfg(target_os = "android")]
    unsafe {
        use std::os::unix::io::AsRawFd;
        let fd = socket2_sock.as_raw_fd();
        let val: libc::c_int = 0; 

        if target_addr.is_ipv4() {
            let _ = libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of_val(&val) as libc::socklen_t,
            );
        } else {
            let _ = libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                23, 
                &val as *const _ as *const libc::c_void,
                std::mem::size_of_val(&val) as libc::socklen_t,
            );
        }
        info!("UDP Fragmentation enabled (PMTUDISC_DONT) for Android socket");
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
    
    match socket.set_nonblocking(true) {
        Ok(_) => {},
        Err(e) => {
            error!("Failed to set non-blocking: {}", e);
            return 0;
        }
    }

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
            info!("Handshake successful. IP: {:?}", config);
            let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
            let session = VpnSession {
                runtime: rt,
                connection,
                config,
                stop_flag: Arc::new(AtomicBool::new(false)),
                shutdown_tx,
            };
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
        Err(e) => {
            error!("Rust Panic caught in init: {:?}", e);
            0
        }
    }
}

#[allow(improper_ctypes_definitions)]
#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_MaviVpnService_getConfig<'local>(
    env_unowned: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jni::sys::jstring {
    let mut guard = unsafe { AttachGuard::from_unowned(env_unowned.as_raw()) };
    let env = guard.borrow_env_mut();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if handle == 0 { return env.new_string("{}").unwrap().into_raw(); }
        
        let session = unsafe { 
            let ptr = handle as *mut VpnSession;
            if ptr.is_null() { return env.new_string("{}").unwrap().into_raw(); }
            &*ptr 
        };
        
        let json = serde_json::to_string(&session.config).unwrap_or_else(|_| "{}".to_string());
        env.new_string(json).unwrap_or_else(|_| env.new_string("{}").unwrap()).into_raw()
    }));
    
    match result {
        Ok(s) => s,
        Err(_) => {
            error!("Panic in getConfig");
            env.new_string("{}").unwrap().into_raw()
        }
    }
}

#[allow(improper_ctypes_definitions)]
#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_MaviVpnService_startLoop<'local>(
    mut _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    tun_fd: jint,
) {
    if handle == 0 { return; }
    
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let session = unsafe { &mut *(handle as *mut VpnSession) };
        info!("Starting VPN Loop with TUN FD: {}", tun_fd);
        let stop_flag = session.stop_flag.clone();
        let conn = session.connection.clone();
        let config = session.config.clone();
        let shutdown_rx = session.shutdown_tx.subscribe();
        session.runtime.block_on(async {
            run_vpn_loop(conn, tun_fd, stop_flag, config, shutdown_rx).await;
        });
        info!("VPN Loop terminated.");
    }));
}

#[allow(improper_ctypes_definitions)]
#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_MaviVpnService_stop<'local>(
    mut _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
) {
    if handle == 0 { return; }
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let session = unsafe { &*(handle as *mut VpnSession) };
        info!("Stop requested for session");
        session.stop_flag.store(true, Ordering::SeqCst);
        let _ = session.shutdown_tx.send(());
        session.connection.close(0u32.into(), b"user_disconnect");
    }));
}

#[allow(improper_ctypes_definitions)]
#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_MaviVpnService_free<'local>(
    mut _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
) {
    if handle == 0 { return; }
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        info!("Freeing VPN Session memory");
        unsafe {
            let _ = Box::from_raw(handle as *mut VpnSession);
        }
    }));
}

#[allow(improper_ctypes_definitions)]
#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_MaviVpnService_networkChanged<'local>(
    mut _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
) {
    if handle == 0 { return; }
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let session = unsafe { &*(handle as *mut VpnSession) };
        info!("Network Event: Triggering Rebind/Migration Ping");
        let conn = session.connection.clone();
        session.runtime.spawn(async move {
            info!("Starting migration burst (5 packets)...");
            for i in 0..5 {
                info!("Migration datagram {}/5 sent", i+1);
                let _ = conn.send_datagram(bytes::Bytes::from_static(&[0]));
                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            }
            info!("Migration burst completed.");
        });
    }));
}
