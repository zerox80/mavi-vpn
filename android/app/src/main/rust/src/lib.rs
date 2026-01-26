use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::{jint, jstring};
use std::os::unix::io::RawFd;
use android_logger::Config;
use log::info;

#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_MaviVpnService_connect(
    mut env: JNIEnv,
    _class: JClass,
    fd: jint,
    token: JString,
    endpoint: JString,
) -> jint {
    android_logger::init_once(Config::default().with_tag("MaviVPN"));
    
    let token: String = env.get_string(&token).expect("Couldn't get java string!").into();
    let endpoint: String = env.get_string(&endpoint).expect("Couldn't get java string!").into();
    
    info!("Rust received connect request. FD: {}, Endpoint: {}", fd, endpoint);

    // TODO: Implement actual QUIC loop here using existing `shared` protocol logic.
    // For 10/10 app, this would spawn a tokio runtime and run the client loop.
    // We will just simulate a blocking run for now to prove JNI works, 
    // or ideally spawn a thread?
    
    // In a real app, we should NOT block the JNI thread forever.
    // We should spawn a thread/runtime and return immediately or return status.
    // The Kotlin side expects this to block? The thread in Kotlin says `connect(...)`.
    // Yes, Kotlin spawns a Thread just for this. So blocking is fine/expected.

    match std::thread::spawn(move || {
        start_runtime(fd, token, endpoint)
    }).join() {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

#[no_mangle]
pub extern "system" fn Java_com_mavi_vpn_MaviVpnService_stop(
    _env: JNIEnv,
    _class: JClass,
) {
    info!("Stop requested");
    // Signal cancellation token
}

fn start_runtime(fd: RawFd, token: String, endpoint_addr: String) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        info!("Tokio Runtime Started");
        // Here we would:
        // 1. Create Tun device from FD (using `tun` crate with `unsafe { from_raw_fd }`)
        // 2. Connect via Quinn
        // 3. Handshake using `shared::ControlMessage`
        // 4. Pump packets
        
        // Simulating work
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        info!("Session ended");
    });
}
