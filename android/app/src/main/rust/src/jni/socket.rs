use anyhow::{Context, Result};
use jni::objects::JObject;
use jni::sys::jint;
use jni::{Env, JValue};

pub(super) fn protect_socket(
    env: &mut Env<'_>,
    service: &JObject<'_>,
    _socket: &tokio::net::TcpSocket,
) -> Result<()> {
    #[cfg(target_os = "android")]
    let socket_fd = {
        use std::os::unix::io::AsRawFd;
        _socket.as_raw_fd()
    };
    #[cfg(not(target_os = "android"))]
    let socket_fd = 0;

    protect_fd(env, service, socket_fd)
}

pub(super) fn create_udp_socket(
    env: &mut Env<'_>,
    service: &JObject<'_>,
) -> Result<std::net::UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .context("Failed to create UDP socket")?;
    socket
        .set_only_v6(false)
        .context("Failed to enable dual-stack UDP socket")?;
    socket
        .bind(&socket2::SockAddr::from(std::net::SocketAddrV6::new(
            std::net::Ipv6Addr::UNSPECIFIED,
            0,
            0,
            0,
        )))
        .context("Failed to bind UDP socket")?;
    let _ = socket.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = socket.set_send_buffer_size(4 * 1024 * 1024);

    #[cfg(target_os = "android")]
    unsafe {
        use std::os::unix::io::AsRawFd;
        let fd = socket.as_raw_fd();
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

    let socket = std::net::UdpSocket::from(socket);
    #[cfg(target_os = "android")]
    let socket_fd = {
        use std::os::unix::io::AsRawFd;
        socket.as_raw_fd()
    };
    #[cfg(not(target_os = "android"))]
    let socket_fd = 0;
    protect_fd(env, service, socket_fd)?;
    socket
        .set_nonblocking(true)
        .context("Failed to make UDP socket nonblocking")?;
    Ok(socket)
}

fn protect_fd(env: &mut Env<'_>, service: &JObject<'_>, socket_fd: i32) -> Result<()> {
    let protected = env
        .call_method(
            service,
            jni::jni_str!("protect"),
            jni::jni_sig!("(I)Z"),
            &[JValue::Int(socket_fd as jint)],
        )
        .and_then(jni::JValueOwned::z)
        .context("Failed to call VpnService.protect")?;
    anyhow::ensure!(protected, "Failed to protect VPN socket");
    Ok(())
}
