use anyhow::Result;

/// Creates a dual-stack UDP socket for QUIC transport.
pub(super) fn create_udp_socket() -> Result<std::net::UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    socket.set_only_v6(false)?;
    socket.bind(&socket2::SockAddr::from(std::net::SocketAddrV6::new(
        std::net::Ipv6Addr::UNSPECIFIED,
        0,
        0,
        0,
    )))?;

    // Large socket buffers for high-throughput stability (try 4MB, fall back gracefully)
    for size in [4 * 1024 * 1024, 2 * 1024 * 1024, 1024 * 1024] {
        if socket.set_recv_buffer_size(size).is_ok() {
            let _ = socket.set_send_buffer_size(size); // Also set the send buffer
            break;
        }
    }

    // Disable PMTU discovery on the UDP socket to let QUIC handle it
    // (prevents the kernel from dropping packets that exceed path MTU)
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let fd = socket.as_raw_fd();
        let val: libc::c_int = libc::IP_PMTUDISC_DONT;
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of_val(&val) as libc::socklen_t,
            );
        }
    }

    Ok(socket.into())
}
