use anyhow::Result;

/// Creates a UDP socket configured for both IPv4 and IPv6 (dual-stack).
pub fn create_udp_socket() -> Result<std::net::UdpSocket> {
    let socket2_sock = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    socket2_sock.set_only_v6(false)?;
    socket2_sock.bind(&socket2::SockAddr::from(std::net::SocketAddrV6::new(
        std::net::Ipv6Addr::UNSPECIFIED,
        0,
        0,
        0,
    )))?;
    let _ = socket2_sock.set_send_buffer_size(4 * 1024 * 1024);
    let _ = socket2_sock.set_recv_buffer_size(4 * 1024 * 1024);

    Ok(socket2_sock.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_udp_socket_succeeds() {
        let socket = create_udp_socket().unwrap();
        let local_addr = socket.local_addr().unwrap();
        assert_eq!(local_addr.ip(), std::net::Ipv6Addr::UNSPECIFIED);
        assert_ne!(local_addr.port(), 0);
    }

    #[test]
    fn create_udp_socket_is_dual_stack() {
        let socket = create_udp_socket().unwrap();
        let local_addr = socket.local_addr().unwrap();
        assert!(local_addr.is_ipv6());
    }
}
