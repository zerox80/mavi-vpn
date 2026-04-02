use anyhow::Result;
use quinn::{Endpoint, ServerConfig, TransportConfig};
use std::sync::Arc;
use crate::config::Config;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

const QUIC_PAYLOAD_MTU: u16 = 1360;

pub fn create_quic_endpoint(
    config: &Config,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Endpoint> {
    let mut server_crypto = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into()
    )
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_no_client_auth()
    .with_single_cert(certs, key)?;
    
    server_crypto.alpn_protocols = if config.censorship_resistant {
        vec![b"h3".to_vec()]
    } else {
        vec![b"h3".to_vec(), b"mavivpn".to_vec()]
    };
    
    let mut server_config = ServerConfig::with_crypto(Arc::new(quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?));
    let transport_config = Arc::get_mut(&mut server_config.transport)
        .ok_or_else(|| anyhow::anyhow!("Failed to access transport config"))?;
    
    setup_transport_config(transport_config);
    
    let socket = std::net::UdpSocket::bind(config.bind_addr)?;
    let socket2_sock = socket2::Socket::from(socket);
    let _ = socket2_sock.set_recv_buffer_size(4 * 1024 * 1024); 
    let _ = socket2_sock.set_send_buffer_size(4 * 1024 * 1024); 
    
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = socket2_sock.as_raw_fd();
        unsafe {
            let val: libc::c_int = 0; 
            let _ = libc::setsockopt(fd, libc::IPPROTO_IP, libc::IP_MTU_DISCOVER, &val as *const _ as *const libc::c_void, std::mem::size_of_val(&val) as libc::socklen_t);
            let _ = libc::setsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER, &val as *const _ as *const libc::c_void, std::mem::size_of_val(&val) as libc::socklen_t);
        }
    }

    let socket = std::net::UdpSocket::from(socket2_sock);
    let endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )?;

    Ok(endpoint)
}

fn setup_transport_config(transport_config: &mut TransportConfig) {
    // We disable the max_idle_timeout so mobile clients in Doze mode don't get forcefully disconnected
    transport_config.max_idle_timeout(None);
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
    transport_config.datagram_receive_buffer_size(Some(4 * 1024 * 1024)); 
    transport_config.datagram_send_buffer_size(4 * 1024 * 1024); 
    transport_config.receive_window(quinn::VarInt::from(4u32 * 1024 * 1024)); 
    transport_config.stream_receive_window(quinn::VarInt::from(1024u32 * 1024)); 
    transport_config.send_window(4 * 1024 * 1024); 
    transport_config.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    transport_config.mtu_discovery_config(None); 
    transport_config.initial_mtu(QUIC_PAYLOAD_MTU); 
    transport_config.min_mtu(QUIC_PAYLOAD_MTU);
    transport_config.enable_segmentation_offload(true);
}
