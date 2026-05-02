use anyhow::Result;
use quinn::{Endpoint, ServerConfig, TransportConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;

use crate::config::Config;

#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

/// Fixed overhead budget reserved on top of the inner TUN MTU to account for
/// QUIC short-header framing + AEAD tag + connection-ID bytes. The outer QUIC
/// payload MTU is derived as `config.mtu + QUIC_OVERHEAD_BYTES`, so the inner
/// MTU remains the single knob operators turn.
const QUIC_OVERHEAD_BYTES: u16 = 80;

pub fn create_quic_endpoint(
    config: &Config,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Endpoint> {
    let mut server_crypto = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_no_client_auth()
    .with_single_cert(certs, key)?;

    server_crypto.alpn_protocols = if config.censorship_resistant {
        vec![b"h3".to_vec()]
    } else {
        vec![b"mavivpn".to_vec(), b"h3".to_vec()]
    };

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)?,
    ));
    let transport_config = Arc::get_mut(&mut server_config.transport)
        .ok_or_else(|| anyhow::anyhow!("Failed to access transport config"))?;

    setup_transport_config(transport_config, config.mtu + QUIC_OVERHEAD_BYTES);

    let socket = std::net::UdpSocket::bind(config.bind_addr)?;
    let socket2_sock = socket2::Socket::from(socket);
    let _ = socket2_sock.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = socket2_sock.set_send_buffer_size(4 * 1024 * 1024);

    #[cfg(target_os = "linux")]
    {
        let fd = socket2_sock.as_raw_fd();
        unsafe {
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

fn setup_transport_config(transport_config: &mut TransportConfig, quic_payload_mtu: u16) {
    let idle_timeout = quinn::IdleTimeout::try_from(std::time::Duration::from_secs(60))
        .expect("60s fits in a QUIC IdleTimeout");
    transport_config.max_idle_timeout(Some(idle_timeout));
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
    transport_config.datagram_receive_buffer_size(Some(4 * 1024 * 1024));
    transport_config.datagram_send_buffer_size(4 * 1024 * 1024);
    transport_config.receive_window(quinn::VarInt::from(4u32 * 1024 * 1024));
    transport_config.stream_receive_window(quinn::VarInt::from(1024u32 * 1024));
    transport_config.send_window(4 * 1024 * 1024);
    transport_config
        .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
    transport_config.mtu_discovery_config(None);
    transport_config.initial_mtu(quic_payload_mtu);
    transport_config.min_mtu(quic_payload_mtu);
    transport_config.enable_segmentation_offload(true);
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn test_config() -> Config {
        Config::parse_from(["mavi-vpn", "--auth-token", "test"])
    }

    fn generate_test_certs() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        use rcgen::generate_simple_self_signed;
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};

        let cert = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.signing_key.serialize_pem();

        let certs = CertificateDer::pem_reader_iter(&mut cert_pem.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        let keys = PrivateKeyDer::from_pem_slice(key_pem.as_bytes())
            .unwrap();
        (certs, keys)
    }

    #[test]
    fn setup_transport_config_sets_mtu() {
        let mut tc = TransportConfig::default();
        setup_transport_config(&mut tc, 1360);
    }

    #[test]
    fn setup_transport_config_with_different_mtu() {
        let mut tc = TransportConfig::default();
        setup_transport_config(&mut tc, 1280);
    }

    #[test]
    fn setup_transport_config_minimum_mtu() {
        let mut tc = TransportConfig::default();
        setup_transport_config(&mut tc, 1200);
    }

    #[tokio::test]
    async fn create_quic_endpoint_standard_mode() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut config = test_config();
        config.bind_addr = "127.0.0.1:0".parse().unwrap();
        let (certs, key) = generate_test_certs();
        let result = create_quic_endpoint(&config, certs, key);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn create_quic_endpoint_censorship_mode() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut config = test_config();
        config.bind_addr = "127.0.0.1:0".parse().unwrap();
        config.censorship_resistant = true;
        let (certs, key) = generate_test_certs();
        let result = create_quic_endpoint(&config, certs, key);
        assert!(result.is_ok());
    }

    #[test]
    fn quic_overhead_constant() {
        assert_eq!(QUIC_OVERHEAD_BYTES, 80);
    }

    #[tokio::test]
    async fn endpoint_bind_address() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let mut config = test_config();
        config.bind_addr = "127.0.0.1:0".parse().unwrap();
        let (certs, key) = generate_test_certs();
        let endpoint = create_quic_endpoint(&config, certs, key).unwrap();
        assert!(endpoint.local_addr().is_ok());
    }
}
