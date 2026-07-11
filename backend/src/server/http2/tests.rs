use super::*;
use clap::Parser;
use h2::{RecvStream, SendStream};
use http::Version;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::ServerName;
use shared::masque::{self, CAPSULE_DATAGRAM, CAPSULE_MAVI_CONFIG};
use std::net::{Ipv4Addr, SocketAddr};
use tokio_rustls::TlsConnector;

const TEST_TOKEN: &str = "http2-e2e-token";

fn connect_ip_request(path: &str) -> Request<()> {
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .version(Version::HTTP_2)
        .uri(path)
        .header("capsule-protocol", "?1")
        .body(())
        .unwrap();
    request
        .extensions_mut()
        .insert(Protocol::from_static(CONNECT_IP_PROTOCOL));
    request
}

#[test]
fn connect_ip_request_requires_capsules_and_supported_path() {
    let mut request = connect_ip_request(CONNECT_IP_PATH);
    assert!(is_connect_ip_request(&request));

    request.headers_mut().remove("capsule-protocol");
    assert!(!is_connect_ip_request(&request));
    assert!(!is_connect_ip_request(&connect_ip_request("/unsupported")));
}

#[test]
fn non_connect_ip_request_is_not_recognized() {
    assert!(!is_connect_ip_request(&Request::new(())));
}

fn generate_test_certs() -> (
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
    CertificateDer<'static>,
) {
    let generated = generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_pem = generated.cert.pem();
    let key_pem = generated.signing_key.serialize_pem();
    let certs = CertificateDer::pem_reader_iter(&mut cert_pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();
    let trusted_cert = certs[0].clone();
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
    (certs, key, trusted_cert)
}

fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr) -> Bytes {
    let mut packet = vec![0_u8; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(20_u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    Bytes::from(packet)
}

async fn connect_client(
    addr: SocketAddr,
    trusted_cert: CertificateDer<'static>,
) -> (h2::client::SendRequest<Bytes>, tokio::task::JoinHandle<()>) {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(trusted_cert).unwrap();
    let mut tls_config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h2".to_vec()];

    let tcp = TcpStream::connect(addr).await.unwrap();
    let tls = TlsConnector::from(Arc::new(tls_config))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));

    let (sender, connection) = h2::client::handshake(tls).await.unwrap();
    let driver = tokio::spawn(async move {
        connection.await.unwrap();
    });
    (sender, driver)
}

async fn wait_for_extended_connect(sender: &mut h2::client::SendRequest<Bytes>) {
    sender.clone().ready().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !sender.is_extended_connect_protocol_enabled() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

async fn send_capsule(stream: &mut SendStream<Bytes>, capsule: Bytes) {
    stream.reserve_capacity(capsule.len());
    while stream.capacity() < capsule.len() {
        std::future::poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .unwrap()
            .unwrap();
    }
    stream.send_data(capsule, false).unwrap();
}

async fn read_capsule(stream: &mut RecvStream, buffer: &mut Vec<u8>, wanted: u64) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            while let Some((kind, payload, consumed)) = masque::read_capsule(buffer) {
                let payload = payload.to_vec();
                buffer.drain(..consumed);
                if kind == wanted {
                    return payload;
                }
            }
            buffer.extend_from_slice(&stream.data().await.unwrap().unwrap());
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn tls_h2_connect_ip_moves_packets_in_both_directions() {
    let (certs, key, trusted_cert) = generate_test_certs();
    let state = Arc::new(AppState::new("10.8.0.0/24").unwrap());
    let config = Config::parse_from(["mavi-vpn", "--auth-token", TEST_TOKEN]);
    let (tx_tun, mut rx_tun) = mpsc::channel(8);
    let listener = bind_http2_listener(
        "127.0.0.1:0".parse().unwrap(),
        certs,
        key,
        state.clone(),
        config,
        tx_tun,
        None,
        false,
    )
    .await
    .unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(listener.run());

    let (mut sender, driver) = connect_client(addr, trusted_cert).await;
    wait_for_extended_connect(&mut sender).await;
    let mut request = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://localhost{CONNECT_IP_PATH}"))
        .header("authorization", format!("Bearer {TEST_TOKEN}"))
        .header("capsule-protocol", "?1")
        .body(())
        .unwrap();
    request
        .extensions_mut()
        .insert(h2::ext::Protocol::from_static(CONNECT_IP_PROTOCOL));
    let (response, mut request_body) = sender.send_request(request, false).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["capsule-protocol"], "?1");

    let mut response_body = response.into_body();
    let mut response_buffer = Vec::new();
    let config_payload = read_capsule(
        &mut response_body,
        &mut response_buffer,
        CAPSULE_MAVI_CONFIG,
    )
    .await;
    let (config_message, _) = bincode::serde::decode_from_slice::<shared::ControlMessage, _>(
        &config_payload,
        bincode::config::standard(),
    )
    .unwrap();
    let assigned_ip = match config_message {
        shared::ControlMessage::Config { assigned_ip, .. } => assigned_ip,
        other => panic!("unexpected config message: {other:?}"),
    };

    let client_packet = ipv4_packet(assigned_ip, Ipv4Addr::new(1, 1, 1, 1));
    send_capsule(
        &mut request_body,
        Bytes::from(masque::encode_connect_ip_datagram_capsule(&client_packet)),
    )
    .await;
    let tunneled = tokio::time::timeout(Duration::from_secs(5), rx_tun.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tunneled, client_packet);

    let peer = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(peer) = state.peers.get(&assigned_ip) {
                break peer.clone();
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let server_packet = ipv4_packet(Ipv4Addr::new(1, 1, 1, 1), assigned_ip);
    peer.send(Bytes::from(masque::wrap_datagram(&server_packet)))
        .await
        .unwrap();
    let datagram_payload =
        read_capsule(&mut response_body, &mut response_buffer, CAPSULE_DATAGRAM).await;
    assert_eq!(
        masque::decode_connect_ip_datagram_payload(&datagram_payload),
        Some(server_packet.as_ref())
    );

    drop(request_body);
    drop(sender);
    driver.abort();
    server.abort();
}
