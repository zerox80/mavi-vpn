use super::*;
use clap::Parser;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::{mpsc, Semaphore};

struct TestConnection {
    client: quinn::Endpoint,
    server: quinn::Endpoint,
    connection: quinn::Connection,
    handler: tokio::task::JoinHandle<Result<()>>,
    slots: Arc<Semaphore>,
    pending: Arc<Semaphore>,
    state: Arc<AppState>,
    tun_rx: mpsc::Receiver<Bytes>,
    h3_driver: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for TestConnection {
    fn drop(&mut self) {
        self.connection.close(0_u32.into(), b"test complete");
        self.client.close(0_u32.into(), b"test complete");
        self.server.close(0_u32.into(), b"test complete");
        self.handler.abort();
        if let Some(driver) = &self.h3_driver {
            driver.abort();
        }
    }
}

async fn connect(alpn: &[u8], censorship_resistant: bool, blocked: bool) -> TestConnection {
    let mut transport = quinn::TransportConfig::default();
    if blocked {
        if alpn == b"h3" {
            transport.max_concurrent_uni_streams(0_u32.into());
        } else {
            transport.stream_receive_window(0_u32.into());
        }
    }
    connect_with_transport(alpn, censorship_resistant, transport).await
}

async fn connect_with_transport(
    alpn: &[u8],
    censorship_resistant: bool,
    mut transport: quinn::TransportConfig,
) -> TestConnection {
    let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert = CertificateDer::from(generated.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(generated.signing_key.serialize_der().into());
    let mut config = Config::parse_from(["mavi-vpn", "--auth-token", "secret"]);
    config.bind_addr = "127.0.0.1:0".parse().unwrap();
    config.censorship_resistant = censorship_resistant;
    let server =
        crate::server::quic::create_quic_endpoint(&config, vec![cert.clone()], key).unwrap();
    let addr = server.local_addr().unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut tls = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::aws_lc_rs::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![alpn.to_vec()];
    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
    ));
    transport.keep_alive_interval(Some(Duration::from_millis(50)));
    client_config.transport_config(Arc::new(transport));
    let client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client.set_default_client_config(client_config);

    let state = Arc::new(AppState::new("10.8.0.0/24").unwrap());
    let slots = Arc::new(Semaphore::new(1));
    let pending = Arc::new(Semaphore::new(1));
    let (tx_tun, tun_rx) = mpsc::channel(16);
    let handler = {
        let server = server.clone();
        let state = state.clone();
        let slots = slots.clone();
        let pending = pending.clone();
        tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let _permit = slots.try_acquire_owned().unwrap();
            let pending_permit = pending.try_acquire_owned().unwrap();
            handle_connection(incoming, state, config, tx_tun, None, false, pending_permit).await
        })
    };
    let connection = client.connect(addr, "localhost").unwrap().await.unwrap();
    TestConnection {
        client,
        server,
        connection,
        handler,
        slots,
        pending,
        state,
        tun_rx,
        h3_driver: None,
    }
}

async fn assert_setup_times_out(test: &mut TestConnection) {
    let result = tokio::time::timeout(
        PREAUTH_PHASE_TIMEOUT + Duration::from_secs(2),
        &mut test.handler,
    )
    .await
    .expect("unauthenticated handler retained its slot beyond the deadline")
    .unwrap();
    assert!(result.unwrap_err().to_string().contains("timed out"));
    assert_eq!(test.slots.available_permits(), 1);
    assert_eq!(test.pending.available_permits(), 1);
    assert!(test.state.peers.is_empty());
    tokio::time::timeout(Duration::from_secs(1), test.connection.closed())
        .await
        .expect("deadline must close the QUIC connection");
}

#[tokio::test]
async fn setup_progress_does_not_restart_the_original_deadline() {
    let test = connect(b"mavivpn", false, false).await;
    let pending = Arc::new(Semaphore::new(1));
    let permit = pending.clone().try_acquire_owned().unwrap();
    let ready = Arc::new(tokio::sync::Notify::new());
    let progressed = std::sync::atomic::AtomicBool::new(false);
    tokio::time::pause();
    let start = tokio::time::Instant::now();
    let handler = async {
        tokio::time::sleep(Duration::from_millis(80)).await;
        progressed.store(true, std::sync::atomic::Ordering::SeqCst);
        std::future::pending::<Result<()>>().await
    };
    let result = preauth::until_ready(
        &test.connection,
        start + Duration::from_millis(100),
        permit,
        ready,
        handler,
    )
    .await;
    assert!(result.unwrap_err().to_string().contains("timed out"));
    assert!(progressed.load(std::sync::atomic::Ordering::SeqCst));
    // Tokio rounds timer deadlines to millisecond ticks. A restarted budget
    // after the 80ms setup step would instead finish at roughly 180ms.
    assert!((Duration::from_millis(100)..=Duration::from_millis(102)).contains(&start.elapsed()));
    assert_eq!(pending.available_permits(), 1);
    tokio::time::resume();
}

#[tokio::test]
async fn readiness_wins_a_simultaneously_ready_deadline_without_canceling_tunnel() {
    let test = connect(b"mavivpn", false, false).await;
    let pending = Arc::new(Semaphore::new(1));
    let permit = pending.clone().try_acquire_owned().unwrap();
    let ready = Arc::new(tokio::sync::Notify::new());
    let signal = ready.clone();
    let handler = async {
        signal.notify_one();
        tokio::task::yield_now().await;
        assert_eq!(pending.available_permits(), 1);
        Ok(())
    };
    preauth::until_ready(
        &test.connection,
        tokio::time::Instant::now(),
        permit,
        ready,
        handler,
    )
    .await
    .unwrap();
    assert!(test.connection.close_reason().is_none());
}

#[tokio::test]
async fn h3_zero_server_stream_credit_releases_slot_despite_keepalives() {
    let mut test = connect(b"h3", false, true).await;
    let mut stream = test.connection.open_uni().await.unwrap();
    stream.write_all(&[0]).await.unwrap();
    assert_setup_times_out(&mut test).await;
}

#[tokio::test]
async fn raw_rejection_zero_receive_credit_releases_slot_despite_keepalives() {
    let mut test = connect(b"mavivpn", false, true).await;
    let (mut send, _recv) = test.connection.open_bi().await.unwrap();
    send.write_all(
        &encode_control_message_frame(&ControlMessage::Auth {
            token: "wrong".to_owned(),
        })
        .unwrap(),
    )
    .await
    .unwrap();
    send.finish().unwrap();
    assert_setup_times_out(&mut test).await;
}

#[tokio::test]
async fn h3_camouflage_zero_server_stream_credit_releases_slot() {
    let mut test = connect(b"h3", true, true).await;
    let mut stream = test.connection.open_uni().await.unwrap();
    stream.write_all(&[0]).await.unwrap();
    assert_setup_times_out(&mut test).await;
}

#[tokio::test]
async fn raw_blocked_success_response_returns_address_lease() {
    let mut test = connect(b"mavivpn", false, true).await;
    let expected = test.state.assign_ip_pair().unwrap();
    test.state.release_ips(expected.0, expected.1);
    let (mut send, _recv) = test.connection.open_bi().await.unwrap();
    send.write_all(
        &encode_control_message_frame(&ControlMessage::Auth {
            token: "secret".to_owned(),
        })
        .unwrap(),
    )
    .await
    .unwrap();
    send.finish().unwrap();
    assert_setup_times_out(&mut test).await;
    assert_eq!(test.state.assign_ip_pair().unwrap(), expected);
}

async fn h3_client(
    test: &mut TestConnection,
) -> h3::client::SendRequest<h3_quinn::OpenStreams, Bytes> {
    let (mut driver, sender) = h3::client::builder()
        .enable_datagram(true)
        .enable_extended_connect(true)
        .build(h3_quinn::Connection::new(test.connection.clone()))
        .await
        .unwrap();
    test.h3_driver = Some(tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    }));
    sender
}

#[tokio::test]
async fn h3_camouflage_blocked_response_releases_slot() {
    let mut transport = quinn::TransportConfig::default();
    transport.stream_receive_window(32_u32.into());
    let mut test = connect_with_transport(b"h3", true, transport).await;
    let mut sender = h3_client(&mut test).await;
    let mut stream = sender
        .send_request(
            http::Request::builder()
                .uri("https://localhost/")
                .body(())
                .unwrap(),
        )
        .await
        .unwrap();
    stream.finish().await.unwrap();
    let response = stream.recv_response().await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(response.headers()["server"], "nginx");
    // The small window permits H3 setup but stalls the nginx body. Do not read
    // the body, so the peer cannot keep granting receive credit on its stream.
    assert_setup_times_out(&mut test).await;
}

#[tokio::test]
async fn h3_authenticated_tunnel_survives_setup_deadline() {
    let mut test = connect(b"h3", true, false).await;
    let mut sender = h3_client(&mut test).await;
    let request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri("https://localhost/.well-known/masque/ip/*/*/")
        .extension(h3::ext::Protocol::CONNECT_IP)
        .header("authorization", "Bearer secret")
        .header("capsule-protocol", "?1")
        .body(())
        .unwrap();
    let mut stream = sender.send_request(request).await.unwrap();
    assert_eq!(
        stream.recv_response().await.unwrap().status(),
        http::StatusCode::OK
    );
    assert!(stream.recv_data().await.unwrap().is_some());
    tokio::time::sleep(PREAUTH_PHASE_TIMEOUT + Duration::from_millis(100)).await;
    assert!(!test.handler.is_finished());
    assert_eq!(test.pending.available_permits(), 1);
    let assigned_ip = *test.state.peers.iter().next().unwrap().key();
    forward_packet(&mut test, assigned_ip, true).await;
}

#[tokio::test]
async fn raw_authenticated_tunnel_survives_setup_deadline() {
    let mut test = connect(b"mavivpn", false, false).await;
    let (mut send, mut recv) = test.connection.open_bi().await.unwrap();
    send.write_all(
        &encode_control_message_frame(&ControlMessage::Auth {
            token: "secret".to_owned(),
        })
        .unwrap(),
    )
    .await
    .unwrap();
    send.finish().unwrap();
    let len = recv.read_u32_le().await.unwrap() as usize;
    let mut config = vec![0; len];
    recv.read_exact(&mut config).await.unwrap();
    let (ControlMessage::Config { assigned_ip, .. }, _) =
        bincode::serde::decode_from_slice(&config, bincode::config::standard()).unwrap()
    else {
        panic!("expected configuration")
    };
    tokio::time::sleep(PREAUTH_PHASE_TIMEOUT + Duration::from_millis(100)).await;
    assert!(!test.handler.is_finished());
    assert_eq!(test.slots.available_permits(), 0);
    assert_eq!(test.pending.available_permits(), 1);
    forward_packet(&mut test, assigned_ip, false).await;
}

async fn forward_packet(test: &mut TestConnection, assigned_ip: std::net::Ipv4Addr, is_h3: bool) {
    let mut packet = vec![0_u8; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&20_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&assigned_ip.octets());
    packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
    let framed = if is_h3 {
        [
            shared::masque::DATAGRAM_PREFIX.as_slice(),
            packet.as_slice(),
        ]
        .concat()
    } else {
        packet.clone()
    };
    test.connection.send_datagram(Bytes::from(framed)).unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), test.tun_rx.recv())
            .await
            .unwrap()
            .unwrap(),
        packet
    );
}
