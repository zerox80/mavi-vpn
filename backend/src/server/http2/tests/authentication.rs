use super::*;

struct TestConnection {
    sender: h2::client::SendRequest<Bytes>,
    ping_pong: h2::PingPong,
    client: tokio::task::JoinHandle<()>,
    server: tokio::task::JoinHandle<Result<()>>,
    pending: Arc<Semaphore>,
    connections: Arc<Semaphore>,
}

impl Drop for TestConnection {
    fn drop(&mut self) {
        self.client.abort();
        self.server.abort();
    }
}

async fn open_connection() -> TestConnection {
    let (certs, key, trusted_cert) = generate_test_certs();
    let acceptor = TlsAcceptor::from(Arc::new(build_tls_config(certs, key).unwrap()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let pending = Arc::new(Semaphore::new(1));
    let connections = Arc::new(Semaphore::new(1));
    let pending_permit = pending.clone().try_acquire_owned().unwrap();
    let connection_permit = connections.clone().try_acquire_owned().unwrap();
    let server = tokio::spawn(async move {
        let _connection_permit = connection_permit;
        let (tcp, peer) = listener.accept().await.unwrap();
        let tls = accept_tls(&acceptor, tcp, TLS_HANDSHAKE_TIMEOUT)
            .await
            .unwrap();
        let state = Arc::new(AppState::new("10.8.0.0/24").unwrap());
        let config = Config::parse_from(["mavi-vpn", "--auth-token", TEST_TOKEN]);
        let (tx, _rx) = mpsc::channel(8);
        serve_connection(tls, peer, state, config, tx, None, false, pending_permit).await
    });
    let (mut sender, ping_pong, client) = connect_client(addr, trusted_cert).await;
    wait_for_extended_connect(&mut sender).await;
    TestConnection {
        sender,
        ping_pong,
        client,
        server,
        pending,
        connections,
    }
}

async fn advance(seconds: u64) {
    tokio::time::advance(Duration::from_secs(seconds)).await;
    // Poll socket tasks and the connection deadline before inspecting state.
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn idle_h2_with_successful_pings_expires_and_releases_both_budgets() {
    let mut connection = open_connection().await;
    connection.ping_pong.ping(h2::Ping::opaque()).await.unwrap();
    assert_eq!(connection.pending.available_permits(), 0);
    assert_eq!(connection.connections.available_permits(), 0);
    tokio::time::pause();
    advance(AUTHENTICATION_TIMEOUT.as_secs() + 1).await;
    assert!(connection.server.is_finished());
    let error = (&mut connection.server).await.unwrap().unwrap_err();
    assert!(error.to_string().contains("VPN authentication timed out"));
    assert_eq!(connection.pending.available_permits(), 1);
    assert_eq!(connection.connections.available_permits(), 1);
}

#[tokio::test]
async fn http_requests_and_failed_authentication_do_not_release_pending_budget() {
    let mut connection = open_connection().await;
    tokio::time::pause();
    advance(AUTHENTICATION_TIMEOUT.as_secs() / 2).await;
    tokio::time::resume();
    let (response, _) = connection
        .sender
        .send_request(
            Request::builder()
                .uri("https://localhost/")
                .body(())
                .unwrap(),
            true,
        )
        .unwrap();
    assert_ne!(response.await.unwrap().status(), StatusCode::OK);
    let mut request = connect_ip_request("https://localhost/.well-known/masque/ip/*/*/");
    request
        .extensions_mut()
        .insert(h2::ext::Protocol::from_static(CONNECT_IP_PROTOCOL));
    request
        .headers_mut()
        .insert("authorization", "Bearer invalid".parse().unwrap());
    let (response, _) = connection.sender.send_request(request, true).unwrap();
    assert_eq!(response.await.unwrap().status(), StatusCode::UNAUTHORIZED);
    assert_eq!(connection.pending.available_permits(), 0);
    tokio::time::pause();
    // Later traffic must not restart the original authentication deadline.
    advance(AUTHENTICATION_TIMEOUT.as_secs() / 2 + 1).await;
    assert!(connection.server.is_finished());
    assert_eq!(connection.pending.available_permits(), 1);
}

#[tokio::test]
async fn authenticated_connect_releases_pending_budget_and_outlives_deadline() {
    let mut connection = open_connection().await;
    let mut request = connect_ip_request("https://localhost/.well-known/masque/ip/*/*/");
    request
        .extensions_mut()
        .insert(h2::ext::Protocol::from_static(CONNECT_IP_PROTOCOL));
    request.headers_mut().insert(
        "authorization",
        format!("Bearer {TEST_TOKEN}").parse().unwrap(),
    );
    let (response, _request_body) = connection.sender.send_request(request, false).unwrap();
    let response = response.await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut response_body = response.into_body();
    read_capsule(&mut response_body, &mut Vec::new(), CAPSULE_MAVI_CONFIG).await;
    assert_eq!(connection.pending.available_permits(), 1);
    assert_eq!(connection.connections.available_permits(), 0);
    tokio::time::pause();
    advance(AUTHENTICATION_TIMEOUT.as_secs() + 1).await;
    assert!(!connection.server.is_finished());
    assert_eq!(connection.connections.available_permits(), 0);
    tokio::time::resume();
    connection.ping_pong.ping(h2::Ping::opaque()).await.unwrap();
}
