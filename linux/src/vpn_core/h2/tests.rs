use super::*;
use tokio::io::DuplexStream;
use tokio::sync::oneshot;

fn config_capsule() -> Bytes {
    let config = ControlMessage::Config {
        assigned_ip: "10.8.0.2".parse().unwrap(),
        netmask: "255.255.255.0".parse().unwrap(),
        gateway: "10.8.0.1".parse().unwrap(),
        dns_server: "1.1.1.1".parse().unwrap(),
        mtu: 1280,
        assigned_ipv6: None,
        netmask_v6: None,
        gateway_v6: None,
        dns_server_v6: None,
        whitelist_domains: None,
    };
    let payload = bincode::serde::encode_to_vec(config, bincode::config::standard()).unwrap();
    let mut capsule = Vec::new();
    masque::encode_capsule(CAPSULE_MAVI_CONFIG, &payload, &mut capsule);
    capsule.into()
}

/// Keep both directions open without granting any upload capacity.
async fn stalled_peer(io: DuplexStream, send_config: bool, ready: oneshot::Sender<()>) {
    let mut builder = h2::server::Builder::new();
    builder.enable_connect_protocol().initial_window_size(0);
    let mut connection = builder.handshake::<_, Bytes>(io).await.unwrap();
    let (request, mut respond) = connection.accept().await.unwrap().unwrap();
    let response = http::Response::builder()
        .header("capsule-protocol", "?1")
        .body(())
        .unwrap();
    let mut stream = respond.send_response(response, false).unwrap();
    if send_config {
        stream.send_data(config_capsule(), false).unwrap();
    }
    ready.send(()).unwrap();
    let _ = connection.accept().await;
    drop((request, stream));
}

#[tokio::test]
async fn last_session_drop_stops_transport_with_exhausted_send_window() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (client, server) = tokio::io::duplex(65536);
        let (ready, accepted) = oneshot::channel();
        let peer = tokio::spawn(stalled_peer(server, true, ready));
        let (session, _) = establish_h2(client, "127.0.0.1:443".parse().unwrap(), "test".into())
            .await
            .unwrap();
        accepted.await.unwrap();
        session
            .send_packet(Bytes::from(vec![0x45; 1280]))
            .await
            .unwrap();
        // Wait until send_capsules has dequeued the packet and is waiting for
        // flow control. Closing its input channel alone cannot wake this wait.
        while session.outbound.capacity() != CHANNEL_CAPACITY {
            tokio::task::yield_now().await;
        }
        let tasks = session._tasks.0.clone();
        let retained = session.clone();
        drop(session);
        tokio::task::yield_now().await;
        assert!(tasks.iter().all(|task| !task.is_finished()));

        drop(retained);
        while tasks.iter().any(|task| !task.is_finished()) {
            tokio::task::yield_now().await;
        }
        peer.await.unwrap();
    })
    .await
    .expect("dropping a stopped session must release the transport promptly");
}

#[tokio::test]
async fn cancelled_handshake_closes_the_connection_before_config_arrives() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (client, server) = tokio::io::duplex(65536);
        let (ready, accepted) = oneshot::channel();
        let peer = tokio::spawn(stalled_peer(server, false, ready));
        let handshake = tokio::spawn(establish_h2(
            client,
            "127.0.0.1:443".parse().unwrap(),
            "test".into(),
        ));
        accepted.await.unwrap();
        handshake.abort();
        assert!(matches!(handshake.await, Err(error) if error.is_cancelled()));
        peer.await.unwrap();
    })
    .await
    .expect("cancelling setup must release the HTTP/2 driver");
}
