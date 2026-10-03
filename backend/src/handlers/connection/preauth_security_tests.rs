use super::*;

#[tokio::test]
async fn oversized_encoded_h3_headers_fail_before_the_setup_timeout() {
    let mut test = connect(b"h3", false, false).await;
    let mut control = test.connection.open_uni().await.unwrap();
    control.write_all(&[0, 4, 0]).await.unwrap(); // control stream + SETTINGS
    let (mut send, _recv) = test.connection.open_bi().await.unwrap();
    let mut header = Vec::new();
    shared::masque::write_varint(1, &mut header); // HEADERS
    shared::masque::write_varint(1 << 30, &mut header);
    send.write_all(&header).await.unwrap();
    for _ in 0..17 {
        let _ = send.write_all(&[0; 4096]).await;
    }
    let result = tokio::time::timeout(Duration::from_secs(2), &mut test.handler)
        .await
        .expect("encoded header budget must reject before preauth timeout")
        .unwrap();
    assert!(result.is_err());
    assert_eq!(test.pending.available_permits(), 1);
    assert!(test.state.peers.is_empty());
}

#[tokio::test]
async fn source_permit_is_released_at_authentication_readiness() {
    let test = connect(b"mavivpn", false, false).await;
    let quota = crate::state::quota::Quota::new();
    let source = quota.try_acquire("source", 1).unwrap();
    let pending = Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap();
    let ready = Arc::new(tokio::sync::Notify::new());
    let notify = ready.clone();
    let inspect = quota.clone();
    let tunnel = async move {
        notify.notify_one();
        tokio::task::yield_now().await;
        assert!(inspect.try_acquire("source", 1).is_some());
        Ok(())
    };
    preauth::until_ready(
        &test.connection,
        tokio::time::Instant::now() + Duration::from_secs(1),
        (pending, source),
        ready,
        tunnel,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn oversized_decoded_h3_fields_are_rejected() {
    let mut test = connect(b"h3", false, false).await;
    let (mut driver, mut sender) = h3::client::builder()
        .build::<_, _, Bytes>(h3_quinn::Connection::new(test.connection.clone()))
        .await
        .unwrap();
    // Send before polling the client driver, so the client has not learned the
    // peer's SETTINGS and the server must enforce its own decoded field limit.
    let mut stream = sender
        .send_request(
            http::Request::builder()
                .uri("https://localhost/")
                .header("x-padding", "a".repeat(20_000))
                .body(())
                .unwrap(),
        )
        .await
        .unwrap();
    test.h3_driver = Some(tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    }));
    let _ = stream.finish().await;
    let result = tokio::time::timeout(Duration::from_secs(2), &mut test.handler)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_err());
    assert!(test.state.peers.is_empty());
}
