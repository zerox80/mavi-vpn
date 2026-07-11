//! HTTP/2 CONNECT-IP client transport (RFC 9484 + RFC 9297).

use super::cert_pin::PinnedServerVerifier;
use anyhow::{Context, Result};
use bytes::Bytes;
use h2::{RecvStream, SendStream};
use shared::{looks_like_html_response, masque, masque::CAPSULE_MAVI_CONFIG, ControlMessage};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tokio_rustls::TlsConnector;

const CHANNEL_CAPACITY: usize = 4096;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Packet-plane handle. Unlike QUIC, HTTP/2 capsules are reliable and ordered.
#[derive(Clone)]
pub(super) struct Http2Session {
    outbound: mpsc::Sender<Bytes>,
    inbound: Arc<Mutex<mpsc::Receiver<Bytes>>>,
    reauth_results: Arc<Mutex<mpsc::Receiver<bool>>>,
    remote_addr: std::net::SocketAddr,
}

impl Http2Session {
    pub(super) fn remote_addr(&self) -> std::net::SocketAddr {
        self.remote_addr
    }

    pub(super) async fn send_packet(&self, packet: Bytes) -> Result<()> {
        let capsule = Bytes::from(masque::encode_connect_ip_datagram_capsule(&packet));
        self.outbound
            .send(capsule)
            .await
            .map_err(|_| anyhow::anyhow!("HTTP/2 CONNECT-IP send task stopped"))
    }

    pub(super) async fn recv_packet(&self) -> Result<Bytes> {
        self.inbound
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("HTTP/2 CONNECT-IP receive task stopped"))
    }

    pub(super) async fn reauthenticate(&self, token: &str) -> Result<bool> {
        let mut results = self.reauth_results.lock().await;
        while results.try_recv().is_ok() {}
        let message = ControlMessage::Reauth {
            token: token.to_owned(),
        };
        let payload = bincode::serde::encode_to_vec(&message, bincode::config::standard())?;
        let mut capsule = Vec::new();
        masque::encode_capsule(masque::CAPSULE_MAVI_REAUTH, &payload, &mut capsule);
        self.outbound
            .send(Bytes::from(capsule))
            .await
            .map_err(|_| anyhow::anyhow!("HTTP/2 CONNECT-IP send task stopped"))?;
        tokio::time::timeout(Duration::from_secs(10), results.recv())
            .await
            .map_err(|_| anyhow::anyhow!("HTTP/2 reauth timed out"))?
            .ok_or_else(|| anyhow::anyhow!("HTTP/2 CONNECT-IP receive task stopped"))
    }
}

/// Establishes TLS + extended CONNECT and returns after `MAVI_CONFIG` arrives.
pub(super) async fn connect_and_handshake_h2(
    endpoint: &str,
    token: String,
    cert_pin: Vec<Vec<u8>>,
) -> Result<(Http2Session, ControlMessage)> {
    let addrs: Vec<_> = tokio::net::lookup_host(endpoint).await?.collect();
    let host = shared::endpoint_host(endpoint);
    let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|_| anyhow::anyhow!("invalid server name in endpoint"))?;
    let verifier = Arc::new(PinnedServerVerifier::new(cert_pin));
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let mut tls_config = rustls::ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(tls_config));

    let mut last_error = None;
    for addr in addrs {
        let tcp = match tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect(addr),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                last_error = Some(anyhow::Error::from(error));
                continue;
            }
            Err(_) => {
                last_error = Some(anyhow::anyhow!("TCP connection to {addr} timed out"));
                continue;
            }
        };
        let remote_addr = tcp.peer_addr()?;
        let tls = match connector.connect(server_name.clone(), tcp).await {
            Ok(stream) => stream,
            Err(error) => {
                last_error = Some(anyhow::Error::from(error));
                continue;
            }
        };
        if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
            last_error = Some(anyhow::anyhow!("server did not negotiate ALPN h2"));
            continue;
        }
        return establish_h2(tls, remote_addr, token).await;
    }
    Err(last_error
        .unwrap_or_else(|| anyhow::anyhow!("TCP connection failed for every resolved address")))
}

async fn establish_h2(
    tls: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    remote_addr: std::net::SocketAddr,
    token: String,
) -> Result<(Http2Session, ControlMessage)> {
    let builder = h2::client::Builder::new();
    let (mut sender, connection) = builder
        .handshake(tls)
        .await
        .context("HTTP/2 client handshake failed")?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            tracing::debug!(%error, "HTTP/2 connection driver ended");
        }
    });

    sender
        .clone()
        .ready()
        .await
        .context("HTTP/2 sender not ready")?;
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        while !sender.is_extended_connect_protocol_enabled() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("server did not advertise SETTINGS_ENABLE_CONNECT_PROTOCOL")?;
    let mut request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri("https://mavi-vpn/.well-known/masque/ip/*/*/")
        .header("authorization", format!("Bearer {token}"))
        .header("capsule-protocol", "?1")
        .body(())
        .context("failed to build HTTP/2 CONNECT-IP request")?;
    request
        .extensions_mut()
        .insert(h2::ext::Protocol::from_static("connect-ip"));
    let (response, send_stream) = sender.send_request(request, false)?;
    let response = response
        .await
        .context("HTTP/2 CONNECT-IP response failed")?;
    if response.status() != http::StatusCode::OK {
        anyhow::bail!("AUTH_FAILED: server returned HTTP {}", response.status());
    }
    if response
        .headers()
        .get("capsule-protocol")
        .is_none_or(|value| value != "?1")
    {
        anyhow::bail!("server did not enable CONNECT-IP capsule protocol");
    }

    let mut recv_stream = response.into_body();
    let (config, capsule_buf) = read_config(&mut recv_stream).await?;
    let (outbound, outbound_rx) = mpsc::channel(CHANNEL_CAPACITY);
    let (inbound_tx, inbound) = mpsc::channel(CHANNEL_CAPACITY);
    let (reauth_tx, reauth_results) = mpsc::channel(CHANNEL_CAPACITY);
    tokio::spawn(send_capsules(send_stream, outbound_rx));
    tokio::spawn(receive_capsules(
        recv_stream,
        capsule_buf,
        inbound_tx,
        reauth_tx,
    ));
    Ok((
        Http2Session {
            outbound,
            inbound: Arc::new(Mutex::new(inbound)),
            reauth_results: Arc::new(Mutex::new(reauth_results)),
            remote_addr,
        },
        config,
    ))
}

async fn read_config(recv: &mut RecvStream) -> Result<(ControlMessage, Vec<u8>)> {
    let mut buffer = Vec::new();
    let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;
    loop {
        while let Some((kind, payload, consumed)) = masque::read_capsule(&buffer) {
            if kind == CAPSULE_MAVI_CONFIG {
                let (config, _) =
                    bincode::serde::decode_from_slice(payload, bincode::config::standard())
                        .context("invalid MAVI_CONFIG capsule")?;
                buffer.drain(..consumed);
                return Ok((config, buffer));
            }
            buffer.drain(..consumed);
        }
        if buffer.len() > masque::MAX_CAPSULE_BUF {
            anyhow::bail!("CONNECT-IP capsule buffer exceeds limit");
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let data = tokio::time::timeout(remaining, recv.data())
            .await
            .map_err(|_| anyhow::anyhow!("timed out waiting for MAVI_CONFIG capsule"))?
            .ok_or_else(|| anyhow::anyhow!("server closed CONNECT-IP stream before MAVI_CONFIG"))?
            .context("HTTP/2 response body failed")?;
        buffer.extend_from_slice(&data);
        recv.flow_control()
            .release_capacity(data.len())
            .context("failed to release HTTP/2 receive capacity")?;
        if looks_like_html_response(&buffer) {
            anyhow::bail!("AUTH_FAILED: server returned HTML instead of CONNECT-IP capsules");
        }
    }
}

async fn send_capsules(mut stream: SendStream<Bytes>, mut capsules: mpsc::Receiver<Bytes>) {
    while let Some(capsule) = capsules.recv().await {
        stream.reserve_capacity(capsule.len());
        while stream.capacity() < capsule.len() {
            let Some(result) = std::future::poll_fn(|cx| stream.poll_capacity(cx)).await else {
                return;
            };
            if result.is_err() {
                return;
            }
        }
        if stream.send_data(capsule, false).is_err() {
            return;
        }
    }
    let _ = stream.send_data(Bytes::new(), true);
}

async fn receive_capsules(
    mut stream: RecvStream,
    mut buffer: Vec<u8>,
    packets: mpsc::Sender<Bytes>,
    reauth_results: mpsc::Sender<bool>,
) {
    loop {
        while let Some((kind, payload, consumed)) = masque::read_capsule(&buffer) {
            if kind == masque::CAPSULE_DATAGRAM {
                if let Some(packet) = masque::decode_connect_ip_datagram_payload(payload) {
                    if packets.send(Bytes::copy_from_slice(packet)).await.is_err() {
                        return;
                    }
                }
            } else if kind == masque::CAPSULE_MAVI_REAUTH_RESULT {
                let Ok((ControlMessage::ReauthResult { accepted }, _)) =
                    bincode::serde::decode_from_slice(payload, bincode::config::standard())
                else {
                    return;
                };
                if reauth_results.send(accepted).await.is_err() {
                    return;
                }
            }
            buffer.drain(..consumed);
        }
        if buffer.len() > masque::MAX_CAPSULE_BUF {
            return;
        }
        match stream.data().await {
            Some(Ok(data)) => {
                buffer.extend_from_slice(&data);
                if stream.flow_control().release_capacity(data.len()).is_err() {
                    return;
                }
            }
            None | Some(Err(_)) => return,
        }
    }
}
