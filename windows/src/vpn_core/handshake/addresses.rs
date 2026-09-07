use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tracing::{info, warn};

// Leave time for another address and authentication within the 15s session deadline.
const ADDRESS_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) async fn connect(
    endpoint: &quinn::Endpoint,
    addrs: Vec<SocketAddr>,
    server_name: &str,
) -> Result<quinn::Connection> {
    let mut last_error = None;
    for addr in addrs {
        let started = Instant::now();
        info!("Connecting to {addr} (SNI: {server_name})");
        let attempt = async {
            let connecting = endpoint.connect(addr, server_name)?;
            tokio::time::timeout(ADDRESS_TIMEOUT, connecting)
                .await
                .with_context(|| format!("QUIC handshake to {addr} timed out after 5s"))?
                .map_err(anyhow::Error::from)
        }
        .await;
        match attempt {
            Ok(connection) => {
                info!(
                    "QUIC handshake to {addr} completed in {} ms",
                    started.elapsed().as_millis()
                );
                return Ok(connection);
            }
            Err(error) => {
                warn!("QUIC handshake to {addr} failed: {error:#}");
                last_error = Some(error);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("No reachable address for {server_name}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn silent_first_address_falls_back_before_session_deadline() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
        let server_config =
            quinn::ServerConfig::with_single_cert(vec![cert.cert.der().clone()], key.into())
                .unwrap();
        let server =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(
            quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap(),
        );
        // A bound socket silently absorbs Initial packets instead of returning ICMP errors.
        let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let connection = server.accept().await.unwrap().await.unwrap();
            (server, connection)
        });
        let connection = tokio::time::timeout(
            Duration::from_secs(14),
            connect(
                &client,
                vec![silent.local_addr().unwrap(), server_addr],
                "localhost",
            ),
        )
        .await
        .expect("fallback must fit inside the session deadline")
        .unwrap();
        assert_eq!(connection.remote_address(), server_addr);
        let (_server, peer) = accept.await.unwrap();
        connection.close(0u32.into(), b"test complete");
        peer.closed().await;
    }
}
