//! HTTP/2 CONNECT-IP packet and control capsule transport.

use anyhow::Result;
use bytes::Bytes;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tracing::{info, warn};

use shared::{masque, ControlMessage};

use super::{packet_source_is_assigned, server_to_client_datagram};
use crate::handlers::connection::reauth::{
    decode_reauth_payload, reauth_decision, reauth_rate_limited, record_reauth_result,
};
use crate::handlers::connection::validate_raw_auth_len;
use crate::keycloak::KeycloakValidator;
use crate::state::AppState;

const CLIENT_CHANNEL_CAPACITY: usize = 4096;
const CONTROL_CHANNEL_CAPACITY: usize = 8;

struct ReauthContext {
    state: Arc<AppState>,
    keycloak: Option<Arc<KeycloakValidator>>,
    expected_subject: Option<String>,
    remote_ip: IpAddr,
    expiry_tx: watch::Sender<Option<i64>>,
    control_tx: mpsc::Sender<Bytes>,
}

impl ReauthContext {
    async fn handle(&self, payload: &[u8]) -> Result<()> {
        let accepted = self.validate(payload).await;
        let reply = ControlMessage::ReauthResult { accepted };
        let payload = bincode::serde::encode_to_vec(&reply, bincode::config::standard())?;
        let mut capsule = Vec::new();
        masque::encode_capsule(masque::CAPSULE_MAVI_REAUTH_RESULT, &payload, &mut capsule);
        self.control_tx
            .send(Bytes::from(capsule))
            .await
            .map_err(|_| anyhow::anyhow!("HTTP/2 response task stopped"))
    }

    async fn validate(&self, payload: &[u8]) -> bool {
        let (Some(keycloak), Some(expected_subject)) = (&self.keycloak, &self.expected_subject)
        else {
            return false;
        };
        if let Err(error) = validate_raw_auth_len(payload.len()) {
            warn!(%error, remote_ip = %self.remote_ip, "Oversized HTTP/2 reauth capsule");
            return false;
        }
        let token = match decode_reauth_payload(payload) {
            Ok(token) => token,
            Err(error) => {
                warn!(%error, remote_ip = %self.remote_ip, "Invalid HTTP/2 reauth capsule");
                return false;
            }
        };
        if reauth_rate_limited(&self.state, self.remote_ip) {
            warn!(remote_ip = %self.remote_ip, "HTTP/2 reauth rate limited");
            return false;
        }
        let validated = match keycloak.validate_token(&token).await {
            Ok(validated) => validated,
            Err(error) => {
                warn!(%error, remote_ip = %self.remote_ip, "HTTP/2 reauth validation failed");
                record_reauth_result(&self.state, self.remote_ip, false);
                return false;
            }
        };
        let Some(expiry) = reauth_decision(validated, expected_subject) else {
            record_reauth_result(&self.state, self.remote_ip, false);
            warn!(remote_ip = %self.remote_ip, "HTTP/2 reauth rejected");
            return false;
        };
        record_reauth_result(&self.state, self.remote_ip, true);
        let _ = self.expiry_tx.send(Some(expiry));
        info!(remote_ip = %self.remote_ip, expiry, "HTTP/2 reauth accepted");
        true
    }
}

/// Runs a CONNECT-IP tunnel transported by HTTP/2 DATA frames.
#[allow(clippy::too_many_arguments)]
pub async fn run_http2_tunnel(
    on_upgrade: OnUpgrade,
    initial_capsules: Vec<u8>,
    state: Arc<AppState>,
    tx_tun: mpsc::Sender<Bytes>,
    assigned_ip: Ipv4Addr,
    assigned_ip6: Ipv6Addr,
    tunnel_mtu: u16,
    session_expiry: Option<i64>,
    session_subject: Option<String>,
    keycloak: Option<Arc<KeycloakValidator>>,
    remote_ip: IpAddr,
) -> Result<()> {
    let upgraded = on_upgrade
        .await
        .map_err(|error| anyhow::anyhow!("HTTP/2 CONNECT upgrade failed: {error}"))?;
    let (mut request_stream, mut response_stream) = tokio::io::split(TokioIo::new(upgraded));
    response_stream.write_all(&initial_capsules).await?;

    let (tx_client, mut rx_client) = mpsc::channel::<Bytes>(CLIENT_CHANNEL_CAPACITY);
    let (control_tx, mut control_rx) = mpsc::channel::<Bytes>(CONTROL_CHANNEL_CAPACITY);
    let (expiry_tx, expiry_rx) = watch::channel(session_expiry);
    state.register_client(assigned_ip, assigned_ip6, tx_client);

    let server_to_client = async move {
        loop {
            tokio::select! {
                packet = rx_client.recv() => {
                    let Some(framed) = packet else { break };
                    let Some((_frame, packet)) = server_to_client_datagram(framed, false) else {
                        continue;
                    };
                    let capsule = masque::encode_connect_ip_datagram_capsule(&packet);
                    response_stream.write_all(&capsule).await?;
                }
                capsule = control_rx.recv() => {
                    let Some(capsule) = capsule else { break };
                    response_stream.write_all(&capsule).await?;
                }
            }
        }
        Ok(())
    };

    let reauth = ReauthContext {
        state,
        keycloak,
        expected_subject: session_subject,
        remote_ip,
        expiry_tx: expiry_tx.clone(),
        control_tx,
    };
    let client_to_server = async move {
        let mut capsule_buf = Vec::new();
        let mut read_buf = [0_u8; 16 * 1024];
        loop {
            let read = request_stream.read(&mut read_buf).await?;
            if read == 0 {
                break;
            }
            capsule_buf.extend_from_slice(&read_buf[..read]);
            if capsule_buf.len() > masque::MAX_CAPSULE_BUF {
                anyhow::bail!("HTTP/2 capsule buffer exceeds limit");
            }

            while let Some((capsule_type, payload, consumed)) = masque::read_capsule(&capsule_buf) {
                let reauth_payload = (capsule_type == masque::CAPSULE_MAVI_REAUTH)
                    .then(|| Bytes::copy_from_slice(payload));
                if capsule_type == masque::CAPSULE_DATAGRAM {
                    forward_packet(payload, tunnel_mtu, assigned_ip, assigned_ip6, &tx_tun)?;
                }
                capsule_buf.drain(..consumed);
                if let Some(payload) = reauth_payload {
                    reauth.handle(&payload).await?;
                }
            }
        }
        if !capsule_buf.is_empty() {
            anyhow::bail!("truncated HTTP/2 capsule at end of request body");
        }
        Ok(())
    };

    let tunnel = async {
        tokio::select! {
            result = server_to_client => result,
            result = client_to_server => result,
        }
    };
    let result = run_until_expiry(remote_ip, expiry_rx, tunnel).await;
    drop(expiry_tx);
    result
}

fn forward_packet(
    payload: &[u8],
    tunnel_mtu: u16,
    assigned_ip: Ipv4Addr,
    assigned_ip6: Ipv6Addr,
    tx_tun: &mpsc::Sender<Bytes>,
) -> Result<()> {
    let Some(packet) = masque::decode_connect_ip_datagram_payload(payload) else {
        anyhow::bail!("malformed HTTP/2 CONNECT-IP DATAGRAM capsule");
    };
    if packet.len() <= usize::from(tunnel_mtu)
        && packet_source_is_assigned(packet, assigned_ip, assigned_ip6)
    {
        match tx_tun.try_send(Bytes::copy_from_slice(packet)) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
            Err(mpsc::error::TrySendError::Closed(_)) => anyhow::bail!("TUN closed"),
        }
    }
    Ok(())
}

async fn run_until_expiry(
    remote_ip: IpAddr,
    mut expiry_rx: watch::Receiver<Option<i64>>,
    tunnel: impl std::future::Future<Output = Result<()>>,
) -> Result<()> {
    tokio::pin!(tunnel);
    loop {
        let Some(deadline) = crate::handlers::connection::session_deadline(*expiry_rx.borrow())
        else {
            return tunnel.await;
        };
        tokio::select! {
            result = &mut tunnel => return result,
            changed = expiry_rx.changed() => {
                if changed.is_err() {
                    return tunnel.await;
                }
            }
            () = tokio::time::sleep_until(deadline) => {
                if crate::handlers::connection::session_deadline(*expiry_rx.borrow())
                    .is_some_and(|current| current > deadline)
                {
                    continue;
                }
                warn!(%remote_ip, "Closing HTTP/2 tunnel: session token expired");
                return Ok(());
            }
        }
    }
}
