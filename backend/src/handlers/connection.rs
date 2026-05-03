use anyhow::Result;
use bytes::Bytes;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};

use shared::ControlMessage;

use crate::config::Config;
use crate::keycloak::KeycloakValidator;
use crate::state::AppState;

use crate::handlers::auth::authenticate_client;
use crate::handlers::h3::handle_h3_connection;
use crate::handlers::tunnel::run_tunnel;
use crate::handlers::utils::{emulate_http3, negotiated_alpn, negotiated_sni, IpGuard};

enum InitialStreams {
    Raw {
        send_stream: quinn::SendStream,
        recv_stream: quinn::RecvStream,
    },
    H3 {
        pre_bi: Option<(quinn::SendStream, quinn::RecvStream)>,
        pre_uni: quinn::RecvStream,
    },
}

const RAW_AUTH_MAX_BYTES: usize = 16_384;

fn validate_raw_auth_len(len: usize) -> Result<()> {
    if len > RAW_AUTH_MAX_BYTES {
        anyhow::bail!("Auth message too big");
    }
    Ok(())
}

fn decode_raw_auth_payload(buf: &[u8]) -> Result<String> {
    let msg: ControlMessage =
        bincode::serde::decode_from_slice(buf, bincode::config::standard())
            .map(|(v, _)| v)
            .map_err(|e| anyhow::anyhow!("Protocol error: {e}"))?;

    match msg {
        ControlMessage::Auth { token } => Ok(token),
        _ => anyhow::bail!("Protocol error: Expected Auth"),
    }
}

fn encode_control_message_frame(msg: &ControlMessage) -> Result<Vec<u8>> {
    let encoded = bincode::serde::encode_to_vec(msg, bincode::config::standard())?;
    let mut framed = Vec::with_capacity(4 + encoded.len());
    framed.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
    framed.extend_from_slice(&encoded);
    Ok(framed)
}

fn unauthorized_control_message(error: &anyhow::Error) -> ControlMessage {
    ControlMessage::Error {
        message: format!("Unauthorized: {error}"),
    }
}

pub(super) fn build_config_message(
    state: &AppState,
    config: &Config,
    assigned_ip: std::net::Ipv4Addr,
    assigned_ip6: std::net::Ipv6Addr,
    ipv6_enabled: bool,
) -> ControlMessage {
    ControlMessage::Config {
        assigned_ip,
        netmask: state.network.mask(),
        gateway: state.gateway_ip(),
        dns_server: config.dns,
        mtu: config.mtu,
        assigned_ipv6: if ipv6_enabled {
            Some(assigned_ip6)
        } else {
            None
        },
        netmask_v6: if ipv6_enabled { Some(64) } else { None },
        gateway_v6: if ipv6_enabled {
            Some(state.gateway_ip_v6())
        } else {
            None
        },
        dns_server_v6: if ipv6_enabled {
            Some(config.dns_v6.unwrap_or_else(|| {
                std::net::Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)
            }))
        } else {
            None
        },
        whitelist_domains: Some(config.whitelist_domains.clone()),
    }
}

async fn detect_initial_streams(connection: &quinn::Connection) -> Result<InitialStreams> {
    match negotiated_alpn(connection).as_deref() {
        // ALPN is the authoritative protocol signal. If the peer negotiated h3,
        // waiting for a unidirectional HTTP/3 control stream is correct; falling
        // back to raw mode after an arbitrary grace period races real H3 clients
        // on slow or jittery networks and makes their H3 bytes look like a raw
        // bincode auth message.
        Some(protocol) if protocol == b"h3" => {
            let pre_uni = connection.accept_uni().await?;
            Ok(InitialStreams::H3 {
                pre_bi: None,
                pre_uni,
            })
        }
        Some(protocol) if protocol == b"mavivpn" => {
            let (send_stream, recv_stream) = connection.accept_bi().await?;
            Ok(InitialStreams::Raw {
                send_stream,
                recv_stream,
            })
        }
        // Legacy fallback for peers without an ALPN value: accept the first bidi
        // stream as the raw control channel. Modern clients negotiate either
        // `mavivpn` or `h3`, so this avoids timing heuristics for supported paths.
        _ => {
            let (send_stream, recv_stream) = connection.accept_bi().await?;
            Ok(InitialStreams::Raw {
                send_stream,
                recv_stream,
            })
        }
    }
}

#[allow(clippy::too_many_lines)]
#[allow(clippy::cast_possible_truncation)]
pub async fn handle_connection(
    conn: quinn::Incoming,
    state: Arc<AppState>,
    config: Config,
    tx_tun: tokio::sync::mpsc::Sender<Bytes>,
    keycloak: Option<Arc<KeycloakValidator>>,
    ipv6_enabled: bool,
) -> Result<()> {
    let connection = conn.await?;
    let remote_addr = connection.remote_address();

    let sni = negotiated_sni(&connection);
    let alpn = negotiated_alpn(&connection).map_or_else(
        || "<none>".to_string(),
        |p| String::from_utf8_lossy(&p).into_owned(),
    );

    if config.censorship_resistant {
        let expected = &config.ech_public_name;
        match &sni {
            Some(s) if s == expected => info!(
                "New connection from {} | SNI: {:?} | ALPN: {} | ECH: cover SNI matches (ok)",
                remote_addr, s, alpn
            ),
            Some(s) => warn!(
                "New connection from {} | SNI: {:?} | ALPN: {} | ECH: expected cover SNI {:?}",
                remote_addr, s, alpn, expected
            ),
            None => info!(
                "New connection from {} | SNI: <none> | ALPN: {} | ECH: cover SNI expected {:?}",
                remote_addr, alpn, expected
            ),
        }
    } else {
        info!(
            "New connection from {} | SNI: {} | ALPN: {}",
            remote_addr,
            sni.as_deref().unwrap_or("<none>"),
            alpn
        );
    }

    let (pre_bi, pre_uni) = match detect_initial_streams(&connection).await? {
        InitialStreams::Raw {
            send_stream,
            recv_stream,
        } => (Some((send_stream, recv_stream)), None),
        InitialStreams::H3 { pre_bi, pre_uni } => (pre_bi, Some(pre_uni)),
    };

    if let Some(pre_uni) = pre_uni {
        return handle_h3_connection(
            connection,
            pre_bi,
            pre_uni,
            state,
            config,
            tx_tun,
            keycloak,
            ipv6_enabled,
            sni,
        )
        .await;
    }

    let (mut send_stream, mut recv_stream) =
        pre_bi.expect("raw detection always includes a bidi stream");

    let auth_result = async {
        let buf = tokio::time::timeout(Duration::from_secs(5), async {
            let len = recv_stream.read_u32_le().await? as usize;
            validate_raw_auth_len(len)?;

            let mut buf = vec![0u8; len];
            recv_stream.read_exact(&mut buf).await?;
            Ok::<Vec<u8>, anyhow::Error>(buf)
        })
        .await
        .map_err(|_| anyhow::anyhow!("Handshake timeout"))??;

        let token = decode_raw_auth_payload(&buf)?;
        authenticate_client(
            &token,
            &state,
            &config,
            keycloak
                .as_deref()
                .map(|kc| kc as &dyn crate::handlers::auth::TokenValidator),
        )
        .await
    }
    .await;

    let (assigned_ip, assigned_ip6) = match auth_result {
        Ok(ips) => ips,
        Err(e) => {
            let error_msg = format!("Unauthorized: {e}");
            if config.censorship_resistant {
                warn!(
                    "Unauthorized probe from {}. Emulating HTTP/3. Error: {}",
                    remote_addr, e
                );
                let _ = emulate_http3(&connection, &mut send_stream).await;
                return Err(anyhow::anyhow!("HTTP/3 probe response sent: {e}"));
            }
            let err_payload = unauthorized_control_message(&e);
            if let Ok(framed) = encode_control_message_frame(&err_payload) {
                let _ = send_stream.write_all(&framed).await;
                let _ = send_stream.finish();
            }
            return Err(anyhow::anyhow!("{error_msg}"));
        }
    };

    let _ip_guard = IpGuard {
        state: state.clone(),
        ip4: assigned_ip,
        ip6: assigned_ip6,
    };

    let success_msg = build_config_message(&state, &config, assigned_ip, assigned_ip6, ipv6_enabled);
    let bytes = encode_control_message_frame(&success_msg)?;
    send_stream.write_all(&bytes).await?;
    let _ = send_stream.finish();

    info!(
        "Authenticated {} | SNI: {} -> IPv4: {}, IPv6: {}",
        remote_addr,
        sni.as_deref().unwrap_or("<none>"),
        assigned_ip,
        assigned_ip6
    );

    let (tx_client, rx_client) = tokio::sync::mpsc::channel::<Bytes>(4096);
    state.register_client(assigned_ip, assigned_ip6, tx_client);

    let connection_arc = Arc::new(connection);
    let conn_stats = connection_arc.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let conn_metrics = conn_stats.stats();
            info!(
                "[SERVER QUIC STATS] Peer: {} | RTT: {}ms | CWND: {} bytes | Lost Packets: {} | Max Datagram: {}",
                remote_addr,
                conn_metrics.path.rtt.as_millis(),
                conn_metrics.path.cwnd,
                conn_metrics.path.lost_packets,
                conn_stats.max_datagram_size().unwrap_or(0)
            );
            if conn_stats.close_reason().is_some() {
                break;
            }
        }
    });

    run_tunnel(
        connection_arc,
        rx_client,
        tx_tun,
        assigned_ip,
        assigned_ip6,
        state.gateway_ip(),
        state.gateway_ip_v6(),
        config.mtu,
        false, // is_h3
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn test_config() -> Config {
        Config::parse_from([
            "mavi-vpn",
            "--auth-token",
            "secret",
            "--dns",
            "9.9.9.9",
            "--dns-v6",
            "2001:4860:4860::8888",
            "--whitelist-domains",
            "example.com,internal.test",
            "--mtu",
            "1340",
        ])
    }

    fn encode_message(msg: &ControlMessage) -> Vec<u8> {
        bincode::serde::encode_to_vec(msg, bincode::config::standard()).unwrap()
    }

    #[test]
    fn raw_auth_len_accepts_boundary_and_rejects_oversize() {
        assert!(validate_raw_auth_len(RAW_AUTH_MAX_BYTES).is_ok());
        assert!(validate_raw_auth_len(RAW_AUTH_MAX_BYTES + 1)
            .unwrap_err()
            .to_string()
            .contains("too big"));
    }

    #[test]
    fn raw_auth_payload_extracts_token() {
        let payload = encode_message(&ControlMessage::Auth {
            token: "token-123".to_string(),
        });

        assert_eq!(decode_raw_auth_payload(&payload).unwrap(), "token-123");
    }

    #[test]
    fn raw_auth_payload_rejects_non_auth_and_malformed() {
        let payload = encode_message(&ControlMessage::Error {
            message: "nope".to_string(),
        });
        assert!(decode_raw_auth_payload(&payload)
            .unwrap_err()
            .to_string()
            .contains("Expected Auth"));

        assert!(decode_raw_auth_payload(&[0xde, 0xad, 0xbe, 0xef])
            .unwrap_err()
            .to_string()
            .contains("Protocol error"));
    }

    #[test]
    fn unauthorized_response_frame_contains_error_message() {
        let err = anyhow::anyhow!("Access Denied: Invalid Token");
        let framed = encode_control_message_frame(&unauthorized_control_message(&err)).unwrap();
        let len = u32::from_le_bytes(framed[..4].try_into().unwrap()) as usize;
        assert_eq!(len, framed.len() - 4);

        let (decoded, _): (ControlMessage, _) =
            bincode::serde::decode_from_slice(&framed[4..], bincode::config::standard()).unwrap();
        match decoded {
            ControlMessage::Error { message } => {
                assert_eq!(message, "Unauthorized: Access Denied: Invalid Token");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn config_message_omits_ipv6_when_disabled() {
        let state = AppState::new("10.8.0.0/24").unwrap();
        let config = test_config();
        let msg = build_config_message(
            &state,
            &config,
            Ipv4Addr::new(10, 8, 0, 2),
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            false,
        );

        match msg {
            ControlMessage::Config {
                assigned_ipv6,
                netmask_v6,
                gateway_v6,
                dns_server_v6,
                whitelist_domains,
                mtu,
                ..
            } => {
                assert_eq!(mtu, 1340);
                assert!(assigned_ipv6.is_none());
                assert!(netmask_v6.is_none());
                assert!(gateway_v6.is_none());
                assert!(dns_server_v6.is_none());
                assert_eq!(
                    whitelist_domains,
                    Some(vec!["example.com".to_string(), "internal.test".to_string()])
                );
            }
            other => panic!("expected Config, got {other:?}"),
        }
    }

    #[test]
    fn config_message_includes_ipv6_and_default_dns_v6() {
        let state = AppState::new("10.8.0.0/24").unwrap();
        let mut config = test_config();
        config.dns_v6 = None;
        let assigned_ip6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        let msg = build_config_message(
            &state,
            &config,
            Ipv4Addr::new(10, 8, 0, 2),
            assigned_ip6,
            true,
        );

        match msg {
            ControlMessage::Config {
                assigned_ipv6,
                netmask_v6,
                gateway_v6,
                dns_server_v6,
                ..
            } => {
                assert_eq!(assigned_ipv6, Some(assigned_ip6));
                assert_eq!(netmask_v6, Some(64));
                assert_eq!(gateway_v6, Some(state.gateway_ip_v6()));
                assert_eq!(
                    dns_server_v6,
                    Some(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111))
                );
            }
            other => panic!("expected Config, got {other:?}"),
        }
    }
}
