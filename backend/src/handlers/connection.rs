use std::sync::Arc;
use std::time::Duration;
use anyhow::Result;
use bytes::Bytes;
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

const H3_DETECTION_GRACE: Duration = Duration::from_millis(50);

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

async fn detect_initial_streams(connection: &quinn::Connection) -> Result<InitialStreams> {
    match negotiated_alpn(connection).as_deref() {
        Some(protocol) if protocol == b"mavivpn" => {
            let (send_stream, recv_stream) = connection.accept_bi().await?;
            Ok(InitialStreams::Raw {
                send_stream,
                recv_stream,
            })
        }
        _ => {
            tokio::select! {
                biased;
                uni_res = connection.accept_uni() => {
                    Ok(InitialStreams::H3 {
                        pre_bi: None,
                        pre_uni: uni_res?,
                    })
                }
                bi_res = connection.accept_bi() => {
                    let pre_bi = bi_res?;
                    match tokio::time::timeout(H3_DETECTION_GRACE, connection.accept_uni()).await {
                        Ok(Ok(pre_uni)) => Ok(InitialStreams::H3 {
                            pre_bi: Some(pre_bi),
                            pre_uni,
                        }),
                        Ok(Err(err)) => Err(err.into()),
                        Err(_) => {
                            let (send_stream, recv_stream) = pre_bi;
                            Ok(InitialStreams::Raw {
                                send_stream,
                                recv_stream,
                            })
                        }
                    }
                }
            }
        }
    }
}

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
    let alpn = negotiated_alpn(&connection)
        .map(|p| String::from_utf8_lossy(&p).into_owned())
        .unwrap_or_else(|| "<none>".to_string());

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

    let (mut send_stream, mut recv_stream) = pre_bi.expect("raw detection always includes a bidi stream");
    
    let auth_result = async {
        let buf = tokio::time::timeout(Duration::from_secs(5), async {
            let len = recv_stream.read_u32_le().await? as usize;
            if len > 16384 {
                anyhow::bail!("Auth message too big");
            }

            let mut buf = vec![0u8; len];
            recv_stream.read_exact(&mut buf).await?;
            Ok::<Vec<u8>, anyhow::Error>(buf)
        })
        .await
        .map_err(|_| anyhow::anyhow!("Handshake timeout"))??;
        
        let msg: ControlMessage = bincode::serde::decode_from_slice(&buf, bincode::config::standard())
            .map(|(v, _)| v)
            .map_err(|e| anyhow::anyhow!("Protocol error: {}", e))?;
        
        match msg {
            ControlMessage::Auth { token } => {
                authenticate_client(&token, &state, &config, &keycloak).await
            }
            _ => anyhow::bail!("Protocol error: Expected Auth"),
        }
    }.await;

    let (assigned_ip, assigned_ip6) = match auth_result {
        Ok(ips) => ips,
        Err(e) => {
            let error_msg = format!("Unauthorized: {}", e);
            if config.censorship_resistant {
                warn!("Unauthorized probe from {}. Emulating HTTP/3. Error: {}", remote_addr, e);
                let _ = emulate_http3(&connection, &mut send_stream).await;
                return Err(anyhow::anyhow!("HTTP/3 probe response sent: {}", e));
            } else {
                let err_payload = ControlMessage::Error { message: error_msg.clone() };
                if let Ok(encoded) = bincode::serde::encode_to_vec(&err_payload, bincode::config::standard()) {
                    let _ = send_stream.write_u32_le(encoded.len() as u32).await;
                    let _ = send_stream.write_all(&encoded).await;
                    let _ = send_stream.finish();
                }
                return Err(anyhow::anyhow!("{}", error_msg));
            }
        }
    };

    let _ip_guard = IpGuard { state: state.clone(), ip4: assigned_ip, ip6: assigned_ip6 };

    let success_msg = ControlMessage::Config {
        assigned_ip,
        netmask: state.network.mask(),
        gateway: state.gateway_ip(),
        dns_server: config.dns,
        mtu: config.mtu as u16,
        assigned_ipv6: if ipv6_enabled { Some(assigned_ip6) } else { None },
        netmask_v6: if ipv6_enabled { Some(64) } else { None },
        gateway_v6: if ipv6_enabled { Some(state.gateway_ip_v6()) } else { None },
        dns_server_v6: if ipv6_enabled {
            Some(config.dns_v6.unwrap_or_else(|| std::net::Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)))
        } else { None },
        whitelist_domains: Some(config.whitelist_domains.clone()),
    };
    
    let bytes = bincode::serde::encode_to_vec(&success_msg, bincode::config::standard())?;
    send_stream.write_u32_le(bytes.len() as u32).await?;
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
            let stats = conn_stats.stats();
            info!(
                "[SERVER QUIC STATS] Peer: {} | RTT: {}ms | CWND: {} bytes | Lost Packets: {} | Max Datagram: {}",
                remote_addr,
                stats.path.rtt.as_millis(),
                stats.path.cwnd,
                stats.path.lost_packets,
                conn_stats.max_datagram_size().unwrap_or(0)
            );
            if conn_stats.close_reason().is_some() { break; }
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
    ).await
}
