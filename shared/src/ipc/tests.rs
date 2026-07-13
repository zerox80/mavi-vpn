use super::*;

#[test]
fn test_effective_http3_framing() {
    let mut config = Config {
        endpoint: "test".to_string(),
        token: "test".to_string(),
        cert_pin: "test".to_string(),
        censorship_resistant: false,
        http3_framing: false,
        kc_auth: None,
        kc_url: None,
        kc_realm: None,
        kc_client_id: None,
        refresh_token: None,
        ech_config: None,
        vpn_mtu: None,
        http2_framing: false,
        split_tunnel_mode: SplitTunnelMode::Disabled,
        split_tunnel_apps: Vec::new(),
        split_tunnel_uid: None,
    };

    // case: http3_framing=false, censorship_resistant=false => effective framing is false
    assert!(!config.effective_http3_framing());

    // case: http3_framing=true, censorship_resistant=false => effective framing is true
    config.http3_framing = true;
    assert!(config.effective_http3_framing());

    // case: http3_framing=false, censorship_resistant=true => effective framing is true
    config.http3_framing = false;
    config.censorship_resistant = true;
    assert!(config.effective_http3_framing());

    // case: http3_framing=true, censorship_resistant=true => effective framing is true
    config.http3_framing = true;
    assert!(config.effective_http3_framing());
}

#[test]
fn test_normalize_transport() {
    let mut config = Config {
        endpoint: "test".to_string(),
        token: "test".to_string(),
        cert_pin: "test".to_string(),
        censorship_resistant: true,
        http3_framing: false,
        kc_auth: None,
        kc_url: None,
        kc_realm: None,
        kc_client_id: None,
        refresh_token: None,
        ech_config: None,
        vpn_mtu: None,
        http2_framing: false,
        split_tunnel_mode: SplitTunnelMode::Disabled,
        split_tunnel_apps: Vec::new(),
        split_tunnel_uid: None,
    };

    // normalize_transport() returns true only when it actually changes http3_framing
    // censorship_resistant=true requires http3_framing=true
    assert!(config.normalize_transport());
    assert!(config.http3_framing);

    // Second call should return false as no change is needed
    assert!(!config.normalize_transport());
    assert!(config.http3_framing);

    // Case where no change is needed from the start
    config.censorship_resistant = false;
    config.http3_framing = false;
    assert!(!config.normalize_transport());
    assert!(!config.http3_framing);
}

#[test]
fn http2_transport_is_mutually_exclusive_with_http3_and_cr() {
    let mut config = Config {
        endpoint: "test".to_string(),
        token: "test".to_string(),
        cert_pin: "test".to_string(),
        censorship_resistant: true,
        http3_framing: true,
        kc_auth: None,
        kc_url: None,
        kc_realm: None,
        kc_client_id: None,
        refresh_token: None,
        ech_config: None,
        vpn_mtu: None,
        http2_framing: true,
        split_tunnel_mode: SplitTunnelMode::Disabled,
        split_tunnel_apps: Vec::new(),
        split_tunnel_uid: None,
    };
    assert!(config.normalize_transport());
    assert!(config.uses_http2());
    assert!(!config.effective_http3_framing());
    assert!(!config.censorship_resistant && !config.http3_framing);
}

#[test]
fn test_ipc_request_roundtrip() {
    let configs = vec![
        IpcRequest::Start(Config {
            endpoint: "vpn.example.com:4433".to_string(),
            token: "secret".to_string(),
            cert_pin: "pinned".to_string(),
            censorship_resistant: true,
            http3_framing: false,
            kc_auth: Some(true),
            kc_url: Some("https://auth.com".to_string()),
            kc_realm: Some("master".to_string()),
            kc_client_id: Some("vpn-client".to_string()),
            refresh_token: Some("refresh-secret".to_string()),
            ech_config: None,
            vpn_mtu: Some(1300),
            http2_framing: false,
            split_tunnel_mode: SplitTunnelMode::Exclude,
            split_tunnel_apps: vec![SplitTunnelApp {
                id: "firefox".to_string(),
                name: "Firefox".to_string(),
                exec: vec!["firefox".to_string()],
            }],
            split_tunnel_uid: Some(1000),
        }),
        IpcRequest::Start(Config {
            endpoint: "vpn.example.com:4433".to_string(),
            token: "secret".to_string(),
            cert_pin: "pinned".to_string(),
            censorship_resistant: false,
            http3_framing: true,
            kc_auth: Some(false),
            kc_url: None,
            kc_realm: None,
            kc_client_id: None,
            refresh_token: None,
            ech_config: Some("ech-config".to_string()),
            vpn_mtu: None,
            http2_framing: false,
            split_tunnel_mode: SplitTunnelMode::Disabled,
            split_tunnel_apps: Vec::new(),
            split_tunnel_uid: None,
        }),
        IpcRequest::Stop,
        IpcRequest::Status,
        IpcRequest::RepairNetwork,
        IpcRequest::UpdateToken {
            token: "fresh-access-token".to_string(),
        },
        IpcRequest::StartWithKeycloak {
            config: Config {
                endpoint: "vpn.example.com:4433".to_string(),
                token: "secret".to_string(),
                cert_pin: "pinned".to_string(),
                censorship_resistant: true,
                http3_framing: true,
                kc_auth: Some(true),
                kc_url: Some("https://auth.com".to_string()),
                kc_realm: Some("master".to_string()),
                kc_client_id: Some("vpn-client".to_string()),
                refresh_token: Some("refresh-secret".to_string()),
                ech_config: None,
                vpn_mtu: Some(1300),
                http2_framing: false,
                split_tunnel_mode: SplitTunnelMode::Include,
                split_tunnel_apps: vec![SplitTunnelApp {
                    id: "org.example.Chat".to_string(),
                    name: "Chat".to_string(),
                    exec: vec![
                        "flatpak".to_string(),
                        "run".to_string(),
                        "org.example.Chat".to_string(),
                    ],
                }],
                split_tunnel_uid: Some(1000),
            },
            keycloak: KeycloakRuntimeAuth {
                connection_id: "conn-1".to_string(),
                kc_url: "https://auth.com".to_string(),
                realm: "master".to_string(),
                client_id: "vpn-client".to_string(),
                refresh_token: "refresh-token".to_string(),
            },
        },
        IpcRequest::TakeRefreshTokenUpdate,
    ];

    for req in configs {
        let encoded = bincode::serde::encode_to_vec(&req, bincode::config::standard()).unwrap();
        let (decoded, _): (IpcRequest, usize) =
            bincode::serde::decode_from_slice(&encoded, bincode::config::standard()).unwrap();
        assert_eq!(req, decoded);
    }
}

#[test]
fn config_wire_format_is_stable() {
    // Captured once from `bincode::serde::encode_to_vec` for the exact
    // `Config` built below. IPC bincode is positional, so a future field
    // being added in the middle, removed, or reordered would silently
    // shift every following field on the wire instead of erroring loudly
    // — this fixture pins the layout so such a change fails this test
    // (or, if intentional, forces a conscious update here) rather than
    // only surfacing as a GUI/service version-skew bug in the field.
    const FIXTURE_BYTES: &[u8] = &[
        20, 118, 112, 110, 46, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 58, 52, 52, 51,
        51, 6, 115, 101, 99, 114, 101, 116, 6, 112, 105, 110, 110, 101, 100, 1, 0, 1, 1, 1, 16,
        104, 116, 116, 112, 115, 58, 47, 47, 97, 117, 116, 104, 46, 99, 111, 109, 1, 6, 109, 97,
        115, 116, 101, 114, 1, 10, 118, 112, 110, 45, 99, 108, 105, 101, 110, 116, 1, 14, 114, 101,
        102, 114, 101, 115, 104, 45, 115, 101, 99, 114, 101, 116, 0, 1, 251, 20, 5,
    ];

    let (decoded, consumed): (Config, usize) =
        bincode::serde::decode_from_slice(FIXTURE_BYTES, bincode::config::standard())
            .expect("Config wire format changed incompatibly - see comment above");
    assert_eq!(consumed, FIXTURE_BYTES.len());

    assert_eq!(decoded.endpoint, "vpn.example.com:4433");
    assert_eq!(decoded.token, "secret");
    assert_eq!(decoded.cert_pin, "pinned");
    assert!(decoded.censorship_resistant);
    assert!(!decoded.http3_framing);
    assert_eq!(decoded.kc_auth, Some(true));
    assert_eq!(decoded.kc_url.as_deref(), Some("https://auth.com"));
    assert_eq!(decoded.kc_realm.as_deref(), Some("master"));
    assert_eq!(decoded.kc_client_id.as_deref(), Some("vpn-client"));
    assert_eq!(decoded.refresh_token.as_deref(), Some("refresh-secret"));
    assert_eq!(decoded.ech_config, None);
    assert_eq!(decoded.vpn_mtu, Some(1300));
    assert!(!decoded.http2_framing);
    assert_eq!(decoded.split_tunnel_mode, SplitTunnelMode::Disabled);
    assert!(decoded.split_tunnel_apps.is_empty());
    assert_eq!(decoded.split_tunnel_uid, None);

    // Also confirm the current encoder still produces exactly this
    // fixture, so an accidental encoding-side change is caught too, not
    // just a decode-side one.
    let reencoded = bincode::serde::encode_to_vec(&decoded, bincode::config::standard())
        .expect("re-encoding a just-decoded Config cannot fail");
    let mut expected = FIXTURE_BYTES.to_vec();
    // The legacy fixture predates HTTP/2, followed now by the split mode and
    // application list and UID. All four fields encode to zero by default.
    expected.extend_from_slice(&[0, 0, 0, 0]);
    assert_eq!(reencoded, expected);
}

#[test]
fn test_ipc_response_roundtrip() {
    let responses = vec![
        IpcResponse::Ok,
        IpcResponse::Error("Failed to start".to_string()),
        IpcResponse::Status {
            running: true,
            endpoint: Some("1.2.3.4:443".to_string()),
            state: VpnState::Connected,
            last_error: None,
            assigned_ip: Some("10.8.0.2".to_string()),
        },
        IpcResponse::Status {
            running: false,
            endpoint: None,
            state: VpnState::Failed,
            last_error: Some("Auth failed".to_string()),
            assigned_ip: None,
        },
        IpcResponse::Status {
            running: false,
            endpoint: Some("1.2.3.4:443".to_string()),
            state: VpnState::Reconnecting,
            last_error: Some("H3 recv_response failed".to_string()),
            assigned_ip: None,
        },
        IpcResponse::RefreshTokenUpdate {
            connection_id: Some("conn-1".to_string()),
            refresh_token: Some("rotated-refresh-token".to_string()),
        },
        IpcResponse::RefreshTokenUpdate {
            connection_id: None,
            refresh_token: None,
        },
    ];

    for res in responses {
        let encoded = bincode::serde::encode_to_vec(&res, bincode::config::standard()).unwrap();
        let (decoded, _): (IpcResponse, usize) =
            bincode::serde::decode_from_slice(&encoded, bincode::config::standard()).unwrap();
        assert_eq!(res, decoded);
    }
}

#[test]
fn test_secure_ipc_request_roundtrip() {
    let req = SecureIpcRequest {
        auth_token: "local-secret".to_string(),
        request: IpcRequest::Status,
    };

    let encoded = bincode::serde::encode_to_vec(&req, bincode::config::standard()).unwrap();
    let (decoded, _): (SecureIpcRequest, usize) =
        bincode::serde::decode_from_slice(&encoded, bincode::config::standard()).unwrap();

    assert_eq!(req, decoded);
}
