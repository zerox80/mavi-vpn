use super::*;

#[test]
fn ipc_config_roundtrips_without_optional_keycloak_fields() {
    let decoded: ipc::Config = roundtrip(&sample_ipc_config_minimal());

    assert_eq!(decoded.endpoint, "vpn.example.com:4433");
    assert_eq!(decoded.token, "plain-token");
    assert_eq!(decoded.cert_pin, "deadbeef");
    assert!(!decoded.censorship_resistant);
    assert!(decoded.kc_auth.is_none());
    assert!(decoded.kc_url.is_none());
    assert!(decoded.kc_realm.is_none());
    assert!(decoded.kc_client_id.is_none());
}
