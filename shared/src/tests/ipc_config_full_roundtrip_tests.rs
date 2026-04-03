use super::*;

#[test]
fn ipc_config_roundtrips_with_all_fields_present() {
    let decoded: ipc::Config = roundtrip(&sample_ipc_config_full());

    assert_eq!(decoded.endpoint, "vpn.example.com:4433");
    assert_eq!(decoded.token, "jwt-token");
    assert_eq!(decoded.cert_pin, "abcd1234");
    assert!(decoded.censorship_resistant);
    assert_eq!(decoded.kc_auth, Some(true));
    assert_eq!(decoded.kc_url.as_deref(), Some("https://sso.example.com"));
    assert_eq!(decoded.kc_realm.as_deref(), Some("mavi"));
    assert_eq!(decoded.kc_client_id.as_deref(), Some("desktop-client"));
}
