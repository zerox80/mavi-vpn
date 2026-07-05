use super::*;

#[test]
fn test_default_config() {
    let config = Config::parse_from(["mavi-vpn", "--auth-token", "secret123"]);
    assert_eq!(config.mtu, 1280);
    assert_eq!(config.network_cidr, "10.8.0.0/24");
    assert_eq!(config.network_cidr_v6, "fd00::/64");
    assert_eq!(config.dns, std::net::Ipv4Addr::new(1, 1, 1, 1));
    assert_eq!(config.auth_token.as_deref(), Some("secret123"));
    assert!(!config.censorship_resistant);
    assert!(!config.mss_clamping);
    assert!(config.validate().is_ok());
}

fn mtu_setting_for(args: &[&str]) -> MtuSetting {
    let matches = <Config as clap::CommandFactory>::command().get_matches_from(args);
    MtuSetting::from_matches(&matches)
}

#[test]
fn test_mtu_setting_provenance() {
    assert_eq!(
        mtu_setting_for(&["mavi-vpn", "--auth-token", "secret"]),
        MtuSetting::Default
    );
    assert_eq!(
        mtu_setting_for(&["mavi-vpn", "--auth-token", "secret", "--mtu", "1280"]),
        MtuSetting::Flag,
        "an explicit --mtu must report as flag-set even at the default value"
    );
}

#[test]
fn test_mtu_setting_labels() {
    assert_eq!(MtuSetting::Flag.label(), "--mtu flag");
    assert_eq!(MtuSetting::Env.label(), "VPN_MTU env / .env");
    assert_eq!(MtuSetting::Default.label(), "default");
}

#[test]
fn test_mtu_valid_range() {
    let config = Config::parse_from(["mavi-vpn", "--auth-token", "secret123", "--mtu", "1360"]);
    assert_eq!(config.mtu, 1360);

    let config = Config::parse_from(["mavi-vpn", "--auth-token", "secret123", "--mtu", "1280"]);
    assert_eq!(config.mtu, 1280);
}

#[test]
fn test_mtu_below_range_rejected() {
    let result = Config::try_parse_from(["mavi-vpn", "--auth-token", "secret123", "--mtu", "1279"]);
    assert!(result.is_err(), "MTU 1279 should be rejected");
}

#[test]
fn test_mtu_above_range_rejected() {
    let result = Config::try_parse_from(["mavi-vpn", "--auth-token", "secret123", "--mtu", "1361"]);
    assert!(result.is_err(), "MTU 1361 should be rejected");
}

#[test]
fn test_custom_arguments() {
    let config = Config::parse_from([
        "mavi-vpn",
        "--auth-token",
        "super_secret",
        "--network-cidr",
        "192.168.10.0/24",
        "--dns",
        "8.8.8.8",
        "--censorship-resistant",
        "--mss-clamping",
    ]);
    assert_eq!(config.auth_token.as_deref(), Some("super_secret"));
    assert_eq!(config.network_cidr, "192.168.10.0/24");
    assert_eq!(config.dns, std::net::Ipv4Addr::new(8, 8, 8, 8));
    assert!(config.censorship_resistant);
    assert!(config.mss_clamping);
}

#[test]
fn test_whitelist_domains() {
    let config = Config::parse_from([
        "mavi-vpn",
        "--auth-token",
        "secret",
        "--whitelist-domains",
        "github.com,google.com",
    ]);
    assert_eq!(config.whitelist_domains, vec!["github.com", "google.com"]);
}

#[test]
fn test_keycloak_flags() {
    let config = Config::parse_from([
        "mavi-vpn",
        "--auth-token",
        "secret",
        "--keycloak-enabled",
        "--keycloak-url",
        "https://auth.example.com",
        "--keycloak-realm",
        "my-realm",
        "--keycloak-client-id",
        "my-client",
    ]);
    assert!(config.keycloak_enabled);
    assert_eq!(
        config.keycloak_url.as_deref(),
        Some("https://auth.example.com")
    );
    assert_eq!(config.keycloak_realm, "my-realm");
    assert_eq!(config.keycloak_client_id, "my-client");
    assert!(config.keycloak_required_role.is_none());
    assert!(config.keycloak_required_scope.is_none());
}

#[test]
fn test_keycloak_defaults() {
    let config = Config::parse_from(["mavi-vpn", "--auth-token", "secret"]);
    assert!(!config.keycloak_enabled);
    assert!(config.keycloak_url.is_none());
    assert_eq!(config.keycloak_realm, "mavi-vpn");
    assert_eq!(config.keycloak_client_id, "mavi-client");
    assert!(config.keycloak_required_role.is_none());
    assert!(config.keycloak_required_scope.is_none());
}

#[test]
fn test_keycloak_does_not_require_static_token() {
    let config = Config::parse_from([
        "mavi-vpn",
        "--keycloak-enabled",
        "--keycloak-url",
        "https://auth.example.com",
    ]);
    assert!(config.keycloak_enabled);
    assert!(config.auth_token.is_none());
    assert!(config.validate().is_ok());
}

#[test]
fn test_static_auth_requires_token() {
    let config = Config::parse_from(["mavi-vpn"]);
    assert!(!config.keycloak_enabled);
    assert!(config.auth_token.is_none());
    assert!(config.validate().is_err());
}

#[test]
fn test_keycloak_policy_flags() {
    let config = Config::parse_from([
        "mavi-vpn",
        "--keycloak-enabled",
        "--keycloak-url",
        "https://auth.example.com",
        "--keycloak-required-role",
        "vpn-user",
        "--keycloak-required-scope",
        "vpn:connect",
    ]);

    assert_eq!(config.keycloak_required_role.as_deref(), Some("vpn-user"));
    assert_eq!(
        config.keycloak_required_scope.as_deref(),
        Some("vpn:connect")
    );
    assert!(config.validate().is_ok());
}

#[test]
fn test_keycloak_policy_requires_keycloak_auth() {
    let config = Config::parse_from([
        "mavi-vpn",
        "--auth-token",
        "secret",
        "--keycloak-required-role",
        "vpn-user",
    ]);

    assert!(config.validate().is_err());
}

#[test]
fn test_empty_role_and_scope_treated_as_unset() {
    // docker-compose passes unset variables through as empty strings
    // (`${VAR:-}`); normalize() must not trip the keycloak-policy check.
    let mut config = Config::parse_from([
        "mavi-vpn",
        "--auth-token",
        "secret",
        "--keycloak-required-role",
        "",
        "--keycloak-required-scope",
        "",
    ]);
    config.normalize();
    assert!(config.keycloak_required_role.is_none());
    assert!(config.keycloak_required_scope.is_none());
    assert!(config.validate().is_ok());
}

#[test]
fn test_normalize_keeps_real_role_and_scope() {
    let mut config = Config::parse_from([
        "mavi-vpn",
        "--keycloak-enabled",
        "--keycloak-url",
        "https://auth.example.com",
        "--keycloak-required-role",
        "vpn-user",
        "--keycloak-required-scope",
        "vpn:connect",
    ]);
    config.normalize();
    assert_eq!(config.keycloak_required_role.as_deref(), Some("vpn-user"));
    assert_eq!(
        config.keycloak_required_scope.as_deref(),
        Some("vpn:connect")
    );
    assert!(config.validate().is_ok());
}

#[test]
fn test_keycloak_requires_url() {
    let config = Config::parse_from(["mavi-vpn", "--keycloak-enabled"]);
    assert!(config.validate().is_err());
}

#[test]
fn test_keycloak_rejects_plain_http_url() {
    let config = Config::parse_from([
        "mavi-vpn",
        "--keycloak-enabled",
        "--keycloak-url",
        "http://auth.example.com",
    ]);
    assert!(config.validate().is_err());
}

#[test]
fn test_keycloak_allows_localhost_http_url() {
    for url in [
        "http://localhost:8080",
        "http://127.0.0.1:8080/path",
        "http://[::1]:8080",
    ] {
        let config = Config::parse_from(["mavi-vpn", "--keycloak-enabled", "--keycloak-url", url]);
        assert!(config.validate().is_ok(), "expected {url} to be allowed");
    }
}

#[test]
fn test_ipv6_network_flag() {
    let config = Config::parse_from([
        "mavi-vpn",
        "--auth-token",
        "secret",
        "--network-cidr-v6",
        "fd12:3456::/64",
    ]);
    assert_eq!(config.network_cidr_v6, "fd12:3456::/64");
}

#[test]
fn test_ech_flags() {
    let config = Config::parse_from([
        "mavi-vpn",
        "--auth-token",
        "secret",
        "--ech-public-name",
        "cover.example.com",
    ]);
    assert_eq!(config.ech_public_name, "cover.example.com");
}

#[test]
fn test_ech_defaults() {
    let config = Config::parse_from(["mavi-vpn", "--auth-token", "secret"]);
    assert_eq!(config.ech_public_name, "cloudflare-ech.com");
}

#[test]
fn test_dns_v6_flag() {
    let config = Config::parse_from([
        "mavi-vpn",
        "--auth-token",
        "secret",
        "--dns-v6",
        "2001:4860:4860::8888",
    ]);
    assert_eq!(config.dns_v6, Some("2001:4860:4860::8888".parse().unwrap()));
}

#[test]
fn test_dns_v6_default() {
    let config = Config::parse_from(["mavi-vpn", "--auth-token", "secret"]);
    assert!(config.dns_v6.is_none());
}

#[test]
fn test_bind_addr_default() {
    let config = Config::parse_from(["mavi-vpn", "--auth-token", "secret"]);
    assert_eq!(
        config.bind_addr,
        "0.0.0.0:4433".parse::<std::net::SocketAddr>().unwrap()
    );
}

#[test]
fn test_bind_addr_custom() {
    let config = Config::parse_from([
        "mavi-vpn",
        "--auth-token",
        "secret",
        "--bind-addr",
        "127.0.0.1:8443",
    ]);
    assert_eq!(
        config.bind_addr,
        "127.0.0.1:8443".parse::<std::net::SocketAddr>().unwrap()
    );
}

#[test]
fn test_tun_device_path() {
    let config = Config::parse_from([
        "mavi-vpn",
        "--auth-token",
        "secret",
        "--tun-device-path",
        "tun1",
    ]);
    assert_eq!(config.tun_device_path.as_deref(), Some("tun1"));
}
