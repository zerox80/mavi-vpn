use std::net::Ipv6Addr;

#[must_use]
pub fn split_endpoint(endpoint: &str) -> (&str, Option<&str>) {
    if let Some(rest) = endpoint.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = &rest[..end];
            let port = rest[end + 1..].strip_prefix(':');
            return (host, port);
        }
    }

    if endpoint.matches(':').count() == 1 {
        if let Some((host, port)) = endpoint.rsplit_once(':') {
            return (host, Some(port));
        }
    }

    (endpoint, None)
}

#[must_use]
pub fn endpoint_host(endpoint: &str) -> &str {
    split_endpoint(endpoint).0
}

#[must_use]
pub fn endpoint_host_is_explicit_ipv6(endpoint: &str) -> bool {
    endpoint_host(endpoint).parse::<Ipv6Addr>().is_ok()
}

/// Resolves the TLS server name from an endpoint, optionally preferring an ECH
/// outer SNI.
///
/// # Errors
/// Returns `Err` when the selected host/SNI is empty.
pub fn resolve_server_name(endpoint: &str, ech_outer_sni: Option<&str>) -> Result<String, String> {
    let name = ech_outer_sni.unwrap_or_else(|| endpoint_host(endpoint));
    if name.is_empty() {
        return Err("Endpoint host missing".to_string());
    }
    Ok(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_helpers_parse_host_and_optional_port() {
        assert_eq!(
            split_endpoint("vpn.example.com:4433"),
            ("vpn.example.com", Some("4433"))
        );
        assert_eq!(
            split_endpoint("[2001:db8::1]:443"),
            ("2001:db8::1", Some("443"))
        );
        assert_eq!(split_endpoint("2001:db8::1"), ("2001:db8::1", None));
        assert_eq!(endpoint_host("203.0.113.10:443"), "203.0.113.10");
    }

    #[test]
    fn server_name_prefers_ech_outer_sni_and_rejects_empty() {
        assert_eq!(
            resolve_server_name("vpn.example.com:443", Some("cover.example.com")).unwrap(),
            "cover.example.com"
        );
        assert_eq!(
            resolve_server_name("[2001:db8::1]:443", None).unwrap(),
            "2001:db8::1"
        );
        assert!(resolve_server_name(":443", None).is_err());
    }
}
