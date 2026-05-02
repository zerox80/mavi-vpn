use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use tracing::{info, warn};

/// Detects the current physical IPv4 default gateway and interface.
pub(super) fn detect_physical_gateway() -> (Option<String>, Option<String>) {
    detect_physical_gateway_for(&["route", "show", "default"], "IPv4")
}

/// Detects the current physical IPv6 default gateway and interface.
pub(super) fn detect_physical_gateway_v6() -> (Option<String>, Option<String>) {
    detect_physical_gateway_for(&["-6", "route", "show", "default"], "IPv6")
}

fn detect_physical_gateway_for(
    ip_args: &[&str],
    family_label: &str,
) -> (Option<String>, Option<String>) {
    let output = Command::new("ip").args(ip_args).output();

    if let Ok(output) = output {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Parse first default route only: "default via 192.168.1.1 dev eth0 ..."
        let first_line = stdout.lines().next().unwrap_or("");
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        let gateway = parts
            .iter()
            .position(|&p| p == "via")
            .and_then(|i| parts.get(i + 1))
            .map(|s| s.to_string());
        let device = parts
            .iter()
            .position(|&p| p == "dev")
            .and_then(|i| parts.get(i + 1))
            .map(|s| s.to_string());

        if let (Some(ref gw), Some(ref dev)) = (&gateway, &device) {
            info!(
                "Detected physical {} gateway: {} via {}",
                family_label, gw, dev
            );
        }
        (gateway, device)
    } else {
        warn!("Could not detect physical {} gateway", family_label);
        (None, None)
    }
}

/// Parses an endpoint IP string that may be plain (`1.2.3.4`, `2606:4700::1`)
/// or bracketed (`[2606:4700::1]`). Rejects host:port forms — callers are
/// expected to pass the IP only.
pub(super) fn parse_endpoint_ip(s: &str) -> Result<IpAddr> {
    let cleaned = s.trim().trim_start_matches('[').trim_end_matches(']');
    cleaned
        .parse::<IpAddr>()
        .with_context(|| format!("not a valid IP address: {:?}", s))
}

pub(super) fn netmask_to_prefix(netmask: Ipv4Addr) -> u8 {
    u32::from_be_bytes(netmask.octets()).count_ones() as u8
}
