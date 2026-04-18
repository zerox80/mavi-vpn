//! # Linux Network Configuration
//!
//! Manages IP addresses, routes, MTU, and DNS settings for the VPN tunnel.
//! Uses `ip` commands for routing and supports both systemd-resolved and
//! direct /etc/resolv.conf manipulation for DNS.

use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;
use tracing::{info, warn};

/// Holds all state needed to cleanly tear down networking on exit.
pub struct NetworkConfig {
    pub tun_name: String,
    pub endpoint_ip: String,
    pub gateway_v4: Ipv4Addr,
    pub physical_gateway: Option<String>,
    pub physical_device: Option<String>,
    pub dns_backup: Option<Vec<u8>>,
    pub has_ipv6: bool,
    pub gateway_v6: Option<Ipv6Addr>,
    pub used_resolvconf: bool,
}

impl NetworkConfig {
    /// Applies all network configuration after a successful VPN handshake.
    pub fn apply(
        tun_name: &str,
        assigned_ip: Ipv4Addr,
        netmask: Ipv4Addr,
        gateway: Ipv4Addr,
        dns: Ipv4Addr,
        mtu: u16,
        endpoint_ip: &str,
        assigned_ipv6: Option<Ipv6Addr>,
        netmask_v6: Option<u8>,
        gateway_v6: Option<Ipv6Addr>,
        dns_v6: Option<Ipv6Addr>,
    ) -> Result<Self> {
        let prefix_len = netmask_to_prefix(netmask);

        // 1. Bring up the TUN interface
        run_cmd("ip", &["link", "set", tun_name, "up"])?;

        // 2. Set MTU (Rule 1: Always 1280)
        run_cmd("ip", &["link", "set", tun_name, "mtu", "1280"])?;

        // 3. Set IPv4 address
        run_cmd(
            "ip",
            &[
                "addr",
                "add",
                &format!("{}/{}", assigned_ip, prefix_len),
                "dev",
                tun_name,
            ],
        )?;

        // 4. Set IPv6 address if available
        let has_ipv6 = assigned_ipv6.is_some();
        if let Some(ipv6) = assigned_ipv6 {
            let v6_prefix = netmask_v6.unwrap_or(64);
            run_cmd(
                "ip",
                &[
                    "-6",
                    "addr",
                    "add",
                    &format!("{}/{}", ipv6, v6_prefix),
                    "dev",
                    tun_name,
                ],
            )?;
        }

        // 5. Detect the physical gateway and device (before we add VPN routes)
        let (physical_gateway, physical_device) = detect_physical_gateway();
        let (physical_gateway_v6, physical_device_v6) = detect_physical_gateway_v6();

        // 6. Add host route exception for the VPN server IP via the physical gateway
        //    This prevents routing loops (VPN traffic going back into the tunnel).
        //    The endpoint may be IPv4 or IPv6, so route via the matching family.
        match parse_endpoint_ip(endpoint_ip) {
            Ok(IpAddr::V4(v4)) => {
                if let (Some(ref gw), Some(ref dev)) = (&physical_gateway, &physical_device) {
                    let route = format!("{}/32", v4);
                    let _ = run_cmd(
                        "ip",
                        &["route", "add", &route, "via", gw, "dev", dev],
                    );
                } else {
                    warn!("No physical IPv4 gateway detected; skipping host route exception for {}", v4);
                }
            }
            Ok(IpAddr::V6(v6)) => {
                if let (Some(ref gw), Some(ref dev)) = (&physical_gateway_v6, &physical_device_v6) {
                    let route = format!("{}/128", v6);
                    let _ = run_cmd(
                        "ip",
                        &["-6", "route", "add", &route, "via", gw, "dev", dev],
                    );
                } else {
                    warn!("No physical IPv6 gateway detected; skipping host route exception for {}", v6);
                }
            }
            Err(e) => {
                warn!("Could not parse endpoint IP {:?}: {}; skipping host route exception", endpoint_ip, e);
            }
        }

        // 7. Split routes: 0.0.0.0/1 and 128.0.0.0/1
        //    This overrides the default route without deleting it.
        run_cmd(
            "ip",
            &[
                "route", "add", "0.0.0.0/1", "dev", tun_name, "via",
                &gateway.to_string(),
            ],
        )?;
        run_cmd(
            "ip",
            &[
                "route", "add", "128.0.0.0/1", "dev", tun_name, "via",
                &gateway.to_string(),
            ],
        )?;

        // 8. IPv6 routes
        if let Some(gv6) = gateway_v6 {
            let _ = run_cmd(
                "ip",
                &[
                    "-6", "route", "add", "::/1", "dev", tun_name, "via",
                    &gv6.to_string(),
                ],
            );
            let _ = run_cmd(
                "ip",
                &[
                    "-6", "route", "add", "8000::/1", "dev", tun_name, "via",
                    &gv6.to_string(),
                ],
            );
        }

        // 9. DNS configuration
        let (dns_backup, used_resolvconf) =
            configure_dns(tun_name, dns, dns_v6)?;

        info!(
            "Network configured: {} via {}, DNS={}",
            assigned_ip, tun_name, dns
        );

        Ok(Self {
            tun_name: tun_name.to_string(),
            endpoint_ip: endpoint_ip.to_string(),
            gateway_v4: gateway,
            physical_gateway,
            physical_device,
            dns_backup,
            has_ipv6,
            gateway_v6,
            used_resolvconf,
        })
    }

    /// Tears down all VPN networking: removes routes, restores DNS.
    pub fn cleanup(&self) {
        info!("Cleaning up network configuration...");

        // Remove VPN routes
        let _ = run_cmd("ip", &["route", "del", "0.0.0.0/1"]);
        let _ = run_cmd("ip", &["route", "del", "128.0.0.0/1"]);

        if self.gateway_v6.is_some() {
            let _ = run_cmd("ip", &["-6", "route", "del", "::/1"]);
            let _ = run_cmd("ip", &["-6", "route", "del", "8000::/1"]);
        }

        // Remove host route exception (must match the family used in apply()).
        match parse_endpoint_ip(&self.endpoint_ip) {
            Ok(IpAddr::V4(v4)) => {
                let _ = run_cmd("ip", &["route", "del", &format!("{}/32", v4)]);
            }
            Ok(IpAddr::V6(v6)) => {
                let _ = run_cmd("ip", &["-6", "route", "del", &format!("{}/128", v6)]);
            }
            Err(_) => {}
        }

        // Restore DNS
        restore_dns(&self.dns_backup, self.used_resolvconf);

        // Bring down the TUN interface (kernel will clean up on close, but be explicit)
        let _ = run_cmd("ip", &["link", "set", &self.tun_name, "down"]);

        info!("Network cleanup complete.");
    }
}

/// Detects the current physical IPv4 default gateway and interface.
fn detect_physical_gateway() -> (Option<String>, Option<String>) {
    detect_physical_gateway_for(&["route", "show", "default"], "IPv4")
}

/// Detects the current physical IPv6 default gateway and interface.
fn detect_physical_gateway_v6() -> (Option<String>, Option<String>) {
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
            info!("Detected physical {} gateway: {} via {}", family_label, gw, dev);
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
fn parse_endpoint_ip(s: &str) -> Result<IpAddr> {
    let cleaned = s.trim().trim_start_matches('[').trim_end_matches(']');
    cleaned
        .parse::<IpAddr>()
        .with_context(|| format!("not a valid IP address: {:?}", s))
}

/// Configures DNS to use the VPN's DNS servers.
/// Returns the backup of the previous resolv.conf (if applicable) and whether resolvconf was used.
fn configure_dns(
    tun_name: &str,
    dns_v4: Ipv4Addr,
    dns_v6: Option<Ipv6Addr>,
) -> Result<(Option<Vec<u8>>, bool)> {
    // Strategy 1: Try systemd-resolved via resolvectl
    if is_systemd_resolved_active() {
        info!("Using systemd-resolved for DNS configuration");

        let mut dns_servers = dns_v4.to_string();
        if let Some(v6) = dns_v6 {
            dns_servers.push(' ');
            dns_servers.push_str(&v6.to_string());
        }

        let _ = run_cmd("resolvectl", &["dns", tun_name, &dns_servers]);
        let _ = run_cmd("resolvectl", &["domain", tun_name, "~."]);
        // Set the VPN interface as default route for DNS
        let _ = run_cmd("resolvectl", &["default-route", tun_name, "true"]);

        return Ok((None, true));
    }

    // Strategy 2: Direct /etc/resolv.conf modification
    info!("Using /etc/resolv.conf for DNS configuration");

    // Only back up the file if it does NOT already carry the Mavi marker.
    // Otherwise a previous session that was killed before cleanup (crash,
    // SIGKILL, power loss) would have left its own nameserver line in place,
    // and capturing that as the "original" would mean `restore_dns` later
    // writes the VPN's own DNS back — permanently pointing the host at a
    // nameserver that is only reachable while the (now-gone) tunnel is up.
    let backup = std::fs::read("/etc/resolv.conf").ok().and_then(|bytes| {
        if is_mavi_generated_resolv_conf(&bytes) {
            warn!(
                "/etc/resolv.conf was left over from a previous Mavi VPN session \
                 (likely a crash). Skipping backup so we don't restore a dead \
                 tunnel's nameserver on stop."
            );
            None
        } else {
            Some(bytes)
        }
    });

    let mut content = format!(
        "# Generated by Mavi VPN - DO NOT EDIT\nnameserver {}\n",
        dns_v4
    );
    if let Some(v6) = dns_v6 {
        content.push_str(&format!("nameserver {}\n", v6));
    }

    std::fs::write("/etc/resolv.conf", &content)
        .context("Failed to write /etc/resolv.conf. Are you running as root?")?;

    Ok((backup, false))
}

/// Restores DNS configuration to its pre-VPN state.
fn restore_dns(backup: &Option<Vec<u8>>, used_resolvconf: bool) {
    if used_resolvconf {
        // systemd-resolved cleans up automatically when the interface goes down
        info!("systemd-resolved will restore DNS automatically");
        return;
    }

    if let Some(ref data) = backup {
        if let Err(e) = std::fs::write("/etc/resolv.conf", data) {
            warn!("Failed to restore /etc/resolv.conf: {}", e);
        } else {
            info!("Restored /etc/resolv.conf");
        }
    }
}

fn is_systemd_resolved_active() -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", "systemd-resolved"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn netmask_to_prefix(netmask: Ipv4Addr) -> u8 {
    u32::from_be_bytes(netmask.octets()).count_ones() as u8
}

/// Marker written at the top of `/etc/resolv.conf` while the VPN owns DNS.
/// Used to detect files left behind by a previous (crashed) session so we
/// don't adopt the VPN's own nameserver line as the "original" backup.
const RESOLV_CONF_MARKER: &[u8] = b"# Generated by Mavi VPN";

fn is_mavi_generated_resolv_conf(bytes: &[u8]) -> bool {
    bytes.starts_with(RESOLV_CONF_MARKER)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_detected_on_mavi_generated_file() {
        let bytes = b"# Generated by Mavi VPN - DO NOT EDIT\nnameserver 10.8.0.1\n";
        assert!(is_mavi_generated_resolv_conf(bytes));
    }

    #[test]
    fn marker_absent_on_real_resolv_conf() {
        let bytes = b"# Provided by systemd-resolved\nnameserver 1.1.1.1\n";
        assert!(!is_mavi_generated_resolv_conf(bytes));
    }

    #[test]
    fn marker_requires_prefix_not_substring() {
        // Marker must be at the very start; a line deeper in the file
        // doesn't count (and could appear in a user comment).
        let bytes = b"nameserver 1.1.1.1\n# Generated by Mavi VPN\n";
        assert!(!is_mavi_generated_resolv_conf(bytes));
    }

    #[test]
    fn empty_file_is_not_marked() {
        assert!(!is_mavi_generated_resolv_conf(b""));
    }
}

fn run_cmd(cmd: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("Failed to execute: {} {}", cmd, args.join(" ")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Don't fail on "RTNETLINK answers: File exists" (route already present)
        if stderr.contains("File exists") {
            return Ok(());
        }
        warn!("{} {} failed: {}", cmd, args.join(" "), stderr.trim());
        return Err(anyhow::anyhow!("{} failed: {}", cmd, stderr.trim()));
    }
    Ok(())
}
