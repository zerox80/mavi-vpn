//! # Linux Network Configuration
//!
//! Manages IP addresses, routes, MTU, and DNS settings for the VPN tunnel.
//! Uses `ip` commands for routing and supports both systemd-resolved and
//! direct /etc/resolv.conf manipulation for DNS.

use anyhow::{Context, Result};
use std::net::{Ipv4Addr, Ipv6Addr};
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

        // 6. Add host route exception for the VPN server IP via the physical gateway
        //    This prevents routing loops (VPN traffic going back into the tunnel).
        if let (Some(ref gw), Some(ref dev)) = (&physical_gateway, &physical_device) {
            let server_ip = endpoint_ip
                .split(':')
                .next()
                .unwrap_or(endpoint_ip)
                .trim_start_matches('[')
                .trim_end_matches(']');
            let _ = run_cmd(
                "ip",
                &["route", "add", &format!("{}/32", server_ip), "via", gw, "dev", dev],
            );
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

        // Remove host route exception
        let server_ip = self
            .endpoint_ip
            .split(':')
            .next()
            .unwrap_or(&self.endpoint_ip)
            .trim_start_matches('[')
            .trim_end_matches(']');
        let _ = run_cmd("ip", &["route", "del", &format!("{}/32", server_ip)]);

        // Restore DNS
        restore_dns(&self.dns_backup, self.used_resolvconf);

        // Bring down the TUN interface (kernel will clean up on close, but be explicit)
        let _ = run_cmd("ip", &["link", "set", &self.tun_name, "down"]);

        info!("Network cleanup complete.");
    }
}

/// Detects the current physical default gateway and interface.
fn detect_physical_gateway() -> (Option<String>, Option<String>) {
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output();

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
            info!("Detected physical gateway: {} via {}", gw, dev);
        }
        (gateway, device)
    } else {
        warn!("Could not detect physical gateway");
        (None, None)
    }
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

    let backup = std::fs::read("/etc/resolv.conf").ok();

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
