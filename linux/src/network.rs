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
    //
    // On the first successful overwrite we also mirror the original bytes to
    // a durable on-disk backup (`/var/lib/mavi-vpn/resolv.conf.backup`), so a
    // crash between `apply` and `cleanup` doesn't strand the host with a dead
    // nameserver: the next session (or even a manual restore) can recover the
    // real resolv.conf even though the in-memory backup is gone.
    let current = std::fs::read(RESOLV_CONF_PATH).ok();
    let backup = match current {
        Some(bytes) if is_mavi_generated_resolv_conf(&bytes) => {
            // A previous session already overwrote /etc/resolv.conf and died
            // before it could restore. Fall back to the persistent backup we
            // saved at that time.
            match load_persistent_backup() {
                Some(persisted) => {
                    info!(
                        "Recovered original /etc/resolv.conf from persistent backup at {} \
                         (previous session appears to have crashed)",
                        BACKUP_PATH
                    );
                    Some(persisted)
                }
                None => {
                    warn!(
                        "/etc/resolv.conf was left over from a previous Mavi VPN session \
                         and no persistent backup at {} is available. On stop we will \
                         fall back to public resolvers to keep DNS working.",
                        BACKUP_PATH
                    );
                    None
                }
            }
        }
        Some(bytes) => {
            if let Err(e) = save_persistent_backup(&bytes) {
                warn!(
                    "Failed to write persistent resolv.conf backup to {}: {}. \
                     A crash before stop may leave DNS pointing at the VPN resolver.",
                    BACKUP_PATH, e
                );
            }
            Some(bytes)
        }
        None => None,
    };

    let mut content = format!(
        "# Generated by Mavi VPN - DO NOT EDIT\nnameserver {}\n",
        dns_v4
    );
    if let Some(v6) = dns_v6 {
        content.push_str(&format!("nameserver {}\n", v6));
    }

    std::fs::write(RESOLV_CONF_PATH, &content)
        .context("Failed to write /etc/resolv.conf. Are you running as root?")?;

    Ok((backup, false))
}

/// Restores DNS configuration to its pre-VPN state.
///
/// Preference order:
///   1. In-memory backup captured at `configure_dns` time.
///   2. Persistent on-disk backup at `BACKUP_PATH`, used to survive crashes
///      between `apply` and `cleanup`.
///   3. Safe fallback nameservers (public resolvers) so the host keeps
///      working DNS instead of being left pointing at a dead VPN resolver.
fn restore_dns(backup: &Option<Vec<u8>>, used_resolvconf: bool) {
    if used_resolvconf {
        // systemd-resolved cleans up automatically when the interface goes down
        info!("systemd-resolved will restore DNS automatically");
        return;
    }

    let restored = if let Some(ref data) = backup {
        write_resolv_conf(data, "in-memory backup")
    } else if let Some(persisted) = load_persistent_backup() {
        write_resolv_conf(&persisted, "persistent backup")
    } else {
        warn!(
            "No resolv.conf backup available (neither in-memory nor at {}). \
             Writing safe fallback nameservers so DNS keeps working.",
            BACKUP_PATH
        );
        write_resolv_conf(FALLBACK_RESOLV_CONF.as_bytes(), "fallback resolvers")
    };

    if restored {
        clear_persistent_backup();
    }
}

fn write_resolv_conf(data: &[u8], source_label: &str) -> bool {
    match std::fs::write(RESOLV_CONF_PATH, data) {
        Ok(()) => {
            info!("Restored /etc/resolv.conf from {}", source_label);
            true
        }
        Err(e) => {
            warn!(
                "Failed to restore /etc/resolv.conf from {}: {}",
                source_label, e
            );
            false
        }
    }
}

/// Writes the pre-VPN resolv.conf to a durable location that survives crashes.
/// Created with 0o600 via `O_CREAT | O_EXCL | O_NOFOLLOW` so the file can't be
/// pre-created as a symlink to somewhere else and so it isn't world-readable.
fn save_persistent_backup(bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

    if let Some(parent) = std::path::Path::new(BACKUP_PATH).parent() {
        // Create the directory securely with 0o700 permissions from the start.
        // This ensures the backup (which mirrors /etc/resolv.conf, normally
        // world-readable but potentially containing search-domain hints) isn't
        // listable by non-root users at any point.
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }

    // Best-effort unlink of any stale file (old mode, wrong owner, symlink).
    let _ = std::fs::remove_file(BACKUP_PATH);

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(BACKUP_PATH)?;
    f.write_all(bytes)?;
    f.sync_all()
}

fn load_persistent_backup() -> Option<Vec<u8>> {
    match std::fs::read(BACKUP_PATH) {
        Ok(bytes) if !bytes.is_empty() => Some(bytes),
        Ok(_) => None,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            warn!("Failed to read persistent resolv.conf backup at {}: {}", BACKUP_PATH, e);
            None
        }
    }
}

fn clear_persistent_backup() {
    match std::fs::remove_file(BACKUP_PATH) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!(
            "Failed to remove persistent resolv.conf backup at {}: {}",
            BACKUP_PATH, e
        ),
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

/// Path of the system resolver configuration we manage.
const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

/// Durable copy of the pre-VPN `/etc/resolv.conf`. Used to recover the
/// original DNS configuration after a crash between `apply` and `cleanup`,
/// and to seed `restore_dns` when the in-memory backup is missing because the
/// current process found a Mavi-marked file at startup.
const BACKUP_PATH: &str = "/var/lib/mavi-vpn/resolv.conf.backup";

/// Last-resort resolv.conf content when neither the in-memory nor the
/// persistent backup is available. Keeps name resolution working instead of
/// leaving the host pointing at the dead VPN resolver (e.g. 10.8.0.1).
const FALLBACK_RESOLV_CONF: &str = "\
# Restored by Mavi VPN - original resolv.conf was not available
nameserver 1.1.1.1
nameserver 9.9.9.9
";

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

    #[test]
    fn fallback_resolv_conf_is_parseable() {
        // Smoke-test: every non-empty, non-comment line is `nameserver <IP>`
        // with a valid address. This guards against an accidental edit that
        // would ship a broken fallback to production.
        let mut nameservers = 0;
        for line in FALLBACK_RESOLV_CONF.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let rest = line
                .strip_prefix("nameserver ")
                .expect("fallback line must be a nameserver directive");
            rest.parse::<std::net::IpAddr>()
                .expect("fallback nameserver must be a valid IP");
            nameservers += 1;
        }
        assert!(
            nameservers >= 1,
            "fallback resolv.conf must list at least one nameserver"
        );
    }

    #[test]
    fn marker_detected_with_crlf_line_endings() {
        // Some editors normalise to CRLF; the marker must still match since
        // we only check the prefix bytes.
        let bytes = b"# Generated by Mavi VPN - DO NOT EDIT\r\nnameserver 10.8.0.1\r\n";
        assert!(is_mavi_generated_resolv_conf(bytes));
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
