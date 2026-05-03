//! # Linux Network Configuration
//!
//! Manages IP addresses, routes, MTU, and DNS settings for the VPN tunnel.
//! Uses `ip` commands for routing and supports both systemd-resolved and
//! direct /etc/resolv.conf manipulation for DNS.

use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::{info, warn};

mod command;
mod dns;
mod routes;

use command::{run_cmd, CommandRunner};

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
    #[allow(clippy::too_many_arguments)]
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
        let prefix_len = routes::netmask_to_prefix(netmask);

        let has_ipv6 = assigned_ipv6.is_some();

        // 5. Detect the physical gateway and device (before we add VPN routes)
        let (physical_gateway, physical_device) = routes::detect_physical_gateway();
        let (physical_gateway_v6, physical_device_v6) = routes::detect_physical_gateway_v6();

        // 6. Add host route exception for the VPN server IP via the physical gateway
        //    This prevents routing loops (VPN traffic going back into the tunnel).
        //    The endpoint may be IPv4 or IPv6, so route via the matching family.
        let mut runner = command::ProductionCommandRunner;
        apply_interface_and_routes(
            &mut runner,
            tun_name,
            assigned_ip,
            prefix_len,
            gateway,
            mtu,
            endpoint_ip,
            assigned_ipv6,
            netmask_v6,
            gateway_v6,
            physical_gateway.as_deref(),
            physical_device.as_deref(),
            physical_gateway_v6.as_deref(),
            physical_device_v6.as_deref(),
        )?;

        // 9. DNS configuration
        let (dns_backup, used_resolvconf) = dns::configure_dns(tun_name, dns, dns_v6)?;

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
        match routes::parse_endpoint_ip(&self.endpoint_ip) {
            Ok(IpAddr::V4(v4)) => {
                let _ = run_cmd("ip", &["route", "del", &format!("{}/32", v4)]);
            }
            Ok(IpAddr::V6(v6)) => {
                let _ = run_cmd("ip", &["-6", "route", "del", &format!("{}/128", v6)]);
            }
            Err(_) => {}
        }

        // Restore DNS
        dns::restore_dns(&self.dns_backup, self.used_resolvconf);

        // Bring down the TUN interface (kernel will clean up on close, but be explicit)
        let _ = run_cmd("ip", &["link", "set", &self.tun_name, "down"]);

        info!("Network cleanup complete.");
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_interface_and_routes<R: CommandRunner>(
    runner: &mut R,
    tun_name: &str,
    assigned_ip: Ipv4Addr,
    prefix_len: u8,
    gateway: Ipv4Addr,
    mtu: u16,
    endpoint_ip: &str,
    assigned_ipv6: Option<Ipv6Addr>,
    netmask_v6: Option<u8>,
    gateway_v6: Option<Ipv6Addr>,
    physical_gateway: Option<&str>,
    physical_device: Option<&str>,
    physical_gateway_v6: Option<&str>,
    physical_device_v6: Option<&str>,
) -> Result<()> {
    runner.run("ip", &["link", "set", tun_name, "up"])?;

    let mtu_str = mtu.to_string();
    info!("Setting TUN MTU: {} on {}", mtu, tun_name);
    runner.run("ip", &["link", "set", tun_name, "mtu", &mtu_str])?;

    let assigned = format!("{assigned_ip}/{prefix_len}");
    runner.run("ip", &["addr", "add", &assigned, "dev", tun_name])?;

    if let Some(ipv6) = assigned_ipv6 {
        let v6_prefix = netmask_v6.unwrap_or(64);
        let assigned_v6 = format!("{ipv6}/{v6_prefix}");
        runner.run("ip", &["-6", "addr", "add", &assigned_v6, "dev", tun_name])?;
    }

    add_endpoint_route_exception(
        runner,
        endpoint_ip,
        physical_gateway,
        physical_device,
        physical_gateway_v6,
        physical_device_v6,
    );

    let gateway_s = gateway.to_string();
    runner.run(
        "ip",
        &["route", "add", "0.0.0.0/1", "dev", tun_name, "via", &gateway_s],
    )?;
    runner.run(
        "ip",
        &[
            "route",
            "add",
            "128.0.0.0/1",
            "dev",
            tun_name,
            "via",
            &gateway_s,
        ],
    )?;

    if let Some(gv6) = gateway_v6 {
        let gv6_s = gv6.to_string();
        let _ = runner.run(
            "ip",
            &["-6", "route", "add", "::/1", "dev", tun_name, "via", &gv6_s],
        );
        let _ = runner.run(
            "ip",
            &[
                "-6",
                "route",
                "add",
                "8000::/1",
                "dev",
                tun_name,
                "via",
                &gv6_s,
            ],
        );
    }

    Ok(())
}

fn add_endpoint_route_exception<R: CommandRunner>(
    runner: &mut R,
    endpoint_ip: &str,
    physical_gateway: Option<&str>,
    physical_device: Option<&str>,
    physical_gateway_v6: Option<&str>,
    physical_device_v6: Option<&str>,
) {
    match routes::parse_endpoint_ip(endpoint_ip) {
        Ok(IpAddr::V4(v4)) => {
            if let (Some(gw), Some(dev)) = (physical_gateway, physical_device) {
                let route = format!("{v4}/32");
                let _ = runner.run("ip", &["route", "add", &route, "via", gw, "dev", dev]);
            } else {
                warn!(
                    "No physical IPv4 gateway detected; skipping host route exception for {}",
                    v4
                );
            }
        }
        Ok(IpAddr::V6(v6)) => {
            if let (Some(gw), Some(dev)) = (physical_gateway_v6, physical_device_v6) {
                let route = format!("{v6}/128");
                let _ = runner.run("ip", &["-6", "route", "add", &route, "via", gw, "dev", dev]);
            } else {
                warn!(
                    "No physical IPv6 gateway detected; skipping host route exception for {}",
                    v6
                );
            }
        }
        Err(e) => {
            warn!(
                "Could not parse endpoint IP {:?}: {}; skipping host route exception",
                endpoint_ip, e
            );
        }
    }
}

/// Best-effort cleanup for daemon repair requests and stale state after crashes.
/// This intentionally tolerates missing routes or DNS backups.
pub fn cleanup_stale_network_state() {
    info!("Cleaning stale MaviVPN network state...");

    let _ = run_cmd("ip", &["route", "del", "0.0.0.0/1"]);
    let _ = run_cmd("ip", &["route", "del", "128.0.0.0/1"]);
    let _ = run_cmd("ip", &["-6", "route", "del", "::/1"]);
    let _ = run_cmd("ip", &["-6", "route", "del", "8000::/1"]);
    let _ = run_cmd("ip", &["link", "set", "mavi0", "down"]);

    let current = std::fs::read(dns::RESOLV_CONF_PATH).ok();
    let mavi_owned = current
        .as_deref()
        .is_some_and(dns::is_mavi_generated_resolv_conf);
    if mavi_owned || dns::load_persistent_backup().is_some() {
        dns::restore_dns(&None, false);
    }

    info!("Stale MaviVPN network cleanup complete.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct RecordingRunner {
        calls: Vec<(String, Vec<String>)>,
    }

    impl CommandRunner for RecordingRunner {
        fn run(&mut self, cmd: &str, args: &[&str]) -> Result<()> {
            self.calls.push((
                cmd.to_string(),
                args.iter().map(|arg| (*arg).to_string()).collect(),
            ));
            Ok(())
        }
    }

    #[test]
    fn interface_and_routes_build_ipv4_route_exception() {
        let mut runner = RecordingRunner::default();

        apply_interface_and_routes(
            &mut runner,
            "mavi0",
            Ipv4Addr::new(10, 8, 0, 2),
            24,
            Ipv4Addr::new(10, 8, 0, 1),
            1280,
            "203.0.113.10",
            None,
            None,
            None,
            Some("192.0.2.1"),
            Some("eth0"),
            None,
            None,
        )
        .unwrap();

        assert!(runner.calls.contains(&(
            "ip".to_string(),
            vec!["link", "set", "mavi0", "up"]
                .into_iter()
                .map(String::from)
                .collect()
        )));
        assert!(runner.calls.contains(&(
            "ip".to_string(),
            vec![
                "route",
                "add",
                "203.0.113.10/32",
                "via",
                "192.0.2.1",
                "dev",
                "eth0"
            ]
            .into_iter()
            .map(String::from)
            .collect()
        )));
        assert!(runner.calls.contains(&(
            "ip".to_string(),
            vec!["route", "add", "0.0.0.0/1", "dev", "mavi0", "via", "10.8.0.1"]
                .into_iter()
                .map(String::from)
                .collect()
        )));
    }

    #[test]
    fn interface_and_routes_build_ipv6_address_and_exception() {
        let mut runner = RecordingRunner::default();

        apply_interface_and_routes(
            &mut runner,
            "mavi0",
            Ipv4Addr::new(10, 8, 0, 2),
            24,
            Ipv4Addr::new(10, 8, 0, 1),
            1340,
            "2001:db8::10",
            Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
            Some(64),
            Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
            None,
            None,
            Some("fe80::1"),
            Some("eth0"),
        )
        .unwrap();

        assert!(runner.calls.contains(&(
            "ip".to_string(),
            vec!["-6", "addr", "add", "fd00::2/64", "dev", "mavi0"]
                .into_iter()
                .map(String::from)
                .collect()
        )));
        assert!(runner.calls.contains(&(
            "ip".to_string(),
            vec![
                "-6",
                "route",
                "add",
                "2001:db8::10/128",
                "via",
                "fe80::1",
                "dev",
                "eth0"
            ]
            .into_iter()
            .map(String::from)
            .collect()
        )));
        assert!(runner.calls.contains(&(
            "ip".to_string(),
            vec!["-6", "route", "add", "::/1", "dev", "mavi0", "via", "fd00::1"]
                .into_iter()
                .map(String::from)
                .collect()
        )));
    }

    #[test]
    fn invalid_endpoint_skips_route_exception() {
        let mut runner = RecordingRunner::default();

        add_endpoint_route_exception(
            &mut runner,
            "vpn.example.com",
            Some("192.0.2.1"),
            Some("eth0"),
            Some("fe80::1"),
            Some("eth0"),
        );

        assert!(runner.calls.is_empty());
    }
}
