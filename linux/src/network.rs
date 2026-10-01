//! # Linux Network Configuration
//!
//! Manages IP addresses, routes, MTU, and DNS settings for the VPN tunnel.
//! Uses `ip` commands for routing and supports both systemd-resolved and
//! direct /etc/resolv.conf manipulation for DNS.

use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::info;

mod command;
mod dns;
mod ipv6_block;
mod legacy_ipv6;
mod routes;
mod whitelist;

use command::{run_cmd, CommandRunner};

/// Holds all state needed to cleanly tear down networking on exit.
pub struct NetworkConfig {
    pub tun_name: String,
    pub endpoint_ip: String,
    pub gateway_v4: Ipv4Addr,
    pub dns_backup: Option<Vec<u8>>,
    pub has_ipv6: bool,
    pub gateway_v6: Option<Ipv6Addr>,
    pub used_resolvconf: bool,
    /// Whether DNS was successfully changed by this instance. This prevents a
    /// rollback before DNS setup from writing a fallback resolver config.
    dns_configured: bool,
    /// Split-tunnel whitelist domain IPs resolved once at connect time.
    pub whitelist_ips: Vec<IpAddr>,
    /// Only newly installed exceptions belong to this session's cleanup.
    owned_host_routes: Vec<routes::HostRoute>,
    owned_ipv6_blocks: Vec<&'static str>,
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
        whitelist_domains: &[String],
    ) -> Result<Self> {
        let prefix_len = routes::netmask_to_prefix(netmask);

        let has_ipv6 = assigned_ipv6.is_some();

        // Resolve split-tunnel whitelist domains before DNS is redirected to
        // the tunnel below, so this still queries the physical (pre-VPN)
        // resolver.
        let whitelist_ips = whitelist::resolve_whitelist_ips(whitelist_domains, has_ipv6);

        // Capture all destination-specific paths before changing addresses or
        // routes; looking up whitelist paths after split routes would use mavi0.
        let mut runner = command::ProductionCommandRunner;
        let endpoint_route = resolve_endpoint_route(&mut runner, endpoint_ip)?;
        let whitelist_routes = whitelist::resolve_whitelist_routes(&mut runner, &whitelist_ips);

        let mut network = Self {
            tun_name: tun_name.to_string(),
            endpoint_ip: endpoint_ip.to_string(),
            gateway_v4: gateway,
            dns_backup: None,
            has_ipv6,
            gateway_v6,
            used_resolvconf: false,
            dns_configured: false,
            whitelist_ips,
            owned_host_routes: Vec::new(),
            owned_ipv6_blocks: Vec::new(),
        };

        // Add the endpoint exception before installing split-default routes.
        // If any setup step fails, immediately roll back every change already
        // made instead of leaving a half-configured tunnel behind.
        if let Err(err) = apply_interface_and_routes(
            &mut runner,
            &mut network.owned_host_routes,
            &mut network.owned_ipv6_blocks,
            tun_name,
            assigned_ip,
            prefix_len,
            gateway,
            mtu,
            endpoint_route,
            assigned_ipv6,
            netmask_v6,
            gateway_v6,
        ) {
            network.cleanup();
            return Err(err);
        }

        // 7. Except each resolved whitelist domain IP from the tunnel too.
        network
            .owned_host_routes
            .extend(whitelist::add_whitelist_route_exceptions(
                &mut runner,
                whitelist_routes,
            ));

        let (dns_backup, used_resolvconf) = match dns::configure_dns(tun_name, dns, dns_v6) {
            Ok(config) => config,
            Err(err) => {
                network.cleanup();
                return Err(err);
            }
        };
        network.dns_backup = dns_backup;
        network.used_resolvconf = used_resolvconf;
        network.dns_configured = true;

        info!(
            "Network configured: {} via {}, DNS={}",
            assigned_ip, tun_name, dns
        );

        Ok(network)
    }

    /// Tears down all VPN networking: removes routes, restores DNS.
    pub fn cleanup(&self) {
        info!("Cleaning up network configuration...");

        // Remove VPN routes
        let gateway_v4 = self.gateway_v4.to_string();
        let _ = run_cmd(
            "ip",
            &[
                "route",
                "del",
                "0.0.0.0/1",
                "dev",
                &self.tun_name,
                "via",
                &gateway_v4,
            ],
        );
        let _ = run_cmd(
            "ip",
            &[
                "route",
                "del",
                "128.0.0.0/1",
                "dev",
                &self.tun_name,
                "via",
                &gateway_v4,
            ],
        );

        if let Some(gateway_v6) = self.gateway_v6 {
            let gateway_v6 = gateway_v6.to_string();
            let _ = run_cmd(
                "ip",
                &[
                    "-6",
                    "route",
                    "del",
                    "::/1",
                    "dev",
                    &self.tun_name,
                    "via",
                    &gateway_v6,
                ],
            );
            let _ = run_cmd(
                "ip",
                &[
                    "-6",
                    "route",
                    "del",
                    "8000::/1",
                    "dev",
                    &self.tun_name,
                    "via",
                    &gateway_v6,
                ],
            );
        }
        ipv6_block::remove(
            &mut command::ProductionCommandRunner,
            &self.owned_ipv6_blocks,
        );

        routes::remove_host_route_exceptions(
            &mut command::ProductionCommandRunner,
            &self.owned_host_routes,
        );

        // Restore DNS
        if self.dns_configured {
            dns::restore_dns(&self.dns_backup, self.used_resolvconf);
        }

        // Bring down the TUN interface (kernel will clean up on close, but be explicit)
        let _ = run_cmd("ip", &["link", "set", &self.tun_name, "down"]);

        info!("Network cleanup complete.");
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_interface_and_routes<R: CommandRunner>(
    runner: &mut R,
    owned_host_routes: &mut Vec<routes::HostRoute>,
    owned_ipv6_blocks: &mut Vec<&'static str>,
    tun_name: &str,
    assigned_ip: Ipv4Addr,
    prefix_len: u8,
    gateway: Ipv4Addr,
    mtu: u16,
    endpoint_route: routes::HostRoute,
    assigned_ipv6: Option<Ipv6Addr>,
    netmask_v6: Option<u8>,
    gateway_v6: Option<Ipv6Addr>,
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

    if let Some(route) = routes::add_host_route_exception(runner, endpoint_route)? {
        // Record ownership before any later setup step can fail and roll back.
        owned_host_routes.push(route);
    }

    let gateway_s = gateway.to_string();
    runner.run(
        "ip",
        &[
            "route",
            "add",
            "0.0.0.0/1",
            "dev",
            tun_name,
            "via",
            &gateway_s,
        ],
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
        runner
            .run(
                "ip",
                &["-6", "route", "add", "::/1", "dev", tun_name, "via", &gv6_s],
            )
            .context("Failed to install IPv6 split route ::/1")?;
        runner
            .run(
                "ip",
                &[
                    "-6", "route", "add", "8000::/1", "dev", tun_name, "via", &gv6_s,
                ],
            )
            .context("Failed to install IPv6 split route 8000::/1")?;
    } else {
        ipv6_block::install(runner, owned_ipv6_blocks)?;
    }

    Ok(())
}

fn resolve_endpoint_route(
    runner: &mut impl CommandRunner,
    endpoint_ip: &str,
) -> Result<routes::HostRoute> {
    let endpoint = routes::parse_endpoint_ip(endpoint_ip)
        .with_context(|| format!("Could not parse VPN endpoint IP {endpoint_ip:?}"))?;
    routes::resolve_host_route(runner, endpoint)
}

/// Best-effort cleanup for daemon repair requests and stale state after crashes.
/// This intentionally tolerates missing routes or DNS backups.
pub fn cleanup_stale_network_state() -> Result<()> {
    info!("Cleaning stale MaviVPN network state...");

    cleanup_stale_routes(&mut command::ProductionCommandRunner, "mavi0");

    let current = std::fs::read(dns::RESOLV_CONF_PATH).ok();
    let mavi_owned = current
        .as_deref()
        .is_some_and(dns::is_mavi_generated_resolv_conf);
    if mavi_owned || dns::load_persistent_backup().is_some() {
        dns::restore_dns(&None, false);
    }

    legacy_ipv6::check(&mut command::ProductionCommandRunner)?;
    info!("Stale MaviVPN network cleanup complete.");
    Ok(())
}

/// Operator-approved migration for unmarked blocks from older releases.
pub fn repair_legacy_ipv6_blocks() -> Result<usize> {
    legacy_ipv6::repair(&mut command::ProductionCommandRunner)
}

fn cleanup_stale_routes(runner: &mut impl CommandRunner, tun_name: &str) {
    let _ = runner.run("ip", &["route", "del", "0.0.0.0/1", "dev", tun_name]);
    let _ = runner.run("ip", &["route", "del", "128.0.0.0/1", "dev", tun_name]);
    let _ = runner.run(
        "ip",
        &["-6", "route", "del", "unicast", "::/1", "dev", tun_name],
    );
    let _ = runner.run(
        "ip",
        &["-6", "route", "del", "unicast", "8000::/1", "dev", tun_name],
    );
    ipv6_block::remove(runner, &ipv6_block::PREFIXES);
    let _ = runner.run("ip", &["link", "set", tun_name, "down"]);
}

#[cfg(test)]
#[path = "network/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "network/kernel_tests.rs"]
mod kernel_tests;
