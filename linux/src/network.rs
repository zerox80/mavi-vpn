//! # Linux Network Configuration
//!
//! Manages IP addresses, routes, MTU, and DNS settings for the VPN tunnel.
//! Uses `ip` commands for routing and supports both systemd-resolved and
//! direct /etc/resolv.conf manipulation for DNS.

use anyhow::{Context, Result};
use shared::split_tunnel::{resolve_split_tunnel_targets, SplitRoute, SplitTunnelMode};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tracing::info;

mod command;
mod dns;
mod routes;
mod whitelist;

use command::{run_cmd, CommandRunner};

/// Holds all state needed to cleanly tear down networking on exit.
pub struct NetworkConfig {
    pub tun_name: String,
    pub endpoint_ip: String,
    pub gateway_v4: Ipv4Addr,
    pub physical_gateway: Option<String>,
    pub physical_device: Option<String>,
    pub physical_gateway_v6: Option<String>,
    pub physical_device_v6: Option<String>,
    pub dns_backup: Option<Vec<u8>>,
    pub has_ipv6: bool,
    pub gateway_v6: Option<Ipv6Addr>,
    pub used_resolvconf: bool,
    /// Whether DNS was successfully changed by this instance. This prevents a
    /// rollback before DNS setup from writing a fallback resolver config.
    dns_configured: bool,
    /// Split-tunnel whitelist domain IPs excepted from the tunnel via a host
    /// route, resolved once at connect time. Removed symmetrically in
    /// `cleanup()`.
    pub whitelist_ips: Vec<IpAddr>,
    pub split_tunnel_mode: SplitTunnelMode,
    pub split_routes: Vec<SplitRoute>,
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
        split_tunnel_mode: SplitTunnelMode,
        split_tunnel_targets: &[String],
    ) -> Result<Self> {
        let prefix_len = routes::netmask_to_prefix(netmask);

        let has_ipv6 = assigned_ipv6.is_some();

        // Resolve split-tunnel whitelist domains before DNS is redirected to
        // the tunnel below, so this still queries the physical (pre-VPN)
        // resolver.
        let whitelist_ips = whitelist::resolve_whitelist_ips(whitelist_domains, has_ipv6);
        let split_routes = resolve_split_tunnel_targets(split_tunnel_targets, has_ipv6)
            .map_err(anyhow::Error::msg)?;
        if split_tunnel_mode != SplitTunnelMode::Disabled && split_routes.is_empty() {
            anyhow::bail!("Split tunneling requires at least one usable target");
        }

        // 5. Detect the physical gateway and device (before we add VPN routes)
        let (physical_gateway, physical_device) = routes::detect_physical_gateway();
        let (physical_gateway_v6, physical_device_v6) = routes::detect_physical_gateway_v6();

        let mut network = Self {
            tun_name: tun_name.to_string(),
            endpoint_ip: endpoint_ip.to_string(),
            gateway_v4: gateway,
            physical_gateway,
            physical_device,
            physical_gateway_v6,
            physical_device_v6,
            dns_backup: None,
            has_ipv6,
            gateway_v6,
            used_resolvconf: false,
            dns_configured: false,
            whitelist_ips,
            split_tunnel_mode,
            split_routes,
        };

        // Add the endpoint exception before installing split-default routes.
        // If any setup step fails, immediately roll back every change already
        // made instead of leaving a half-configured tunnel behind.
        let mut runner = command::ProductionCommandRunner;
        if let Err(err) = apply_interface_and_routes(
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
            network.physical_gateway.as_deref(),
            network.physical_device.as_deref(),
            network.physical_gateway_v6.as_deref(),
            network.physical_device_v6.as_deref(),
            network.split_tunnel_mode,
            &network.split_routes,
        ) {
            network.cleanup();
            return Err(err);
        }

        // 7. Except each resolved whitelist domain IP from the tunnel too.
        if network.split_tunnel_mode != SplitTunnelMode::Include {
            whitelist::add_whitelist_route_exceptions(
                &mut runner,
                &network.whitelist_ips,
                network.physical_gateway.as_deref(),
                network.physical_device.as_deref(),
                network.physical_gateway_v6.as_deref(),
                network.physical_device_v6.as_deref(),
            );
        }

        if network.split_tunnel_mode != SplitTunnelMode::Include {
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
        }

        info!(
            "Network configured: {} via {}, DNS={}",
            assigned_ip, tun_name, dns
        );

        Ok(network)
    }

    /// Tears down all VPN networking: removes routes, restores DNS.
    pub fn cleanup(&self) {
        info!("Cleaning up network configuration...");

        if self.split_tunnel_mode == SplitTunnelMode::Include {
            for route in &self.split_routes {
                routes::remove_tunnel_route(
                    *route,
                    &self.tun_name,
                    self.gateway_v4,
                    self.gateway_v6,
                );
            }
        } else {
            remove_default_tunnel_routes(&self.tun_name, self.gateway_v4, self.gateway_v6);
        }

        if self.split_tunnel_mode == SplitTunnelMode::Exclude {
            for route in &self.split_routes {
                routes::remove_route_exception(
                    *route,
                    self.physical_gateway.as_deref(),
                    self.physical_device.as_deref(),
                    self.physical_gateway_v6.as_deref(),
                    self.physical_device_v6.as_deref(),
                );
            }
        }

        // Remove only the exact host-route exception we installed.
        if let Ok(endpoint_ip) = routes::parse_endpoint_ip(&self.endpoint_ip) {
            routes::remove_host_route_exception(
                endpoint_ip,
                self.physical_gateway.as_deref(),
                self.physical_device.as_deref(),
                self.physical_gateway_v6.as_deref(),
                self.physical_device_v6.as_deref(),
            );
        }

        // Remove each whitelist domain's route exception, symmetric with apply().
        if self.split_tunnel_mode != SplitTunnelMode::Include {
            whitelist::remove_whitelist_route_exceptions(
                &self.whitelist_ips,
                self.physical_gateway.as_deref(),
                self.physical_device.as_deref(),
                self.physical_gateway_v6.as_deref(),
                self.physical_device_v6.as_deref(),
            );
        }

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
    split_tunnel_mode: SplitTunnelMode,
    split_routes: &[SplitRoute],
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
    )?;

    if split_tunnel_mode == SplitTunnelMode::Include {
        for route in split_routes {
            routes::add_tunnel_route(runner, *route, tun_name, gateway, gateway_v6).with_context(
                || format!("Failed to install included VPN route {}", route.prefix()),
            )?;
        }
    } else {
        add_default_tunnel_routes(runner, tun_name, gateway, gateway_v6)?;
    }

    if split_tunnel_mode == SplitTunnelMode::Exclude {
        for route in split_routes {
            routes::add_route_exception(
                runner,
                *route,
                physical_gateway,
                physical_device,
                physical_gateway_v6,
                physical_device_v6,
            )
            .with_context(|| format!("Failed to exclude split-tunnel route {}", route.prefix()))?;
        }
    }

    Ok(())
}

fn add_default_tunnel_routes<R: CommandRunner>(
    runner: &mut R,
    tun_name: &str,
    gateway: Ipv4Addr,
    gateway_v6: Option<Ipv6Addr>,
) -> Result<()> {
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

    if let Some(gateway_v6) = gateway_v6 {
        let gateway_v6 = gateway_v6.to_string();
        runner
            .run(
                "ip",
                &[
                    "-6",
                    "route",
                    "add",
                    "::/1",
                    "dev",
                    tun_name,
                    "via",
                    &gateway_v6,
                ],
            )
            .context("Failed to install IPv6 split route ::/1")?;
        runner
            .run(
                "ip",
                &[
                    "-6",
                    "route",
                    "add",
                    "8000::/1",
                    "dev",
                    tun_name,
                    "via",
                    &gateway_v6,
                ],
            )
            .context("Failed to install IPv6 split route 8000::/1")?;
    }
    Ok(())
}

fn remove_default_tunnel_routes(
    tun_name: &str,
    gateway_v4: Ipv4Addr,
    gateway_v6: Option<Ipv6Addr>,
) {
    let gateway_v4 = gateway_v4.to_string();
    let _ = run_cmd(
        "ip",
        &[
            "route",
            "del",
            "0.0.0.0/1",
            "dev",
            tun_name,
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
            tun_name,
            "via",
            &gateway_v4,
        ],
    );
    if let Some(gateway_v6) = gateway_v6 {
        let gateway_v6 = gateway_v6.to_string();
        let _ = run_cmd(
            "ip",
            &[
                "-6",
                "route",
                "del",
                "::/1",
                "dev",
                tun_name,
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
                tun_name,
                "via",
                &gateway_v6,
            ],
        );
    }
}

fn add_endpoint_route_exception<R: CommandRunner>(
    runner: &mut R,
    endpoint_ip: &str,
    physical_gateway: Option<&str>,
    physical_device: Option<&str>,
    physical_gateway_v6: Option<&str>,
    physical_device_v6: Option<&str>,
) -> Result<()> {
    let ip = routes::parse_endpoint_ip(endpoint_ip)
        .with_context(|| format!("Could not parse VPN endpoint IP {endpoint_ip:?}"))?;
    routes::add_host_route_exception(
        runner,
        ip,
        physical_gateway,
        physical_device,
        physical_gateway_v6,
        physical_device_v6,
    )
}

/// Best-effort cleanup for daemon repair requests and stale state after crashes.
/// This intentionally tolerates missing routes or DNS backups.
pub fn cleanup_stale_network_state() {
    info!("Cleaning stale MaviVPN network state...");

    let _ = run_cmd("ip", &["route", "del", "0.0.0.0/1", "dev", "mavi0"]);
    let _ = run_cmd("ip", &["route", "del", "128.0.0.0/1", "dev", "mavi0"]);
    let _ = run_cmd("ip", &["-6", "route", "del", "::/1", "dev", "mavi0"]);
    let _ = run_cmd("ip", &["-6", "route", "del", "8000::/1", "dev", "mavi0"]);
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
#[path = "network/tests.rs"]
mod tests;
