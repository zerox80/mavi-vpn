use super::command_runner::{CommandRunner, SystemCommandRunner};
use super::utils::split_endpoint;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;
use tracing::warn;

/// Identity of a host route created by this process, retained for exact cleanup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRoute {
    pub(super) destination: IpAddr,
    pub(super) interface_index: u32,
    pub(super) next_hop: IpAddr,
}

impl HostRoute {
    pub(super) fn prefix(&self) -> String {
        format!(
            "{}/{}",
            self.destination,
            if self.destination.is_ipv4() { 32 } else { 128 }
        )
    }

    fn is_valid(&self) -> bool {
        self.interface_index > 0 && self.destination.is_ipv4() == self.next_hop.is_ipv4()
    }

    fn parse(record: &str) -> Option<Self> {
        let route: Self = serde_json::from_str(record).ok()?;
        route.is_valid().then_some(route)
    }
}

#[derive(Deserialize)]
struct HostRouteResult {
    #[serde(flatten)]
    route: HostRoute,
    created: bool,
}

pub(super) fn add_host_route_exception_fixed(endpoint: &str) -> Result<Option<HostRoute>> {
    let (host, _) = split_endpoint(endpoint);
    let host_ip = host
        .parse::<IpAddr>()
        .context("VPN endpoint must be a resolved IP address")?;
    add_host_route_exception_for_ip_with_runner(&SystemCommandRunner, host_ip, true)
}

/// Same as [`add_host_route_exception_fixed`], but for an already-resolved IP
/// (a split-tunnel whitelist domain) rather than the VPN endpoint's own
/// `host:port` string.
pub(super) fn add_host_route_exception_for_ip(ip: IpAddr) -> Result<Option<HostRoute>> {
    add_host_route_exception_for_ip_with_runner(&SystemCommandRunner, ip, true)
}

fn add_host_route_exception_for_ip_with_runner(
    runner: &dyn CommandRunner,
    host_ip: IpAddr,
    persist: bool,
) -> Result<Option<HostRoute>> {
    let (prefix, on_link) = match host_ip {
        IpAddr::V4(_) => (format!("{host_ip}/32"), "0.0.0.0"),
        IpAddr::V6(_) => (format!("{host_ip}/128"), "::"),
    };

    let script = format!(
        "$ErrorActionPreference = 'Stop'; \
         $gw = Find-NetRoute -RemoteIPAddress '{host_ip}' | Where-Object {{ $_.PSObject.Properties['DestinationPrefix'] }} | Select-Object -First 1; \
         $iface = if ($gw) {{ Get-NetAdapter -InterfaceIndex $gw.InterfaceIndex -ErrorAction SilentlyContinue }}; \
         if ($gw -and $iface -and $iface.Status -eq 'Up' -and $iface.Name -notlike 'MaviVPN*' -and $iface.InterfaceDescription -notlike '*WireGuard*') {{ \
             $nextHop = if ($gw.NextHop) {{ [string]$gw.NextHop }} else {{ '{on_link}' }}; \
             $args = @{{ \
                 DestinationPrefix = '{prefix}'; \
                 InterfaceIndex = $gw.InterfaceIndex; \
                 NextHop = $nextHop; \
                 PolicyStore = 'ActiveStore'; \
                 RouteMetric = 0; \
                 Confirm = $false; \
             }}; \
             $existing = Get-NetRoute -DestinationPrefix '{prefix}' -InterfaceIndex $gw.InterfaceIndex -NextHop $nextHop -PolicyStore ActiveStore -ErrorAction SilentlyContinue; \
             $created = -not [bool]$existing; \
             if ($created) {{ New-NetRoute @args | Out-Null }}; \
             [pscustomobject]@{{ destination = '{host_ip}'; interface_index = [uint32]$gw.InterfaceIndex; next_hop = $nextHop; created = $created }} | ConvertTo-Json -Compress \
         }} else {{ throw 'No physical route to {host_ip}' }}"
    );

    let outcome =
        runner.run_powershell_cmd_result(&format!("Add host exception for {prefix}"), &script);
    anyhow::ensure!(
        outcome.is_success(),
        "Failed to install host exception for {prefix}"
    );
    let record: HostRouteResult = serde_json::from_str(outcome.stdout().unwrap_or_default())
        .context("Missing host route ownership record")?;
    anyhow::ensure!(
        record.route.is_valid() && record.route.destination == host_ip,
        "Invalid host route ownership record"
    );
    if !record.created {
        // An existing exception is usable, but belongs to somebody else.
        return Ok(None);
    }
    if persist {
        persist_host_route(&record.route);
    }
    Ok(Some(record.route))
}

fn host_route_path() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from);
    base.join("mavi-vpn").join("last_host_route.txt")
}

/// Appends the route identity to the crash-recovery file so a route survives a service
/// crash (which skips `SessionRouteGuard`'s `Drop`) even when the session
/// installed several exceptions (the endpoint plus each whitelist domain).
fn persist_host_route(route: &HostRoute) {
    use std::io::Write;

    let path = host_route_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    else {
        return;
    };
    if let Ok(record) = serde_json::to_string(route) {
        let _ = writeln!(file, "{record}");
    }
}

pub(super) fn load_persisted_host_routes() -> Vec<HostRoute> {
    std::fs::read_to_string(host_route_path())
        .map(|contents| contents.lines().filter_map(|line| {
            let route = HostRoute::parse(line);
            if route.is_none() {
                warn!("Skipping legacy or invalid host route record: ownership cannot be established");
            }
            route
        }).collect())
        .unwrap_or_default()
}

pub(super) fn host_route_cleanup_script(routes: &[HostRoute]) -> String {
    use std::fmt::Write;
    let mut script = String::from("$ErrorActionPreference = 'SilentlyContinue'; ");
    for route in routes.iter().filter(|route| route.is_valid()) {
        let _ = write!(script,
            "Remove-NetRoute -DestinationPrefix '{}' -InterfaceIndex {} -NextHop '{}' -PolicyStore ActiveStore -Confirm:$false; ",
            route.prefix(), route.interface_index, route.next_hop);
    }
    script
}

pub(super) fn clear_persisted_host_route() {
    let _ = std::fs::remove_file(host_route_path());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vpn_core::network::command_runner::test_support::{
        RecordedCommand, RecordingRunner,
    };

    fn result_record(ip: &str, created: bool) -> String {
        let next_hop = if ip.contains(':') {
            "fe80::1"
        } else {
            "192.0.2.1"
        };
        serde_json::json!({"destination": ip, "interface_index": 7, "next_hop": next_hop, "created": created}).to_string()
    }

    #[test]
    fn host_route_exception_builds_ipv4_power_shell_plan() {
        let runner = RecordingRunner::with_stdout(&result_record("203.0.113.10", true));

        let prefix = add_host_route_exception_for_ip_with_runner(
            &runner,
            "203.0.113.10".parse().unwrap(),
            false,
        );

        assert_eq!(prefix.unwrap().unwrap().prefix(), "203.0.113.10/32");
        let commands = runner.commands();
        assert_eq!(commands.len(), 1);
        let RecordedCommand::PowerShell { label, script } = &commands[0] else {
            panic!("expected PowerShell command");
        };
        assert!(label.contains("203.0.113.10/32"));
        assert!(script.contains("DestinationPrefix = '203.0.113.10/32'"));
        assert!(script.contains("Find-NetRoute -RemoteIPAddress '203.0.113.10'"));
        assert!(script.contains("New-NetRoute @args"));
    }

    #[test]
    fn host_route_exception_builds_ipv6_power_shell_plan() {
        let runner = RecordingRunner::with_stdout(&result_record("2001:db8::10", true));

        let prefix = add_host_route_exception_for_ip_with_runner(
            &runner,
            "2001:db8::10".parse().unwrap(),
            false,
        );

        assert_eq!(prefix.unwrap().unwrap().prefix(), "2001:db8::10/128");
        let commands = runner.commands();
        let RecordedCommand::PowerShell { script, .. } = &commands[0] else {
            panic!("expected PowerShell command");
        };
        assert!(script.contains("DestinationPrefix = '2001:db8::10/128'"));
        assert!(script.contains("Find-NetRoute -RemoteIPAddress '2001:db8::10'"));
    }

    #[test]
    fn host_route_exception_reports_command_failure() {
        let runner = RecordingRunner::new(false);

        let prefix = add_host_route_exception_for_ip_with_runner(
            &runner,
            "203.0.113.10".parse().unwrap(),
            false,
        );

        assert!(prefix.is_err());
    }

    #[test]
    fn persisted_host_routes_require_valid_ownership() {
        for ip in ["203.0.113.10", "2001:0db8::10"] {
            let route = HostRoute::parse(&result_record(ip, true)).unwrap();
            assert_eq!(
                HostRoute::parse(&serde_json::to_string(&route).unwrap()),
                Some(route)
            );
        }
        assert!(HostRoute::parse("203.0.113.10/32").is_none());
        assert!(HostRoute::parse(
            r#"{"destination":"203.0.113.10","interface_index":0,"next_hop":"192.0.2.1"}"#
        )
        .is_none());
        assert!(HostRoute::parse(
            r#"{"destination":"203.0.113.10","interface_index":7,"next_hop":"::"}"#
        )
        .is_none());
        assert!(HostRoute::parse(r#"{"destination":"'; Remove-Item C:\\*; #","interface_index":7,"next_hop":"192.0.2.1"}"#).is_none());
    }

    #[test]
    fn existing_host_routes_are_reused_without_claiming_ownership() {
        let runner = RecordingRunner::with_stdout(&result_record("203.0.113.10", false));
        assert!(add_host_route_exception_for_ip_with_runner(
            &runner,
            "203.0.113.10".parse().unwrap(),
            false
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn cleanup_selects_each_owned_route_by_its_full_identity() {
        let route = HostRoute::parse(&result_record("203.0.113.10", true)).unwrap();
        let script = host_route_cleanup_script(&[route]);
        assert!(script.contains("-DestinationPrefix '203.0.113.10/32' -InterfaceIndex 7 -NextHop '192.0.2.1' -PolicyStore ActiveStore"));
    }

    #[test]
    fn powershell_add_and_cleanup_preserve_foreign_host_routes() {
        for (ip, next_hop, foreign_hop, default_prefix) in [
            ("203.0.113.10", "192.0.2.1", "192.0.2.99", "0.0.0.0/0"),
            ("2001:db8::10", "fe80::1", "fe80::99", "::/0"),
            ("192.168.20.5", "0.0.0.0", "192.0.2.99", "0.0.0.0/0"),
            ("2001:db8::10", "::", "fe80::99", "::/0"),
        ] {
            for existing in [false, true] {
                let record = serde_json::json!({"destination": ip, "interface_index": 7, "next_hop": next_hop, "created": !existing}).to_string();
                let runner = RecordingRunner::with_stdout(&record);
                let route = add_host_route_exception_for_ip_with_runner(
                    &runner,
                    ip.parse().unwrap(),
                    false,
                )
                .unwrap();
                let commands = runner.commands();
                let RecordedCommand::PowerShell {
                    script: add_script, ..
                } = &commands[0]
                else {
                    panic!("expected PowerShell")
                };
                let prefix = format!("{ip}/{}", if ip.contains(':') { 128 } else { 32 });
                let setup = format!("$targetPrefix='{prefix}'; $defaultPrefix='{default_prefix}'; $nextHop='{next_hop}'; $foreignNextHop='{foreign_hop}'; $existing=${existing}; $uninstaller=$false;");
                let mock = include_str!("host_route/tests/routes_mock.ps1")
                    .replace("# SETUP_SCRIPT", &setup)
                    .replace("# ADD_ROUTE_SCRIPT", add_script)
                    .replace(
                        "# CLEANUP_SCRIPT",
                        &host_route_cleanup_script(&route.into_iter().collect::<Vec<_>>()),
                    );
                let directory = tempfile::tempdir().unwrap();
                let path = directory.path().join("routes.ps1");
                std::fs::write(&path, mock).unwrap();
                let output = std::process::Command::new("powershell")
                    .args([
                        "-NoProfile",
                        "-NonInteractive",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                    ])
                    .arg(path)
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(String::from_utf8_lossy(&output.stdout)
                    .contains("host route ownership checks passed"));
            }
        }
    }
}
