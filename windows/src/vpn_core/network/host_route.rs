use super::command_runner::{CommandRunner, SystemCommandRunner};
use super::utils::split_endpoint;
use std::net::IpAddr;
use std::path::PathBuf;

pub(super) fn add_host_route_exception_fixed(endpoint: &str) -> Option<String> {
    let (host, _) = split_endpoint(endpoint);
    let host_ip = host.parse::<IpAddr>().ok()?;
    add_host_route_exception_for_ip_with_runner(&SystemCommandRunner, host_ip, true)
}

/// Same as [`add_host_route_exception_fixed`], but for an already-resolved IP
/// (a split-tunnel whitelist domain) rather than the VPN endpoint's own
/// `host:port` string.
pub(super) fn add_host_route_exception_for_ip(ip: IpAddr) -> Option<String> {
    add_host_route_exception_for_ip_with_runner(&SystemCommandRunner, ip, true)
}

fn add_host_route_exception_for_ip_with_runner(
    runner: &dyn CommandRunner,
    host_ip: IpAddr,
    persist: bool,
) -> Option<String> {
    let (prefix, default_prefix) = match host_ip {
        IpAddr::V4(_) => (format!("{host_ip}/32"), "0.0.0.0/0"),
        IpAddr::V6(_) => (format!("{host_ip}/128"), "::/0"),
    };

    let script = format!(
        "$ErrorActionPreference = 'Stop'; \
         $gw = Get-NetRoute -DestinationPrefix '{default_prefix}' | Sort-Object RouteMetric | ForEach-Object {{ \
             $iface = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue; \
             if ($iface -and $iface.Status -eq 'Up' -and $iface.Name -notlike 'MaviVPN*' -and $iface.InterfaceDescription -notlike '*WireGuard*') {{ $_ }} \
         }} | Select-Object -First 1; \
         if ($gw) {{ \
             $args = @{{ \
                 DestinationPrefix = '{prefix}'; \
                 InterfaceIndex = $gw.InterfaceIndex; \
                 RouteMetric = 0; \
                 Confirm = $false; \
             }}; \
             if ($gw.NextHop -and $gw.NextHop -ne '0.0.0.0' -and $gw.NextHop -ne '::') {{ $args.NextHop = $gw.NextHop }}; \
             New-NetRoute @args; \
             if (-not (Get-NetRoute -DestinationPrefix '{prefix}' -ErrorAction SilentlyContinue)) {{ throw 'Verification failed' }} \
         }} else {{ throw 'No physical gateway for {default_prefix}' }}"
    );

    if runner.run_powershell_cmd(&format!("Add host exception for {prefix}"), &script) {
        if persist {
            persist_host_route(&prefix);
        }
        Some(prefix)
    } else {
        None
    }
}

fn host_route_path() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from);
    base.join("mavi-vpn").join("last_host_route.txt")
}

/// Appends `prefix` to the crash-recovery file so a route survives a service
/// crash (which skips `SessionRouteGuard`'s `Drop`) even when the session
/// installed several exceptions (the endpoint plus each whitelist domain).
fn persist_host_route(prefix: &str) {
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
    let _ = writeln!(file, "{prefix}");
}

pub(super) fn load_persisted_host_routes() -> Vec<String> {
    std::fs::read_to_string(host_route_path())
        .map(|contents| {
            contents
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
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

    #[test]
    fn host_route_exception_builds_ipv4_power_shell_plan() {
        let runner = RecordingRunner::new(true);

        let prefix = add_host_route_exception_for_ip_with_runner(
            &runner,
            "203.0.113.10".parse().unwrap(),
            false,
        );

        assert_eq!(prefix.as_deref(), Some("203.0.113.10/32"));
        let commands = runner.commands();
        assert_eq!(commands.len(), 1);
        let RecordedCommand::PowerShell { label, script } = &commands[0] else {
            panic!("expected PowerShell command");
        };
        assert!(label.contains("203.0.113.10/32"));
        assert!(script.contains("DestinationPrefix = '203.0.113.10/32'"));
        assert!(script.contains("Get-NetRoute -DestinationPrefix '0.0.0.0/0'"));
        assert!(script.contains("New-NetRoute @args"));
    }

    #[test]
    fn host_route_exception_builds_ipv6_power_shell_plan() {
        let runner = RecordingRunner::new(true);

        let prefix = add_host_route_exception_for_ip_with_runner(
            &runner,
            "2001:db8::10".parse().unwrap(),
            false,
        );

        assert_eq!(prefix.as_deref(), Some("2001:db8::10/128"));
        let commands = runner.commands();
        let RecordedCommand::PowerShell { script, .. } = &commands[0] else {
            panic!("expected PowerShell command");
        };
        assert!(script.contains("DestinationPrefix = '2001:db8::10/128'"));
        assert!(script.contains("Get-NetRoute -DestinationPrefix '::/0'"));
    }

    #[test]
    fn host_route_exception_returns_none_when_runner_fails() {
        let runner = RecordingRunner::new(false);

        let prefix = add_host_route_exception_for_ip_with_runner(
            &runner,
            "203.0.113.10".parse().unwrap(),
            false,
        );

        assert!(prefix.is_none());
    }
}
