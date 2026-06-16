use anyhow::Result;
use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;
use tracing::{info, warn};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, DeleteIpForwardEntry2, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

use super::command_runner::{CommandRunner, SystemCommandRunner};
use super::utils::{
    to_sockaddr_inet, win_err, with_forward_table, ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS,
};

pub fn win32_add_route(
    adapter_index: u32,
    destination: IpAddr,
    prefix_len: u8,
    next_hop: Option<IpAddr>,
    metric: u32,
) -> Result<()> {
    // SAFETY: MIB_IPFORWARD_ROW2 is a plain-old-data Win32 struct with no invalid
    // bit patterns; zeroing it is the documented way to start a fresh entry, and
    // InitializeIpForwardEntry then fills in the sentinel defaults the API expects.
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpForwardEntry(&raw mut row) };

    row.InterfaceIndex = adapter_index;
    row.DestinationPrefix.Prefix = to_sockaddr_inet(destination);
    row.DestinationPrefix.PrefixLength = prefix_len;
    if let Some(hop) = next_hop {
        row.NextHop = to_sockaddr_inet(hop);
    }
    row.Metric = metric;

    let res = unsafe { CreateIpForwardEntry2(&raw const row) };
    if res == 0 || res == ERROR_OBJECT_ALREADY_EXISTS {
        Ok(())
    } else {
        Err(win_err(res))
    }
}

pub fn win32_delete_route(adapter_index: u32, destination: IpAddr, prefix_len: u8) -> Result<()> {
    // SAFETY: see `win32_add_route` — zeroing this POD struct and letting
    // InitializeIpForwardEntry seed its defaults is the documented setup.
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpForwardEntry(&raw mut row) };
    row.InterfaceIndex = adapter_index;
    row.DestinationPrefix.Prefix = to_sockaddr_inet(destination);
    row.DestinationPrefix.PrefixLength = prefix_len;

    let res = unsafe { DeleteIpForwardEntry2(&raw const row) };
    if res == 0 || res == ERROR_NOT_FOUND {
        Ok(())
    } else {
        Err(win_err(res))
    }
}

pub fn win32_cleanup_all_routes_on_interface(adapter_index: u32) {
    for family in [AF_INET, AF_INET6] {
        with_forward_table(family, |rows| {
            for row in rows {
                if row.InterfaceIndex == adapter_index {
                    // SAFETY: `row` points into the live table owned by the helper
                    // for the duration of this closure.
                    unsafe { DeleteIpForwardEntry2(row) };
                }
            }
        });
    }
}

pub fn verify_ipv6_split_routes(adapter_index: u32) -> Result<bool> {
    with_forward_table(AF_INET6, |rows| {
        let mut found_zero = false;
        let mut found_eight = false;

        for row in rows {
            if row.InterfaceIndex == adapter_index {
                let prefix = row.DestinationPrefix;
                // SAFETY: union access — IPv6 rows carry an Ipv6 sockaddr here.
                let addr_bytes = unsafe { prefix.Prefix.Ipv6.sin6_addr.u.Byte };
                let plen = prefix.PrefixLength;

                if plen == 1 && addr_bytes.iter().all(|&b| b == 0) {
                    found_zero = true;
                }
                if plen == 1 && addr_bytes[0] == 0x80 && addr_bytes[1..].iter().all(|&b| b == 0) {
                    found_eight = true;
                }
            }
        }

        found_zero && found_eight
    })
    .ok_or_else(|| anyhow::anyhow!("Failed to get IPv6 forward table"))
}

fn prefix_policy_path() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from);
    base.join("mavi-vpn").join("last_prefix_policy.txt")
}

fn persist_prefix_policy(prefix: &str) {
    let path = prefix_policy_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, prefix);
}

pub fn load_persisted_prefix_policy() -> Option<String> {
    std::fs::read_to_string(prefix_policy_path())
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub fn clear_persisted_prefix_policy() {
    let _ = std::fs::remove_file(prefix_policy_path());
}

pub fn apply_ipv6_prefix_policy(prefix: &str) -> bool {
    apply_ipv6_prefix_policy_with_runner(&SystemCommandRunner, prefix, true)
}

fn apply_ipv6_prefix_policy_with_runner(
    runner: &dyn CommandRunner,
    prefix: &str,
    persist: bool,
) -> bool {
    let set_ok = runner.run_cmd(
        "netsh",
        &[
            "interface",
            "ipv6",
            "set",
            "prefixpolicy",
            &format!("prefix={prefix}"),
            "precedence=100",
            "label=13",
            "store=active",
        ],
    );

    if set_ok {
        if persist {
            persist_prefix_policy(prefix);
        }
        info!("Applied IPv6 prefix policy with set: {}", prefix);
        return true;
    }

    let add_ok = runner.run_cmd(
        "netsh",
        &[
            "interface",
            "ipv6",
            "add",
            "prefixpolicy",
            &format!("prefix={prefix}"),
            "precedence=100",
            "label=13",
            "store=active",
        ],
    );

    if add_ok {
        if persist {
            persist_prefix_policy(prefix);
        }
        info!("Applied IPv6 prefix policy with add: {}", prefix);
    } else {
        warn!("Failed to apply IPv6 prefix policy: {}", prefix);
    }

    add_ok
}

pub fn cleanup_ipv6_prefix_policy() {
    if let Some(prefix) = load_persisted_prefix_policy() {
        let runner = SystemCommandRunner;
        let ok = runner.run_cmd(
            "netsh",
            &[
                "interface",
                "ipv6",
                "delete",
                "prefixpolicy",
                &format!("prefix={prefix}"),
            ],
        );

        if ok {
            info!("Removed MaviVPN IPv6 prefix policy: {}", prefix);
        } else {
            warn!("Failed to remove MaviVPN IPv6 prefix policy: {}", prefix);
        }

        clear_persisted_prefix_policy();
    }
}

pub fn ipv6_network_prefix(ip: Ipv6Addr, prefix_len: u8) -> String {
    let segments = ip.segments();
    let mut masked = [0u16; 8];
    let mut bits_left = prefix_len;
    for i in 0..8 {
        if bits_left >= 16 {
            masked[i] = segments[i];
            bits_left -= 16;
        } else if bits_left > 0 {
            let mask = 0xFFFFu16 << (16 - bits_left);
            masked[i] = segments[i] & mask;
            bits_left = 0;
        } else {
            masked[i] = 0;
        }
    }
    format!("{}/{}", Ipv6Addr::from(masked), prefix_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vpn_core::network::command_runner::test_support::{
        RecordedCommand, RecordingRunner,
    };

    #[test]
    fn prefix_policy_uses_set_command_first() {
        let runner = RecordingRunner::with_results(vec![true]);

        assert!(apply_ipv6_prefix_policy_with_runner(
            &runner,
            "fd00::/64",
            false
        ));

        assert_eq!(
            runner.commands(),
            vec![RecordedCommand::Cmd {
                program: "netsh".to_string(),
                args: vec![
                    "interface",
                    "ipv6",
                    "set",
                    "prefixpolicy",
                    "prefix=fd00::/64",
                    "precedence=100",
                    "label=13",
                    "store=active",
                ]
                .into_iter()
                .map(str::to_string)
                .collect(),
            }]
        );
    }

    #[test]
    fn prefix_policy_uses_shared_runner_command_shape() {
        let runner = RecordingRunner::new(true);

        assert!(apply_ipv6_prefix_policy_with_runner(
            &runner,
            "fd00::/64",
            false
        ));

        assert_eq!(
            runner.commands(),
            vec![RecordedCommand::Cmd {
                program: "netsh".to_string(),
                args: vec![
                    "interface",
                    "ipv6",
                    "set",
                    "prefixpolicy",
                    "prefix=fd00::/64",
                    "precedence=100",
                    "label=13",
                    "store=active",
                ]
                .into_iter()
                .map(str::to_string)
                .collect(),
            }]
        );
    }

    #[test]
    fn prefix_policy_falls_back_to_add_when_set_fails() {
        let runner = RecordingRunner::with_results(vec![false, true]);

        assert!(apply_ipv6_prefix_policy_with_runner(
            &runner,
            "fd00::/64",
            false
        ));

        let commands = runner.commands();
        assert_eq!(commands.len(), 2);
        assert_eq!(command_args(&commands[0])[2], "set");
        assert_eq!(command_args(&commands[1])[2], "add");
    }

    #[test]
    fn prefix_policy_reports_failure_when_set_and_add_fail() {
        let runner = RecordingRunner::with_results(vec![false, false]);

        assert!(!apply_ipv6_prefix_policy_with_runner(
            &runner,
            "fd00::/64",
            false
        ));
    }

    fn command_args(command: &RecordedCommand) -> &[String] {
        match command {
            RecordedCommand::Cmd { args, .. } => args,
            RecordedCommand::PowerShell { .. } => panic!("expected netsh command"),
        }
    }

    #[test]
    fn ipv6_network_prefix_full_64() {
        let ip = Ipv6Addr::new(
            0x2001, 0x0db8, 0x85a3, 0x1234, 0x5678, 0xabcd, 0xef01, 0x2345,
        );
        assert_eq!(ipv6_network_prefix(ip, 64), "2001:db8:85a3:1234::/64");
    }

    #[test]
    fn ipv6_network_prefix_full_128() {
        let ip = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        assert_eq!(ipv6_network_prefix(ip, 128), "2001:db8::1/128");
    }

    #[test]
    fn ipv6_network_prefix_zero() {
        let ip = Ipv6Addr::new(
            0x2001, 0x0db8, 0x85a3, 0x1234, 0x5678, 0xabcd, 0xef01, 0x2345,
        );
        assert_eq!(ipv6_network_prefix(ip, 0), "::/0");
    }

    #[test]
    fn ipv6_network_prefix_48() {
        let ip = Ipv6Addr::new(
            0x2001, 0x0db8, 0x85a3, 0x1234, 0x5678, 0xabcd, 0xef01, 0x2345,
        );
        assert_eq!(ipv6_network_prefix(ip, 48), "2001:db8:85a3::/48");
    }

    #[test]
    fn ipv6_network_prefix_partial_segment() {
        let ip = Ipv6Addr::new(0x2001, 0x0db8, 0xffff, 0, 0, 0, 0, 0);
        assert_eq!(ipv6_network_prefix(ip, 20), "2001::/20");
    }

    #[test]
    fn ipv6_network_prefix_loopback() {
        let ip = Ipv6Addr::LOCALHOST;
        assert_eq!(ipv6_network_prefix(ip, 128), "::1/128");
        assert_eq!(ipv6_network_prefix(ip, 64), "::/64");
    }

    #[test]
    fn prefix_policy_persist_and_load_roundtrip() {
        let temp = tempfile::tempdir().unwrap();
        let policy_path = temp.path().join("last_prefix_policy.txt");

        std::fs::write(&policy_path, "fd00::/64").unwrap();
        let loaded = std::fs::read_to_string(&policy_path)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        assert_eq!(loaded.as_deref(), Some("fd00::/64"));
    }

    #[test]
    fn prefix_policy_load_returns_none_for_empty_file() {
        let temp = tempfile::tempdir().unwrap();
        let policy_path = temp.path().join("last_prefix_policy.txt");

        std::fs::write(&policy_path, "   \n  ").unwrap();
        let loaded = std::fs::read_to_string(&policy_path)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        assert!(loaded.is_none());
    }
}
