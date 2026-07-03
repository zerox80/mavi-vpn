use super::command_runner::{CommandRunner, SystemCommandRunner};
use std::net::Ipv4Addr;

/// Secondary adapter-level resolver, used only if both the NRPT policy and
/// the primary (server-assigned) DNS are unreachable.
const SECONDARY_FALLBACK_DNS: &str = "8.8.8.8";

/// Sets the adapter's own DNS servers as a defense-in-depth fallback for the
/// NRPT policy installed by `configure_vpn_dns_preference`. The primary entry
/// must be the server-assigned resolver so the two layers agree: if NRPT ever
/// fails to apply, queries still go to the VPN's real DNS instead of a
/// different, possibly locally-censored or -monitored resolver.
pub(super) fn configure_dns(adapter_name: &str, dns_v4: Ipv4Addr) {
    configure_dns_with_runner(&SystemCommandRunner, adapter_name, dns_v4);
}

fn configure_dns_with_runner(runner: &dyn CommandRunner, adapter_name: &str, dns_v4: Ipv4Addr) {
    let primary = dns_v4.to_string();
    runner.run_cmd(
        "netsh",
        &[
            "interface",
            "ipv4",
            "set",
            "dnsservers",
            adapter_name,
            "static",
            &primary,
            "primary",
            "validate=no",
        ],
    );
    runner.run_cmd(
        "netsh",
        &[
            "interface",
            "ipv4",
            "add",
            "dnsservers",
            adapter_name,
            SECONDARY_FALLBACK_DNS,
            "index=2",
            "validate=no",
        ],
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vpn_core::network::command_runner::test_support::{
        RecordedCommand, RecordingRunner,
    };

    #[test]
    fn dns_configuration_uses_expected_netsh_commands() {
        let runner = RecordingRunner::new(true);

        configure_dns_with_runner(&runner, "MaviVPN", Ipv4Addr::new(10, 8, 0, 1));

        assert_eq!(
            runner.commands(),
            vec![
                RecordedCommand::Cmd {
                    program: "netsh".to_string(),
                    args: vec![
                        "interface",
                        "ipv4",
                        "set",
                        "dnsservers",
                        "MaviVPN",
                        "static",
                        "10.8.0.1",
                        "primary",
                        "validate=no",
                    ]
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
                },
                RecordedCommand::Cmd {
                    program: "netsh".to_string(),
                    args: vec![
                        "interface",
                        "ipv4",
                        "add",
                        "dnsservers",
                        "MaviVPN",
                        "8.8.8.8",
                        "index=2",
                        "validate=no",
                    ]
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
                },
            ]
        );
    }
}
