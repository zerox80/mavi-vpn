use super::command_runner::{CommandRunner, SystemCommandRunner};

pub(super) fn configure_dns(adapter_name: &str) {
    configure_dns_with_runner(&SystemCommandRunner, adapter_name);
}

fn configure_dns_with_runner(runner: &dyn CommandRunner, adapter_name: &str) {
    runner.run_cmd(
        "netsh",
        &[
            "interface",
            "ipv4",
            "set",
            "dnsservers",
            adapter_name,
            "static",
            "1.1.1.1",
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
            "8.8.8.8",
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

        configure_dns_with_runner(&runner, "MaviVPN");

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
                        "1.1.1.1",
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
