use super::command::CommandOutcome;
use super::*;

#[derive(Default)]
struct RecordingRunner {
    calls: Vec<(String, Vec<String>)>,
    fail_on_args: Option<Vec<String>>,
    existing_host_prefixes: Vec<String>,
}

impl CommandRunner for RecordingRunner {
    fn run_with_outcome(&mut self, cmd: &str, args: &[&str]) -> Result<CommandOutcome> {
        let args = args
            .iter()
            .map(|arg| (*arg).to_string())
            .collect::<Vec<_>>();
        self.calls.push((cmd.to_string(), args.clone()));
        if self.fail_on_args.as_ref().is_some_and(|fail| fail == &args) {
            anyhow::bail!("forced command failure");
        }
        if args.iter().any(|arg| arg == "add")
            && args
                .iter()
                .any(|arg| self.existing_host_prefixes.contains(arg))
        {
            return Ok(CommandOutcome::AlreadyExists);
        }
        Ok(CommandOutcome::Applied)
    }
}

#[test]
fn interface_and_routes_build_ipv4_route_exception() {
    let mut runner = RecordingRunner::default();
    apply_interface_and_routes(
        &mut runner,
        &mut Vec::new(),
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
    assert!(runner.calls.iter().any(|(_, args)| args
        == &[
            "route",
            "add",
            "203.0.113.10/32",
            "via",
            "192.0.2.1",
            "dev",
            "eth0"
        ]));
    assert!(runner.calls.iter().any(|(_, args)| args
        == &[
            "route",
            "add",
            "0.0.0.0/1",
            "dev",
            "mavi0",
            "via",
            "10.8.0.1"
        ]));
}

#[test]
fn interface_and_routes_block_ipv6_without_vpn_assignment() {
    let mut runner = RecordingRunner::default();
    apply_interface_and_routes(
        &mut runner,
        &mut Vec::new(),
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
    assert!(runner
        .calls
        .iter()
        .any(|(_, args)| args == &["-6", "route", "add", "unreachable", "::/1"]));
    assert!(runner
        .calls
        .iter()
        .any(|(_, args)| args == &["-6", "route", "add", "unreachable", "8000::/1"]));
}

#[test]
fn interface_and_routes_build_ipv6_address_and_exception() {
    let mut runner = RecordingRunner::default();
    apply_interface_and_routes(
        &mut runner,
        &mut Vec::new(),
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
    assert!(runner
        .calls
        .iter()
        .any(|(_, args)| args == &["-6", "addr", "add", "fd00::2/64", "dev", "mavi0"]));
    assert!(runner.calls.iter().any(|(_, args)| args
        == &[
            "-6",
            "route",
            "add",
            "2001:db8::10/128",
            "via",
            "fe80::1",
            "dev",
            "eth0"
        ]));
    assert!(
        runner
            .calls
            .iter()
            .any(|(_, args)| args
                == &["-6", "route", "add", "::/1", "dev", "mavi0", "via", "fd00::1"])
    );
    assert!(!runner
        .calls
        .iter()
        .any(|(_, args)| args.iter().any(|arg| arg == "unreachable")));
}

#[test]
fn interface_and_routes_fails_when_ipv6_split_route_fails() {
    let mut runner = RecordingRunner {
        fail_on_args: Some(
            vec![
                "-6", "route", "add", "::/1", "dev", "mavi0", "via", "fd00::1",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        ),
        ..RecordingRunner::default()
    };
    let err = apply_interface_and_routes(
        &mut runner,
        &mut Vec::new(),
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
    .unwrap_err();
    assert!(err
        .to_string()
        .contains("Failed to install IPv6 split route ::/1"));
}

#[test]
fn interface_and_routes_fails_when_ipv6_block_route_fails() {
    let mut runner = RecordingRunner {
        fail_on_args: Some(
            vec!["-6", "route", "add", "unreachable", "::/1"]
                .into_iter()
                .map(String::from)
                .collect(),
        ),
        ..RecordingRunner::default()
    };
    let err = apply_interface_and_routes(
        &mut runner,
        &mut Vec::new(),
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
    .unwrap_err();
    assert!(err
        .to_string()
        .contains("Failed to install IPv6 leak-prevention route ::/1"));
}

#[test]
fn invalid_endpoint_fails_before_split_routes_are_installed() {
    let mut runner = RecordingRunner::default();
    let err = add_endpoint_route_exception(
        &mut runner,
        "vpn.example.com",
        Some("192.0.2.1"),
        Some("eth0"),
        Some("fe80::1"),
        Some("eth0"),
    )
    .unwrap_err();
    assert!(runner.calls.is_empty());
    assert!(err.to_string().contains("Could not parse VPN endpoint IP"));
}

#[test]
fn interface_and_routes_requires_a_physical_interface_before_split_routes() {
    let mut runner = RecordingRunner::default();
    let err = apply_interface_and_routes(
        &mut runner,
        &mut Vec::new(),
        "mavi0",
        Ipv4Addr::new(10, 8, 0, 2),
        24,
        Ipv4Addr::new(10, 8, 0, 1),
        1280,
        "203.0.113.10",
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap_err();
    assert!(err
        .to_string()
        .contains("No physical interface found for host route exception"));
    assert!(!runner.calls.iter().any(|(_, args)| args
        .iter()
        .any(|arg| arg == "0.0.0.0/1" || arg == "128.0.0.0/1")));
}

#[test]
fn gatewayless_default_routes_allow_tunnel_setup() {
    for endpoint in ["203.0.113.10", "2001:db8::10"] {
        let mut runner = RecordingRunner::default();
        apply_interface_and_routes(
            &mut runner,
            &mut Vec::new(),
            "mavi0",
            Ipv4Addr::new(10, 8, 0, 2),
            24,
            Ipv4Addr::new(10, 8, 0, 1),
            1280,
            endpoint,
            Some("fd00::2".parse().unwrap()),
            Some(64),
            Some("fd00::1".parse().unwrap()),
            None,
            Some("ppp0"),
            None,
            Some("ppp0"),
        )
        .unwrap();
        let exception = runner
            .calls
            .iter()
            .position(|(_, args)| args.iter().any(|arg| arg == "ppp0"))
            .unwrap();
        let split_route = runner
            .calls
            .iter()
            .position(|(_, args)| args.iter().any(|arg| arg == "0.0.0.0/1"))
            .unwrap();
        assert!(exception < split_route);
        assert!(!runner.calls[exception].1.iter().any(|arg| arg == "via"));
    }
}

#[test]
fn endpoint_cleanup_preserves_existing_routes_on_success_and_rollback() {
    for endpoint in ["203.0.113.10", "2001:db8::10"] {
        for gatewayless in [false, true] {
            for existing in [false, true] {
                for fail_after_exception in [false, true] {
                    let prefix = format!(
                        "{endpoint}/{}",
                        if endpoint.contains(':') { 128 } else { 32 }
                    );
                    let mut runner = RecordingRunner {
                        existing_host_prefixes: if existing {
                            vec![prefix.clone()]
                        } else {
                            Vec::new()
                        },
                        fail_on_args: fail_after_exception.then(|| {
                            [
                                "route",
                                "add",
                                "0.0.0.0/1",
                                "dev",
                                "mavi0",
                                "via",
                                "10.8.0.1",
                            ]
                            .into_iter()
                            .map(String::from)
                            .collect()
                        }),
                        ..RecordingRunner::default()
                    };
                    let mut owned_routes = Vec::new();
                    let result = apply_interface_and_routes(
                        &mut runner,
                        &mut owned_routes,
                        "mavi0",
                        Ipv4Addr::new(10, 8, 0, 2),
                        24,
                        Ipv4Addr::new(10, 8, 0, 1),
                        1280,
                        endpoint,
                        Some("fd00::2".parse().unwrap()),
                        Some(64),
                        Some("fd00::1".parse().unwrap()),
                        (!gatewayless).then_some("192.0.2.1"),
                        Some("ppp0"),
                        (!gatewayless).then_some("fe80::1"),
                        Some("ppp0"),
                    );
                    assert_eq!(result.is_err(), fail_after_exception);
                    assert_eq!(owned_routes.len(), usize::from(!existing));

                    let setup_calls = runner.calls.len();
                    routes::remove_host_route_exceptions(&mut runner, &owned_routes);
                    let cleanup_calls = &runner.calls[setup_calls..];
                    assert_eq!(cleanup_calls.len(), usize::from(!existing));
                    if !existing {
                        assert!(cleanup_calls[0].1.contains(&prefix));
                        assert!(cleanup_calls[0].1.iter().any(|arg| arg == "ppp0"));
                        assert_eq!(
                            cleanup_calls[0].1.iter().any(|arg| arg == "via"),
                            !gatewayless
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn failure_before_endpoint_setup_has_no_host_routes_to_clean_up() {
    let mut runner = RecordingRunner {
        fail_on_args: Some(["link", "set", "mavi0", "up"].map(String::from).into()),
        ..RecordingRunner::default()
    };
    let mut owned_routes = Vec::new();
    assert!(apply_interface_and_routes(
        &mut runner,
        &mut owned_routes,
        "mavi0",
        Ipv4Addr::new(10, 8, 0, 2),
        24,
        Ipv4Addr::new(10, 8, 0, 1),
        1280,
        "203.0.113.10",
        None,
        None,
        None,
        None,
        Some("ppp0"),
        None,
        None,
    )
    .is_err());
    assert!(owned_routes.is_empty());
    let setup_calls = runner.calls.len();
    routes::remove_host_route_exceptions(&mut runner, &owned_routes);
    assert_eq!(runner.calls.len(), setup_calls);
}
