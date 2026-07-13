use super::*;

#[derive(Default)]
struct RecordingRunner {
    calls: Vec<(String, Vec<String>)>,
    fail_on_args: Option<Vec<String>>,
}

impl CommandRunner for RecordingRunner {
    fn run(&mut self, cmd: &str, args: &[&str]) -> Result<()> {
        let args = args
            .iter()
            .map(|arg| (*arg).to_string())
            .collect::<Vec<_>>();
        self.calls.push((cmd.to_string(), args.clone()));
        if self.fail_on_args.as_ref().is_some_and(|fail| fail == &args) {
            anyhow::bail!("forced command failure");
        }
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
        Ipv4Addr::new(10, 8, 0, 53),
        None,
        Some("192.0.2.1"),
        Some("eth0"),
        None,
        None,
        SplitTunnelMode::Disabled,
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
        Ipv4Addr::new(10, 8, 0, 53),
        Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 53)),
        None,
        None,
        Some("fe80::1"),
        Some("eth0"),
        SplitTunnelMode::Disabled,
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
        "mavi0",
        Ipv4Addr::new(10, 8, 0, 2),
        24,
        Ipv4Addr::new(10, 8, 0, 1),
        1340,
        "2001:db8::10",
        Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
        Some(64),
        Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
        Ipv4Addr::new(10, 8, 0, 53),
        Some(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 53)),
        None,
        None,
        Some("fe80::1"),
        Some("eth0"),
        SplitTunnelMode::Disabled,
    )
    .unwrap_err();
    assert!(err
        .to_string()
        .contains("Failed to install IPv6 split route ::/1"));
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
fn interface_and_routes_requires_a_physical_gateway_before_split_routes() {
    let mut runner = RecordingRunner::default();
    let err = apply_interface_and_routes(
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
        Ipv4Addr::new(10, 8, 0, 53),
        None,
        None,
        None,
        None,
        None,
        SplitTunnelMode::Disabled,
    )
    .unwrap_err();
    assert!(err
        .to_string()
        .contains("No physical IPv4 gateway found for host route exception"));
    assert!(!runner.calls.iter().any(|(_, args)| args
        .iter()
        .any(|arg| arg == "0.0.0.0/1" || arg == "128.0.0.0/1")));
}

#[test]
fn include_mode_only_installs_the_marked_vpn_default() {
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
        Ipv4Addr::new(10, 8, 0, 53),
        None,
        Some("192.0.2.1"),
        Some("eth0"),
        None,
        None,
        SplitTunnelMode::Include,
    )
    .unwrap();

    assert!(!runner
        .calls
        .iter()
        .any(|(_, args)| args.contains(&"0.0.0.0/1".to_string())));
    assert!(runner.calls.iter().any(|(_, args)| args
        == &[
            "route", "replace", "table", "42777", "default", "via", "10.8.0.1", "dev", "mavi0",
            "onlink"
        ]));
    assert!(runner
        .calls
        .iter()
        .any(|(_, args)| args.contains(&"fwmark".to_string())));
}

#[test]
fn exclude_mode_routes_marked_apps_physically_but_keeps_vpn_dns_reachable() {
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
        Ipv4Addr::new(10, 8, 0, 53),
        None,
        Some("192.0.2.1"),
        Some("eth0"),
        None,
        None,
        SplitTunnelMode::Exclude,
    )
    .unwrap();

    assert!(runner.calls.iter().any(|(_, args)| args
        == &[
            "route",
            "replace",
            "table",
            "42777",
            "default",
            "via",
            "192.0.2.1",
            "dev",
            "eth0"
        ]));
    assert!(runner.calls.iter().any(|(_, args)| args
        == &[
            "route",
            "replace",
            "table",
            "42777",
            "10.8.0.53/32",
            "via",
            "10.8.0.1",
            "dev",
            "mavi0",
            "onlink"
        ]));
}
