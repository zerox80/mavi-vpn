//! Exercise route selection and ownership against the real kernel in a fresh
//! user/network namespace. No commands can alter the host network.
use super::command::{CommandRunner, ProductionCommandRunner};
use super::{cleanup_stale_routes, ipv6_block, routes};
use std::process::Command;

#[test]
fn preserves_foreign_blocks_and_connected_endpoint_paths() {
    const CHILD: &str = "MAVI_ROUTE_TEST_NAMESPACE";
    if std::env::var_os(CHILD).is_none() {
        let available = Command::new("unshare").args(["-Urn", "true"]).output();
        if !available.is_ok_and(|output| output.status.success()) {
            eprintln!("Skipping kernel route test: user/network namespaces unavailable");
            return;
        }
        let output = Command::new("unshare")
            .arg("-Urn")
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "network::kernel_tests::preserves_foreign_blocks_and_connected_endpoint_paths",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    let mut runner = ProductionCommandRunner;
    runner.run("ip", &["link", "set", "lo", "up"]).unwrap();
    runner
        .run(
            "ip",
            &[
                "link",
                "add",
                "mavi0",
                "type",
                "veth",
                "peer",
                "name",
                "mavi-peer",
            ],
        )
        .unwrap();
    for device in ["mavi0", "mavi-peer"] {
        runner.run("ip", &["link", "set", device, "up"]).unwrap();
    }
    for prefix in ipv6_block::PREFIXES {
        runner
            .run(
                "ip",
                &[
                    "-6",
                    "route",
                    "add",
                    "unreachable",
                    prefix,
                    "dev",
                    "mavi0",
                    "proto",
                    "99",
                    "metric",
                    "100",
                ],
            )
            .unwrap();
    }
    let foreign = runner
        .output("ip", &["-j", "-6", "route", "show", "proto", "99"])
        .unwrap();
    let mut owned = Vec::new();
    ipv6_block::install(&mut runner, &mut owned).unwrap();
    assert_eq!(owned.len(), 2);
    ipv6_block::remove(&mut runner, &owned);
    cleanup_stale_routes(&mut runner, "mavi0");
    runner.run("ip", &["link", "set", "mavi0", "up"]).unwrap();
    assert_eq!(
        runner
            .output("ip", &["-j", "-6", "route", "show", "proto", "99"])
            .unwrap(),
        foreign
    );
    assert_eq!(
        runner
            .output("ip", &["-j", "-6", "route", "show", "proto", "242"])
            .unwrap()
            .trim(),
        "[]"
    );

    runner
        .run(
            "ip",
            &[
                "link", "add", "eth0", "type", "veth", "peer", "name", "eth1",
            ],
        )
        .unwrap();
    for device in ["eth0", "eth1"] {
        runner.run("ip", &["link", "set", device, "up"]).unwrap();
    }
    runner
        .run("ip", &["addr", "add", "192.0.2.10/24", "dev", "eth0"])
        .unwrap();
    runner
        .run("ip", &["addr", "add", "192.168.20.10/24", "dev", "eth1"])
        .unwrap();
    runner
        .run(
            "ip",
            &["route", "add", "default", "via", "192.0.2.1", "dev", "eth0"],
        )
        .unwrap();
    runner
        .run(
            "ip",
            &[
                "route",
                "add",
                "203.0.113.0/24",
                "via",
                "192.168.20.1",
                "dev",
                "eth1",
            ],
        )
        .unwrap();
    runner
        .run(
            "ip",
            &[
                "-6",
                "addr",
                "add",
                "2001:db8:20::2/64",
                "dev",
                "eth1",
                "nodad",
            ],
        )
        .unwrap();
    runner
        .run(
            "ip",
            &["-6", "addr", "add", "fe80::2/64", "dev", "eth1", "nodad"],
        )
        .unwrap();
    runner
        .run(
            "ip",
            &[
                "-6",
                "route",
                "add",
                "2001:db8:30::/64",
                "via",
                "fe80::99",
                "dev",
                "eth1",
            ],
        )
        .unwrap();
    for (ip, expected_gateway) in [
        ("192.168.20.5", None),
        ("203.0.113.10", Some("192.168.20.1")),
        ("2001:db8:20::10", None),
        ("2001:db8:30::10", Some("fe80::99")),
    ] {
        let route = routes::resolve_host_route(&mut runner, ip.parse().unwrap()).unwrap();
        assert_eq!(route.gateway.as_deref(), expected_gateway);
        assert_eq!(route.device, "eth1");
        let owned = routes::add_host_route_exception(&mut runner, route)
            .unwrap()
            .unwrap();
        let selected = routes::resolve_host_route(&mut runner, ip.parse().unwrap()).unwrap();
        assert_eq!(selected.gateway.as_deref(), expected_gateway);
        routes::remove_host_route_exceptions(&mut runner, &[owned]);
    }

    // An existing split route must not outrank a newly installed leak block.
    runner
        .run(
            "ip",
            &[
                "-6", "route", "add", "::/1", "via", "fe80::99", "dev", "eth1", "metric", "2",
                "proto", "98",
            ],
        )
        .unwrap();
    let ip = "2001:db8:40::10".parse().unwrap();
    assert_eq!(
        routes::resolve_host_route(&mut runner, ip)
            .unwrap()
            .gateway
            .as_deref(),
        Some("fe80::99")
    );
    let mut blocks = Vec::new();
    ipv6_block::install(&mut runner, &mut blocks).unwrap();
    assert!(routes::resolve_host_route(&mut runner, ip).is_err());
    ipv6_block::remove(&mut runner, &blocks);
    assert_eq!(
        routes::resolve_host_route(&mut runner, ip)
            .unwrap()
            .gateway
            .as_deref(),
        Some("fe80::99")
    );
}
