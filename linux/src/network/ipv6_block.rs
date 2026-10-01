use super::command::{CommandOutcome, CommandRunner};
use anyhow::{Context, Result};

pub(super) const PREFIXES: [&str; 2] = ["::/1", "8000::/1"];
// Linux assigns unreachable IPv6 routes to lo, even when another dev is
// requested. The protocol marker identifies Mavi's blocks; metric 1 ensures
// they win over existing forwarding routes for the same prefix.
const PROTOCOL: &str = "242";
const METRIC: &str = "1";

pub(super) fn install(
    runner: &mut impl CommandRunner,
    owned: &mut Vec<&'static str>,
) -> Result<()> {
    for prefix in PREFIXES {
        let outcome = runner
            .run_with_outcome("ip", &args("add", prefix))
            .with_context(|| format!("Failed to install IPv6 leak-prevention route {prefix}"))?;
        if outcome == CommandOutcome::Applied {
            owned.push(prefix);
        } else {
            // A colliding unicast route must never be treated as a working
            // leak-prevention block. Reuse only an actual unreachable route.
            // Numeric output avoids local rt_protos aliases hiding our marker.
            let output = runner.output(
                "ip",
                &[
                    "-j", "-N", "-details", "-6", "route", "show", "exact", prefix,
                ],
            )?;
            let routes: Vec<serde_json::Value> = serde_json::from_str(&output)?;
            let at_metric: Vec<_> = routes
                .iter()
                .filter(|route| route["metric"].as_u64() == Some(1))
                .collect();
            anyhow::ensure!(
                !at_metric.is_empty() && at_metric.iter().all(|route| route["type"] == "7"),
                "Existing IPv6 route {prefix} does not block traffic"
            );
            if at_metric
                .iter()
                .any(|route| route["protocol"] == PROTOCOL && route["dev"] == "lo")
            {
                // A previous Mavi process may have crashed. The direct CLI has
                // no daemon cleanup after disconnect, so adopt our marked blocks.
                owned.push(prefix);
            }
        }
    }
    Ok(())
}

pub(super) fn remove(runner: &mut impl CommandRunner, prefixes: &[&str]) {
    for prefix in prefixes {
        let _ = runner.run("ip", &args("del", prefix));
    }
}

fn args<'a>(action: &'a str, prefix: &'a str) -> [&'a str; 11] {
    [
        "-6",
        "route",
        action,
        "unreachable",
        prefix,
        "dev",
        "lo",
        "proto",
        PROTOCOL,
        "metric",
        METRIC,
    ]
}

#[cfg(test)]
mod tests {
    use super::super::command::test_support::RecordingRunner;
    use super::*;

    #[test]
    fn existing_blocks_are_not_claimed_or_removed() {
        let mut runner = RecordingRunner {
            outcomes: [
                Ok(CommandOutcome::AlreadyExists),
                Ok(CommandOutcome::Applied),
            ]
            .into(),
            outputs: [Ok(
                r#"[{"dst":"::/1","type":"7","protocol":"99","dev":"lo","metric":1}]"#.into(),
            )]
            .into(),
            ..RecordingRunner::default()
        };
        let mut owned = Vec::new();
        install(&mut runner, &mut owned).unwrap();
        assert_eq!(owned, ["8000::/1"]);
        remove(&mut runner, &owned);
        assert_eq!(runner.calls.len(), 4);
        assert_eq!(runner.calls[3].1, args("del", "8000::/1"));
    }

    #[test]
    fn a_colliding_unicast_route_is_not_accepted_as_leak_prevention() {
        let mut runner = RecordingRunner {
            outcomes: [Ok(CommandOutcome::AlreadyExists)].into(),
            outputs: [Ok(r#"[{"dst":"::/1","dev":"eth0","metric":1}]"#.into())].into(),
            ..RecordingRunner::default()
        };
        let mut owned = Vec::new();
        assert!(install(&mut runner, &mut owned).is_err());
        assert!(owned.is_empty());
    }

    #[test]
    fn partial_failure_retains_exact_rollback_selectors() {
        let mut runner = RecordingRunner {
            outcomes: [
                Ok(CommandOutcome::Applied),
                Err(anyhow::anyhow!("route denied")),
            ]
            .into(),
            ..RecordingRunner::default()
        };
        let mut owned = Vec::new();
        assert!(install(&mut runner, &mut owned).is_err());
        assert_eq!(owned, ["::/1"]);
        remove(&mut runner, &owned);
        assert_eq!(runner.calls[2].1, args("del", "::/1"));
    }

    #[test]
    fn marked_blocks_from_a_crashed_session_are_cleaned_on_disconnect_and_rollback() {
        for fail_second in [false, true] {
            let mut runner = RecordingRunner {
                outcomes: [
                    Ok(CommandOutcome::AlreadyExists),
                    if fail_second {
                        Err(anyhow::anyhow!("route denied"))
                    } else {
                        Ok(CommandOutcome::AlreadyExists)
                    },
                ].into(),
                outputs: PREFIXES.map(|prefix| Ok(format!(
                    r#"[{{"dst":"{prefix}","type":"7","protocol":"242","dev":"lo","metric":1}}]"#
                ))).into(),
                ..RecordingRunner::default()
            };
            let mut owned = Vec::new();
            assert_eq!(install(&mut runner, &mut owned).is_err(), fail_second);
            assert_eq!(owned, PREFIXES[..if fail_second { 1 } else { 2 }]);
            let setup_calls = runner.calls.len();
            remove(&mut runner, &owned);
            for (call, prefix) in runner.calls[setup_calls..].iter().zip(owned) {
                assert_eq!(call.1, args("del", prefix));
            }
        }
    }
}
