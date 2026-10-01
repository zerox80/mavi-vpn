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
            let output = runner.output("ip", &["-j", "-6", "route", "show", "exact", prefix])?;
            let routes: Vec<serde_json::Value> = serde_json::from_str(&output)?;
            let at_metric: Vec<_> = routes
                .iter()
                .filter(|route| route["metric"].as_u64() == Some(1))
                .collect();
            anyhow::ensure!(
                !at_metric.is_empty()
                    && at_metric.iter().all(|route| route["type"] == "unreachable"),
                "Existing IPv6 route {prefix} does not block traffic"
            );
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
                r#"[{"dst":"::/1","type":"unreachable","metric":1}]"#.into()
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
}
