//! Pre-marker releases installed IPv6 blocks with iproute2's default protocol
//! and metric. They are indistinguishable from manually configured routes, so
//! removal requires the operator's explicit `repair --legacy-ipv6` opt-in.
use super::command::CommandRunner;
use super::ipv6_block::PREFIXES;
use anyhow::{Context, Result};

fn blocks(runner: &mut impl CommandRunner) -> Result<Vec<&'static str>> {
    let output = runner.output(
        "ip",
        &[
            "-j", "-N", "-details", "-6", "route", "show", "table", "main",
        ],
    )?;
    let routes: Vec<serde_json::Value> = serde_json::from_str(&output)
        .context("Could not inspect legacy IPv6 leak-prevention routes")?;
    Ok(PREFIXES
        .into_iter()
        .filter(|prefix| {
            routes.iter().any(|route| {
                route["dst"] == *prefix
                    && route["type"] == "7" // RTN_UNREACHABLE, numeric ip output
                    && route["dev"] == "lo"
                    && route["protocol"] == "3" // RTPROT_BOOT (iproute2 default)
                    && route["metric"].as_u64() == Some(1024)
            })
        })
        .collect())
}

pub(super) fn check(runner: &mut impl CommandRunner) -> Result<()> {
    anyhow::ensure!(
        blocks(runner)?.is_empty(),
        "Unmarked IPv6 /1 blocks remain. If left by an older Mavi VPN release, \
         stop all Mavi VPN connections and run `sudo mavi-vpn repair --legacy-ipv6`. \
         This opt-in also removes manually configured routes with the same defaults \
         (unreachable, dev lo, proto boot, metric 1024)."
    );
    Ok(())
}

pub(super) fn repair(runner: &mut impl CommandRunner) -> Result<usize> {
    let output = runner.output("ip", &["-j", "link", "show"])?;
    let links: Vec<serde_json::Value> = serde_json::from_str(&output)?;
    anyhow::ensure!(
        !links.iter().any(|link| link["ifname"] == "mavi0"),
        "mavi0 still exists; stop all Mavi VPN connections before repairing legacy IPv6 blocks"
    );
    let prefixes = blocks(runner)?;
    for prefix in &prefixes {
        runner
            .run(
                "ip",
                &[
                    "-6",
                    "route",
                    "del",
                    "unreachable",
                    prefix,
                    "table",
                    "main",
                    "dev",
                    "lo",
                    "proto",
                    "3",
                    "metric",
                    "1024",
                ],
            )
            .with_context(|| format!("Failed to remove legacy IPv6 block {prefix}"))?;
    }
    Ok(prefixes.len())
}

#[cfg(test)]
mod tests;
