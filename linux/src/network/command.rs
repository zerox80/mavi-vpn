use anyhow::{Context, Result};
use std::process::Command;
use tracing::warn;

pub(super) fn run_cmd(cmd: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("Failed to execute: {} {}", cmd, args.join(" ")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Don't fail on "RTNETLINK answers: File exists" (route already present)
        if stderr.contains("File exists") {
            return Ok(());
        }
        warn!("{} {} failed: {}", cmd, args.join(" "), stderr.trim());
        return Err(anyhow::anyhow!("{} failed: {}", cmd, stderr.trim()));
    }
    Ok(())
}
