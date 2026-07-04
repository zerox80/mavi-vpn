use anyhow::{Context, Result};
use std::process::Command;
use tracing::warn;

pub(super) trait CommandRunner {
    fn run(&mut self, cmd: &str, args: &[&str]) -> Result<()>;
}

#[derive(Default)]
pub(super) struct ProductionCommandRunner;

impl CommandRunner for ProductionCommandRunner {
    fn run(&mut self, cmd: &str, args: &[&str]) -> Result<()> {
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
}

pub(super) fn run_cmd(cmd: &str, args: &[&str]) -> Result<()> {
    let mut runner = ProductionCommandRunner;
    runner.run(cmd, args)
}

/// Records invocations instead of running them, shared by `routes` and
/// `whitelist`'s tests so each doesn't need its own copy.
#[cfg(test)]
pub(super) mod test_support {
    use super::{CommandRunner, Result};

    #[derive(Default)]
    pub(crate) struct RecordingRunner {
        pub(crate) calls: Vec<(String, Vec<String>)>,
    }

    impl CommandRunner for RecordingRunner {
        fn run(&mut self, cmd: &str, args: &[&str]) -> Result<()> {
            self.calls.push((
                cmd.to_string(),
                args.iter().map(|a| (*a).to_string()).collect(),
            ));
            Ok(())
        }
    }
}
