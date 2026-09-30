use anyhow::{Context, Result};
use std::process::Command;
use tracing::warn;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum CommandOutcome {
    Applied,
    AlreadyExists,
}

pub(super) trait CommandRunner {
    fn run_with_outcome(&mut self, cmd: &str, args: &[&str]) -> Result<CommandOutcome>;

    fn run(&mut self, cmd: &str, args: &[&str]) -> Result<()> {
        self.run_with_outcome(cmd, args).map(|_| ())
    }
}

#[derive(Default)]
pub(super) struct ProductionCommandRunner;

impl CommandRunner for ProductionCommandRunner {
    fn run_with_outcome(&mut self, cmd: &str, args: &[&str]) -> Result<CommandOutcome> {
        let output = Command::new(cmd)
            .args(args)
            .output()
            .with_context(|| format!("Failed to execute: {} {}", cmd, args.join(" ")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Existing resources are usable, but must not be claimed for cleanup.
            if cmd == "ip" && stderr.contains("RTNETLINK answers: File exists") {
                return Ok(CommandOutcome::AlreadyExists);
            }
            warn!("{} {} failed: {}", cmd, args.join(" "), stderr.trim());
            return Err(anyhow::anyhow!("{} failed: {}", cmd, stderr.trim()));
        }
        Ok(CommandOutcome::Applied)
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
    use super::{CommandOutcome, CommandRunner, Result};
    use std::collections::VecDeque;

    #[derive(Default)]
    pub(crate) struct RecordingRunner {
        pub(crate) calls: Vec<(String, Vec<String>)>,
        pub(crate) outcomes: VecDeque<Result<CommandOutcome>>,
    }

    impl CommandRunner for RecordingRunner {
        fn run_with_outcome(&mut self, cmd: &str, args: &[&str]) -> Result<CommandOutcome> {
            self.calls.push((
                cmd.to_string(),
                args.iter().map(|a| (*a).to_string()).collect(),
            ));
            self.outcomes
                .pop_front()
                .unwrap_or(Ok(CommandOutcome::Applied))
        }
    }
}
