use super::utils::{run_cmd, run_powershell_cmd};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CommandOutcome {
    success: bool,
    stderr: Option<String>,
}

impl CommandOutcome {
    pub(super) fn success() -> Self {
        Self {
            success: true,
            stderr: None,
        }
    }

    pub(super) fn failure(stderr: impl Into<String>) -> Self {
        Self {
            success: false,
            stderr: Some(stderr.into()),
        }
    }

    pub(super) fn from_success(success: bool) -> Self {
        Self {
            success,
            stderr: None,
        }
    }

    pub(super) fn is_success(&self) -> bool {
        self.success
    }

    pub(super) fn stderr(&self) -> Option<&str> {
        self.stderr.as_deref()
    }
}

impl From<bool> for CommandOutcome {
    fn from(success: bool) -> Self {
        Self::from_success(success)
    }
}

pub(super) trait CommandRunner {
    fn run_cmd_result(&self, program: &str, args: &[&str]) -> CommandOutcome;
    fn run_powershell_cmd_result(&self, label: &str, script: &str) -> CommandOutcome;

    fn run_cmd(&self, program: &str, args: &[&str]) -> bool {
        self.run_cmd_result(program, args).is_success()
    }

    fn run_powershell_cmd(&self, label: &str, script: &str) -> bool {
        self.run_powershell_cmd_result(label, script).is_success()
    }
}

pub(super) struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run_cmd_result(&self, program: &str, args: &[&str]) -> CommandOutcome {
        run_cmd(program, args).into()
    }

    fn run_powershell_cmd_result(&self, label: &str, script: &str) -> CommandOutcome {
        run_powershell_cmd(label, script).into()
    }
}

#[cfg(test)]
pub(super) mod test_support {
    use super::{CommandOutcome, CommandRunner};
    use std::cell::RefCell;
    use std::collections::VecDeque;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) enum RecordedCommand {
        Cmd { program: String, args: Vec<String> },
        PowerShell { label: String, script: String },
    }

    pub(crate) struct RecordingRunner {
        commands: RefCell<Vec<RecordedCommand>>,
        results: RefCell<VecDeque<CommandOutcome>>,
        default: CommandOutcome,
    }

    impl RecordingRunner {
        pub(crate) fn new(succeeds: bool) -> Self {
            Self {
                commands: RefCell::new(Vec::new()),
                results: RefCell::new(VecDeque::new()),
                default: CommandOutcome::from_success(succeeds),
            }
        }

        pub(crate) fn with_results(results: Vec<bool>) -> Self {
            Self {
                commands: RefCell::new(Vec::new()),
                results: RefCell::new(results.into_iter().map(CommandOutcome::from).collect()),
                default: CommandOutcome::failure("no recorded result"),
            }
        }

        pub(crate) fn commands(&self) -> Vec<RecordedCommand> {
            self.commands.borrow().to_vec()
        }

        fn next_result(&self) -> CommandOutcome {
            self.results
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| self.default.clone())
        }
    }

    impl CommandRunner for RecordingRunner {
        fn run_cmd_result(&self, program: &str, args: &[&str]) -> CommandOutcome {
            self.commands.borrow_mut().push(RecordedCommand::Cmd {
                program: program.to_string(),
                args: args.iter().map(|arg| (*arg).to_string()).collect(),
            });
            self.next_result()
        }

        fn run_powershell_cmd_result(&self, label: &str, script: &str) -> CommandOutcome {
            self.commands
                .borrow_mut()
                .push(RecordedCommand::PowerShell {
                    label: label.to_string(),
                    script: script.to_string(),
                });
            self.next_result()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CommandOutcome;

    #[test]
    fn command_outcome_tracks_success() {
        let outcome = CommandOutcome::success();
        assert!(outcome.is_success());
        assert!(outcome.stderr().is_none());
    }

    #[test]
    fn command_outcome_keeps_stderr_context() {
        let outcome = CommandOutcome::failure("access denied");
        assert!(!outcome.is_success());
        assert_eq!(outcome.stderr(), Some("access denied"));
    }
}
