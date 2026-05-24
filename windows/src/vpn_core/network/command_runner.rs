use super::utils::{run_cmd, run_powershell_cmd};

pub(super) trait CommandRunner {
    fn run_cmd(&self, program: &str, args: &[&str]) -> bool;
    fn run_powershell_cmd(&self, label: &str, script: &str) -> bool;
}

pub(super) struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run_cmd(&self, program: &str, args: &[&str]) -> bool {
        run_cmd(program, args)
    }

    fn run_powershell_cmd(&self, label: &str, script: &str) -> bool {
        run_powershell_cmd(label, script)
    }
}

#[cfg(test)]
pub(super) mod test_support {
    use super::CommandRunner;
    use std::cell::RefCell;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) enum RecordedCommand {
        Cmd { program: String, args: Vec<String> },
        PowerShell { label: String, script: String },
    }

    pub(crate) struct RecordingRunner {
        commands: RefCell<Vec<RecordedCommand>>,
        succeeds: bool,
    }

    impl RecordingRunner {
        pub(crate) fn new(succeeds: bool) -> Self {
            Self {
                commands: RefCell::new(Vec::new()),
                succeeds,
            }
        }

        pub(crate) fn commands(&self) -> Vec<RecordedCommand> {
            self.commands.borrow().to_vec()
        }
    }

    impl CommandRunner for RecordingRunner {
        fn run_cmd(&self, program: &str, args: &[&str]) -> bool {
            self.commands.borrow_mut().push(RecordedCommand::Cmd {
                program: program.to_string(),
                args: args.iter().map(|arg| (*arg).to_string()).collect(),
            });
            self.succeeds
        }

        fn run_powershell_cmd(&self, label: &str, script: &str) -> bool {
            self.commands
                .borrow_mut()
                .push(RecordedCommand::PowerShell {
                    label: label.to_string(),
                    script: script.to_string(),
                });
            self.succeeds
        }
    }
}
