#![cfg(windows)]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn invalid_command_exits_nonzero_without_waiting_for_enter() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_mavi-vpn-client"))
        .arg("invalid-command")
        // Keep stdin open: an unconditional Enter prompt would block here.
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if child.try_wait().unwrap().is_some() {
            let output = child.wait_with_output().unwrap();
            assert_eq!(output.status.code(), Some(1));
            assert!(String::from_utf8_lossy(&output.stderr).contains("Unknown command"));
            assert!(!String::from_utf8_lossy(&output.stdout).contains("Press Enter"));
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("CLI command did not exit while stdin remained open");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}
