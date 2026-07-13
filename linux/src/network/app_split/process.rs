use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::Path;

#[derive(Debug)]
pub(super) struct ProcessInfo {
    pub(super) pid: u32,
    pub(super) parent: u32,
    pub(super) uid: u32,
    pub(super) start_time: u64,
    pub(super) executable: String,
    pub(super) command: Vec<String>,
    pub(super) comm: Vec<u8>,
}

pub(super) fn scan_processes(uid: u32) -> Result<Vec<ProcessInfo>> {
    let mut processes = Vec::new();
    for entry in std::fs::read_dir("/proc")
        .context("Failed to read /proc")?
        .flatten()
    {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse().ok())
        else {
            continue;
        };
        let proc_dir = entry.path();
        let Ok(status) = std::fs::read_to_string(proc_dir.join("status")) else {
            continue;
        };
        if process_uid(&status) != Some(uid) {
            continue;
        }
        let Ok(stat) = std::fs::read_to_string(proc_dir.join("stat")) else {
            continue;
        };
        let Some((parent, start_time)) = process_stat(&stat) else {
            continue;
        };
        let executable = std::fs::read_link(proc_dir.join("exe"))
            .ok()
            .map(|path| {
                path.to_string_lossy()
                    .trim_end_matches(" (deleted)")
                    .to_string()
            })
            .unwrap_or_default();
        let command = std::fs::read(proc_dir.join("cmdline"))
            .ok()
            .map(|bytes| {
                bytes
                    .split(|byte| *byte == 0)
                    .filter(|part| !part.is_empty())
                    .map(|part| String::from_utf8_lossy(part).into_owned())
                    .collect()
            })
            .unwrap_or_default();
        let comm = std::fs::read(proc_dir.join("comm"))
            .unwrap_or_default()
            .into_iter()
            .take_while(|byte| *byte != b'\n')
            .collect();
        processes.push(ProcessInfo {
            pid,
            parent,
            uid,
            start_time,
            executable,
            command,
            comm,
        });
    }
    Ok(processes)
}

pub(super) fn selected_processes(
    processes: &[ProcessInfo],
    signatures: &[Vec<String>],
) -> HashSet<u32> {
    let mut selected = processes
        .iter()
        .filter(|process| signatures.iter().any(|rule| process_matches(process, rule)))
        .map(|process| process.pid)
        .collect::<HashSet<_>>();
    loop {
        let before = selected.len();
        for process in processes {
            if selected.contains(&process.parent) {
                selected.insert(process.pid);
            }
        }
        if selected.len() == before {
            return selected;
        }
    }
}

fn process_uid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn process_stat(stat: &str) -> Option<(u32, u64)> {
    // The command name is parenthesized and may contain spaces or ')', so
    // split only after the final closing parenthesis. Fields then start at #3.
    let tail = stat.rsplit_once(") ")?.1;
    let fields = tail.split_whitespace().collect::<Vec<_>>();
    let parent = fields.get(1)?.parse().ok()?; // field 4: ppid
    let start_time = fields.get(19)?.parse().ok()?; // field 22: starttime
    Some((parent, start_time))
}

fn process_matches(process: &ProcessInfo, signature: &[String]) -> bool {
    let Some(expected_executable) = signature.first() else {
        return false;
    };
    let executable_matches = if expected_executable.contains('/') {
        process.executable == *expected_executable
            || process.command.first() == Some(expected_executable)
    } else {
        Path::new(&process.executable)
            .file_name()
            .is_some_and(|name| name == expected_executable.as_str())
            || process.command.first().is_some_and(|argument| {
                Path::new(argument)
                    .file_name()
                    .is_some_and(|name| name == expected_executable.as_str())
            })
    };
    executable_matches
        && signature
            .iter()
            .skip(1)
            .zip(process.command.iter().skip(1))
            .all(|(expected, actual)| expected == actual)
        && process.command.len() >= signature.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(executable: &str, command: &[&str]) -> ProcessInfo {
        ProcessInfo {
            pid: 10,
            parent: 1,
            uid: 1000,
            start_time: 20,
            executable: executable.to_string(),
            command: command.iter().map(ToString::to_string).collect(),
            comm: b"test".to_vec(),
        }
    }

    #[test]
    fn parses_proc_stat_with_spaces_and_parentheses() {
        let stat = "123 (name with ) bracket) S 77 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 98765 0";
        assert_eq!(process_stat(stat), Some((77, 98765)));
    }

    #[test]
    fn matches_absolute_and_path_resolved_commands() {
        assert!(process_matches(
            &process("/usr/bin/firefox", &["firefox", "--private-window"]),
            &["/usr/bin/firefox".into()]
        ));
        assert!(process_matches(
            &process("/usr/bin/flatpak", &["flatpak", "run", "org.example.Chat"]),
            &["flatpak".into(), "run".into(), "org.example.Chat".into()]
        ));
        assert!(!process_matches(
            &process("/usr/bin/flatpak", &["flatpak", "run", "org.example.Other"]),
            &["flatpak".into(), "run".into(), "org.example.Chat".into()]
        ));
    }
}
