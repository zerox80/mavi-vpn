use super::*;
use crate::vpn_core::network::command_runner::test_support::RecordingRunner;

#[test]
fn dns_priority_and_nrpt_failures_are_permanent_setup_errors() {
    use crate::vpn_core::reconnect::{compute_reconnect_delay, ReconnectDecision};
    for results in [vec![false], vec![true, false], vec![true, true, false]] {
        let count = results.len();
        let runner = RecordingRunner::with_results(results);
        let error = configure_vpn_dns_preference_with_runner(
            &runner,
            7,
            Ipv4Addr::new(10, 8, 0, 1),
            Some("fd00::1".parse().unwrap()),
        )
        .unwrap_err();
        assert_eq!(runner.commands().len(), count);
        assert!(matches!(
            compute_reconnect_delay(Err(error), Duration::from_secs(1)),
            ReconnectDecision::PermanentFailure { .. }
        ));
    }
}

#[test]
fn nrpt_setup_propagates_powershell_errors_and_supports_both_dns_families() {
    use std::process::Command;
    for fail_step in ["", "get", "remove", "add", "clear"] {
        for dns_v6 in [None, Some("fd00::1".parse().unwrap())] {
            let script = include_str!("tests/nrpt_setup_mock.ps1")
                .replace("# FAIL_STEP", &format!("$global:failStep = '{fail_step}'"))
                .replace(
                    "# SETUP_SCRIPT",
                    &nrpt_setup_script(Ipv4Addr::new(10, 8, 0, 1), dns_v6),
                );
            let output = Command::new("powershell")
                .args(["-NoProfile", "-NonInteractive", "-Command", &script])
                .output()
                .unwrap();
            assert_eq!(
                output.status.success(),
                fail_step.is_empty(),
                "step={fail_step}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            if fail_step.is_empty() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                assert!(stdout.contains("10.8.0.1"));
                assert_eq!(stdout.contains("fd00::1"), dns_v6.is_some());
            }
        }
    }
}

#[test]
fn nrpt_cleanup_preserves_foreign_rules_and_removes_owned_rules() {
    use std::io::Write;
    use std::process::Command;
    let cleanup = nrpt_cleanup_script_for_path(Path::new(r"C:\mock\last_dns_servers.txt"));
    let script = include_str!("tests/nrpt_mock.ps1").replace("# CLEANUP_SCRIPT", &cleanup);
    let mut file = tempfile::Builder::new().suffix(".ps1").tempfile().unwrap();
    file.write_all(script.as_bytes()).unwrap();
    let path = file.into_temp_path();
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("ownership checks passed"));
}

#[test]
fn adapter_dns_cleanup_only_resets_mavi_adapters() {
    let script = mavi_adapter_dns_cleanup_script();

    assert!(script.contains("Set-DnsClientServerAddress"));
    assert!(script.contains("$_.Name -like 'MaviVPN*'"));
    assert!(script.contains("$_.InterfaceDescription -like '*Mavi VPN Tunnel*'"));
    assert!(script.contains("RegisterThisConnectionsAddress $false"));
    assert!(!script.contains("$_.Name -notlike 'MaviVPN*'"));
    assert!(!script.contains("RegisterThisConnectionsAddress $true"));
}

#[test]
fn powershell_single_quoted_wraps_value() {
    assert_eq!(powershell_single_quoted("hello"), "'hello'");
}

#[test]
fn powershell_single_quoted_escapes_single_quotes() {
    assert_eq!(powershell_single_quoted("it's a test"), "'it''s a test'");
}

#[test]
fn powershell_single_quoted_empty_string() {
    assert_eq!(powershell_single_quoted(""), "''");
}

#[test]
fn powershell_single_quoted_multiple_quotes() {
    assert_eq!(powershell_single_quoted("a'b'c"), "'a''b''c'");
}

#[test]
fn dns_servers_path_uses_programdata() {
    let path = dns_servers_path();
    assert!(path.to_string_lossy().contains("mavi-vpn"));
    assert!(path.to_string_lossy().contains("last_dns_servers.txt"));
}

#[test]
fn nrpt_cleanup_script_includes_persisted_path() {
    let script = nrpt_cleanup_script_for_path(Path::new(r"C:\custom\path\dns.txt"));
    assert!(script.contains(r"C:\custom\path\dns.txt"));
    assert!(script.contains("Test-Path"));
}

#[test]
fn nrpt_cleanup_script_handles_path_with_quotes() {
    let script = nrpt_cleanup_script_for_path(Path::new(r"C:\path with 'quotes'\dns.txt"));
    assert!(script.contains("''"));
}

#[test]
fn nrpt_cleanup_script_contains_all_registry_roots() {
    let script =
        nrpt_cleanup_script_for_path(Path::new(r"C:\ProgramData\mavi-vpn\last_dns_servers.txt"));
    assert!(
        script.contains(r"HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig")
    );
    assert!(script
        .contains(r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNSClient\DnsPolicyConfig"));
    assert!(script
        .contains(r"HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig"));
}

#[test]
fn nrpt_cleanup_script_clears_dns_cache() {
    let script =
        nrpt_cleanup_script_for_path(Path::new(r"C:\ProgramData\mavi-vpn\last_dns_servers.txt"));
    assert!(script.contains("Clear-DnsClientCache"));
    assert!(script.contains("Register-DnsClient"));
}

#[test]
fn nrpt_cleanup_script_checks_persisted_path() {
    let script =
        nrpt_cleanup_script_for_path(Path::new(r"C:\ProgramData\mavi-vpn\last_dns_servers.txt"));
    assert!(script.contains("Remove-Item -LiteralPath"));
    assert!(!script.contains("Get-Content"));
}

#[test]
fn nrpt_cleanup_script_handles_unc_path() {
    let script = nrpt_cleanup_script_for_path(Path::new(r"\\server\share\dns.txt"));
    assert!(script.contains(r"\\server\share\dns.txt"));
}

#[test]
fn mavi_adapter_dns_cleanup_sets_metric_9000() {
    let script = mavi_adapter_dns_cleanup_script();
    assert!(script.contains("InterfaceMetric 9000"));
    assert!(script.contains("AutomaticMetric Disabled"));
}

#[test]
fn mavi_adapter_dns_cleanup_clears_cache() {
    let script = mavi_adapter_dns_cleanup_script();
    assert!(script.contains("Clear-DnsClientCache"));
    assert!(script.contains("Register-DnsClient"));
}

#[test]
fn mavi_adapter_dns_cleanup_disables_dns_registration() {
    let script = mavi_adapter_dns_cleanup_script();
    assert!(script.contains("RegisterThisConnectionsAddress $false"));
}

#[test]
fn mavi_adapter_dns_cleanup_resets_dns_servers() {
    let script = mavi_adapter_dns_cleanup_script();
    assert!(script.contains("Set-DnsClientServerAddress"));
    assert!(script.contains("ResetServerAddresses"));
}

#[test]
fn mavi_adapter_dns_cleanup_includes_hidden_adapters() {
    let script = mavi_adapter_dns_cleanup_script();
    assert!(script.contains("Get-NetAdapter -IncludeHidden"));
}

#[test]
fn powershell_single_quoted_handles_backslashes() {
    assert_eq!(
        powershell_single_quoted(r"C:\path\to\file"),
        r"'C:\path\to\file'"
    );
}

#[test]
fn powershell_single_quoted_handles_newlines() {
    assert_eq!(powershell_single_quoted("line1\nline2"), "'line1\nline2'");
}

#[test]
fn powershell_single_quoted_handles_tabs() {
    assert_eq!(powershell_single_quoted("col1\tcol2"), "'col1\tcol2'");
}

#[test]
fn powershell_single_quoted_handles_unicode() {
    assert_eq!(powershell_single_quoted("Hello 世界"), "'Hello 世界'");
}

#[test]
fn powershell_single_quoted_handles_mixed_quotes_and_backslashes() {
    assert_eq!(
        powershell_single_quoted(r"C:\path'with\quotes"),
        r"'C:\path''with\quotes'"
    );
}

#[test]
fn dns_servers_path_ends_with_correct_filename() {
    let path = dns_servers_path();
    assert_eq!(path.file_name().unwrap(), "last_dns_servers.txt");
}

#[test]
fn dns_servers_path_contains_mavi_vpn_directory() {
    let path = dns_servers_path();
    let path_str = path.to_string_lossy();
    assert!(path_str.contains("mavi-vpn"));
}
