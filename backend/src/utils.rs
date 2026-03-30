/// System helper to flush old iptables rules that might interfere with modern Mavi VPN routing.
pub fn cleanup_legacy_rules() {
    let _ = std::process::Command::new("iptables").args(&["-t", "mangle", "-F", "MAVI_CLAMP"]).output();
    let _ = std::process::Command::new("iptables").args(&["-t", "mangle", "-X", "MAVI_CLAMP"]).output();
}
