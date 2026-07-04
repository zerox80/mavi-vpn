use super::adapter::{cleanup_mavi_adapter_dns_state, remove_nrpt_dns_rule};
use super::host_route::{clear_persisted_host_route, load_persisted_host_routes};
use super::ip::win32_cleanup_all_ips_on_interface;
use super::route::{
    cleanup_ipv6_prefix_policy, win32_cleanup_all_routes_on_interface, win32_delete_route,
};
use super::utils::{run_powershell_cmd, with_if_table};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;
use tracing::{debug, info};

pub fn cleanup_routes(host_routes: &[String]) {
    info!("Cleaning up MaviVPN routes...");
    cleanup_ipv6_prefix_policy();

    let started = Instant::now();

    // The two split-default routes may legitimately be absent (already torn down);
    // log a failure at debug so it never adds noise to normal cleanup.
    for prefix in [
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)),
    ] {
        if let Err(e) = win32_delete_route(0, prefix, 1) {
            debug!("split-default route {prefix}/1 not removed during cleanup: {e}");
        }
    }

    with_if_table(|rows| {
        for row in rows {
            let name = String::from_utf16_lossy(&row.Alias);
            if name.contains("MaviVPN") {
                win32_cleanup_all_routes_on_interface(row.InterfaceIndex);
                win32_cleanup_all_ips_on_interface(row.InterfaceIndex);
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        }
    });

    let mut host_prefixes: Vec<String> = host_routes.to_vec();
    for prefix in load_persisted_host_routes() {
        if !host_prefixes.contains(&prefix) {
            host_prefixes.push(prefix);
        }
    }

    if !host_prefixes.is_empty() {
        use std::fmt::Write;
        let mut ps_script = String::from("$ErrorActionPreference = 'SilentlyContinue'; ");
        for prefix in host_prefixes {
            let _ = write!(
                ps_script,
                "Remove-NetRoute -DestinationPrefix '{prefix}' -Confirm:$false; "
            );
        }
        let _ = run_powershell_cmd("Cleanup host routes", &ps_script);
    }

    info!(
        "Network cleanup completed in {} ms",
        started.elapsed().as_millis()
    );
    cleanup_mavi_adapter_dns_state();
    clear_persisted_host_route();
}

pub fn cleanup_stale_network_state() {
    cleanup_routes(&[]);
    remove_nrpt_dns_rule();
}
