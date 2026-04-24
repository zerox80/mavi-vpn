use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::time::Duration;
use tracing::{info, warn};
use wintun::Adapter;

pub struct SessionRouteGuard {
    host_route: Option<String>,
}

impl SessionRouteGuard {
    pub fn new(host_route: Option<String>) -> Self {
        Self { host_route }
    }
}

impl Drop for SessionRouteGuard {
    fn drop(&mut self) {
        cleanup_routes(self.host_route.as_deref());
    }
}

/// Creates a UDP socket configured for both IPv4 and IPv6 (dual-stack).
pub fn create_udp_socket() -> Result<std::net::UdpSocket> {
    let socket2_sock = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    // V6ONLY = false allows this socket to receive IPv4 traffic as well.
    socket2_sock.set_only_v6(false)?;
    socket2_sock.bind(&socket2::SockAddr::from(std::net::SocketAddrV6::new(
        std::net::Ipv6Addr::UNSPECIFIED,
        0,
        0,
        0,
    )))?;
    // Set larger socket buffers for high-throughput stability on Windows (4MB for GSO bursts)
    let _ = socket2_sock.set_send_buffer_size(4 * 1024 * 1024);
    let _ = socket2_sock.set_recv_buffer_size(4 * 1024 * 1024);

    Ok(socket2_sock.into())
}
/// Helper: run a command and log its outcome.
fn run_cmd(program: &str, args: &[&str]) -> bool {
    let display = format!("{} {}", program, args.join(" "));
    match std::process::Command::new(program).args(args).output() {
        Ok(out) if out.status.success() => {
            let msg = format!("[OK]  {}", display);
            info!(cmd = %msg);
            true
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let msg = format!("[FAIL] {} → {} {}", display, stdout, stderr);
            warn!(cmd = %msg);
            false
        }
        Err(e) => {
            let msg = format!("[ERR] {} → {}", display, e);
            warn!(cmd = %msg);
            false
        }
    }
}

fn run_powershell_cmd(display: &str, script: &str) -> bool {
    match std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .output()
    {
        Ok(out) if out.status.success() => {
            let msg = format!("[OK]  {}", display);
            info!(cmd = %msg);
            true
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let msg = format!("[FAIL] {} → {} {}", display, stdout, stderr);
            warn!(cmd = %msg);
            false
        }
        Err(e) => {
            let msg = format!("[ERR] {} → {}", display, e);
            warn!(cmd = %msg);
            false
        }
    }
}

fn adapter_alias_by_index(adapter_index: u32) -> Option<String> {
    let script = format!(
        "$adapter = Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object InterfaceIndex -eq {adapter_index} | Select-Object -First 1; if ($adapter) {{ $adapter.Name }}"
    );

    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .ok()?;

    if !out.status.success() {
        return None;
    }

    let alias = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if alias.is_empty() {
        None
    } else {
        Some(alias)
    }
}

fn wait_for_adapter_alias(adapter_index: u32, requested_name: &str) -> Result<String> {
    for attempt in 1..=30 {
        if let Some(alias) = adapter_alias_by_index(adapter_index) {
            if alias == requested_name {
                info!(
                    "WinTUN adapter '{}' is now visible in Windows (if={})",
                    alias, adapter_index
                );
            } else {
                info!(
                    "WinTUN adapter requested as '{}' is visible in Windows as '{}' (if={})",
                    requested_name, alias, adapter_index
                );
            }
            return Ok(alias);
        }

        info!(
            "Waiting for adapter interface index {} to become available (attempt {}/30)...",
            adapter_index, attempt
        );
        std::thread::sleep(Duration::from_millis(1000));
    }

    anyhow::bail!(
        "Adapter '{}' (if={}) did not appear in Windows networking within 30 seconds.",
        requested_name,
        adapter_index
    )
}

fn wait_for_ipv4_address(adapter_index: u32, ip: Ipv4Addr) -> bool {
    let ip_str = ip.to_string();
    let script = format!(
        "$addr = Get-NetIPAddress -InterfaceIndex {adapter_index} -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object IPAddress -eq '{ip_str}' | Select-Object -First 1; if ($addr) {{ 'ok' }}"
    );

    for _ in 0..10 {
        let out = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .output();

        if let Ok(out) = out {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                if text.contains("ok") {
                    return true;
                }
            }
        }

        std::thread::sleep(Duration::from_millis(500));
    }

    false
}

pub fn split_endpoint(endpoint: &str) -> (&str, Option<&str>) {
    if let Some(rest) = endpoint.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = &rest[..end];
            let port = rest[end + 1..].strip_prefix(':');
            return (host, port);
        }
    }

    if endpoint.matches(':').count() == 1 {
        if let Some((host, port)) = endpoint.rsplit_once(':') {
            return (host, Some(port));
        }
    }

    (endpoint, None)
}

/// Comprehensive helper to apply all Windows networking settings for the VPN.
#[allow(clippy::too_many_arguments)]
pub fn set_adapter_network_config(
    adapter: &Adapter,
    ip: Ipv4Addr,
    netmask: Ipv4Addr,
    gateway: Ipv4Addr,
    dns: Ipv4Addr,
    tun_mtu: u16,
    endpoint: &str,
    assigned_ipv6: Option<Ipv6Addr>,
    netmask_v6: Option<u8>,
    gateway_v6: Option<Ipv6Addr>,
    dns_v6: Option<Ipv6Addr>,
) -> Result<Option<String>> {
    let requested_adapter_name = adapter.get_name().unwrap_or_else(|_| "MaviVPN".to_string());
    let adapter_index = adapter.get_adapter_index()?;
    let if_str = adapter_index.to_string();
    let ip_str = ip.to_string();
    let mask_str = netmask.to_string();
    let gw_str = gateway.to_string();
    let dns_str = dns.to_string();
    let adapter_name = wait_for_adapter_alias(adapter_index, &requested_adapter_name)?;

    info!(
        "Configuring adapter '{}' (if={}) ip={} mask={} gw={} dns={}",
        adapter_name, adapter_index, ip, netmask, gateway, dns
    );

    // 1. Ensure adapter is administratively up once it is visible in the OS.
    let enable_script = format!(
        "$adapter = Get-NetAdapter -IncludeHidden -ErrorAction Stop | Where-Object InterfaceIndex -eq {adapter_index} | Select-Object -First 1; if (-not $adapter) {{ throw 'Adapter not found' }}; if ($adapter.Status -eq 'Disabled') {{ $adapter | Enable-NetAdapter -Confirm:$false -ErrorAction Stop | Out-Null }}"
    );
    let _ = run_powershell_cmd(
        &format!("Enable-NetAdapter ifIndex={}", adapter_index),
        &enable_script,
    );

    // 2. Set IPv4 address — positional syntax is the most reliable across Windows versions.
    //    "netsh interface ipv4 set address <name> static <ip> <mask>"
    //    Do NOT set gateway here — we add split routes manually.
    if !run_cmd(
        "netsh",
        &[
            "interface",
            "ipv4",
            "set",
            "address",
            &adapter_name,
            "static",
            &ip_str,
            &mask_str,
        ],
    ) {
        // Retry with "add" in case "set" fails on fresh adapter
        run_cmd(
            "netsh",
            &[
                "interface",
                "ipv4",
                "add",
                "address",
                &adapter_name,
                &ip_str,
                &mask_str,
            ],
        );
    }

    // Wait for Windows to register the on-link route for the new IP.
    info!("Waiting for IP to register on adapter...");
    std::thread::sleep(Duration::from_millis(500));

    // Verify the IP was actually set
    if wait_for_ipv4_address(adapter_index, ip) {
        info!("IP {} confirmed on adapter", ip);
    } else {
        anyhow::bail!(
            "IPv4 address {} was not applied to adapter '{}' (if={}). Aborting session setup.",
            ip,
            adapter_name,
            adapter_index
        );
    }

    // 3. Set IPv6 address if available
    if let (Some(ipv6), Some(plen)) = (assigned_ipv6, netmask_v6) {
        let ipv6_str = format!("{}/{}", ipv6, plen);
        run_cmd(
            "netsh",
            &[
                "interface",
                "ipv6",
                "add",
                "address",
                &adapter_name,
                &ipv6_str,
            ],
        );
    }

    // 4. Set DNS
    run_cmd(
        "netsh",
        &[
            "interface",
            "ipv4",
            "set",
            "dnsservers",
            &adapter_name,
            "static",
            &dns_str,
            "primary",
        ],
    );
    if let Some(dv6) = dns_v6 {
        let dv6_str = dv6.to_string();
        run_cmd(
            "netsh",
            &[
                "interface",
                "ipv6",
                "add",
                "dnsservers",
                &adapter_name,
                &dv6_str,
                "index=1",
            ],
        );
    }

    // 5. Set MTU from the operator-configured inner TUN MTU (default 1280).
    let _ = adapter.set_mtu(usize::from(tun_mtu));
    let mtu_val = format!("mtu={}", tun_mtu);
    run_cmd(
        "netsh",
        &[
            "interface",
            "ipv4",
            "set",
            "subinterface",
            &adapter_name,
            &mtu_val,
            "store=active",
        ],
    );
    run_cmd(
        "netsh",
        &[
            "interface",
            "ipv6",
            "set",
            "subinterface",
            &adapter_name,
            &mtu_val,
            "store=active",
        ],
    );

    // 6. Host exception FIRST — must run before split routes so that
    //    Get-NetRoute still sees the real physical default route.
    let endpoint_route = add_host_route_exception_fixed(endpoint);

    // 7. Split routes 0.0.0.0/1 + 128.0.0.0/1 — override default route without deleting it.
    run_cmd(
        "route",
        &[
            "add",
            "0.0.0.0",
            "mask",
            "128.0.0.0",
            &gw_str,
            "metric",
            "5",
            "if",
            &if_str,
        ],
    );
    run_cmd(
        "route",
        &[
            "add",
            "128.0.0.0",
            "mask",
            "128.0.0.0",
            &gw_str,
            "metric",
            "5",
            "if",
            &if_str,
        ],
    );

    if let Some(gv6) = gateway_v6 {
        let gv6_str = gv6.to_string();
        run_cmd(
            "netsh",
            &[
                "interface",
                "ipv6",
                "add",
                "route",
                "::/1",
                &adapter_name,
                &gv6_str,
            ],
        );
        run_cmd(
            "netsh",
            &[
                "interface",
                "ipv6",
                "add",
                "route",
                "8000::/1",
                &adapter_name,
                &gv6_str,
            ],
        );
    }

    // Verify routes were added
    let route_check = std::process::Command::new("route")
        .args(["print", "0.0.0.0"])
        .output();
    if let Ok(out) = route_check {
        let text = String::from_utf8_lossy(&out.stdout);
        if text.contains(&gw_str) {
            info!("Split routes confirmed (gateway {})", gw_str);
        } else {
            warn!("Split routes NOT visible! Check 'route print' output");
        }
    }

    // 8. DNS leak prevention (NRPT + SMHNR)
    set_nrpt_dns_rule(dns, dns_v6);

    info!(
        "Network config complete: endpoint_exception={}",
        endpoint_route.as_deref().unwrap_or("none")
    );
    Ok(endpoint_route)
}

/// Remove the two split-tunnel routes and the host exception.
/// Called both before a new session (stale cleanup) and on disconnect.
pub fn cleanup_routes(host_route: Option<&str>) {
    let _ = std::process::Command::new("route")
        .args(["delete", "0.0.0.0", "mask", "128.0.0.0"])
        .output();
    let _ = std::process::Command::new("route")
        .args(["delete", "128.0.0.0", "mask", "128.0.0.0"])
        .output();
    let mut host_routes = Vec::new();
    if let Some(prefix) = host_route {
        host_routes.push(prefix.to_string());
    }
    if let Some(prefix) = load_persisted_host_route() {
        if !host_routes.iter().any(|item| item == &prefix) {
            host_routes.push(prefix);
        }
    }
    for prefix in host_routes {
        let cmd = format!("Remove-NetRoute -DestinationPrefix '{}' -Confirm:$false -ErrorAction SilentlyContinue | Out-Null", prefix);
        let _ = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", &cmd])
            .output();
    }
    clear_persisted_host_route();
    let _ = std::process::Command::new("netsh")
        .args(["interface", "ipv6", "delete", "route", "::/1", "MaviVPN"])
        .output();
    let _ = std::process::Command::new("netsh")
        .args([
            "interface",
            "ipv6",
            "delete",
            "route",
            "8000::/1",
            "MaviVPN",
        ])
        .output();
}

fn persisted_host_route_path() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("mavi-vpn").join("last_host_route.txt")
}

fn load_persisted_host_route() -> Option<String> {
    std::fs::read_to_string(persisted_host_route_path())
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn persist_host_route(prefix: &str) {
    let path = persisted_host_route_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, prefix);
}

fn clear_persisted_host_route() {
    let _ = std::fs::remove_file(persisted_host_route_path());
}

fn add_host_route_exception_fixed(endpoint: &str) -> Option<String> {
    let server_ip: IpAddr = match endpoint.parse() {
        Ok(ip) => ip,
        Err(_) => {
            warn!(
                "Could not parse endpoint IP '{}' for host exception route",
                endpoint
            );
            return None;
        }
    };

    let route_prefix = match server_ip {
        IpAddr::V4(v4) => format!("{}/32", v4),
        IpAddr::V6(v6) => format!("{}/128", v6),
    };

    let (default_prefix, family, empty_next_hop) = match server_ip {
        IpAddr::V4(_) => ("0.0.0.0/0", "IPv4", "0.0.0.0"),
        IpAddr::V6(_) => ("::/0", "IPv6", "::"),
    };

    let ps = format!(
        "$best = Get-NetRoute -DestinationPrefix '{}' -AddressFamily {} \
        | Where-Object {{ (Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue).InterfaceDescription -notlike '*WireGuard*' -and \
          (Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue).Name -notlike 'MaviVPN*' }} \
        | Sort-Object {{ $_.RouteMetric + $_.InterfaceMetric }} \
        | Select-Object -First 1; \
        if ($best) {{ \
            if ($best.NextHop -and $best.NextHop -ne '{}') {{ \
                New-NetRoute -DestinationPrefix '{}' -InterfaceIndex $best.InterfaceIndex -NextHop $best.NextHop -RouteMetric 1 -ErrorAction SilentlyContinue | Out-Null; \
                Write-Output $best.NextHop \
            }} else {{ \
                New-NetRoute -DestinationPrefix '{}' -InterfaceIndex $best.InterfaceIndex -RouteMetric 1 -ErrorAction SilentlyContinue | Out-Null; \
                Write-Output 'On-Link' \
            }} \
        }}",
        default_prefix,
        family,
        empty_next_hop,
        route_prefix,
        route_prefix,
    );

    let output = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &ps])
        .output();

    if let Ok(out) = output {
        let gateway = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !gateway.is_empty() && gateway != empty_next_hop {
            persist_host_route(&route_prefix);
            info!("Host exception: {} -> {}", route_prefix, gateway);
            return Some(route_prefix);
        }
    }

    warn!("Could not determine physical gateway for host exception route");
    None
}

const NRPT_COMMENT: &str = "MaviVPN";

/// Configures NRPT (Name Resolution Policy Table) to force all DNS through the VPN.
/// This prevents DNS leaks where Windows might try local DNS even when the VPN is up.
fn set_nrpt_dns_rule(dns_v4: Ipv4Addr, dns_v6: Option<Ipv6Addr>) {
    let dns_servers = match dns_v6 {
        Some(v6) => format!("'{}','{}'", dns_v4, v6),
        None => format!("'{}'", dns_v4),
    };

    // 1. Add NRPT rule for the root namespace "." to capture all queries
    let nrpt_cmd = format!("Add-DnsClientNrptRule -Namespace '.' -NameServers {} -Comment '{}' -ErrorAction SilentlyContinue", dns_servers, NRPT_COMMENT);
    let _ = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &nrpt_cmd])
        .output();

    // 2. Disable Smart Multi-Homed Name Resolution (SMHNR)
    // Windows sends DNS queries over ALL adapters simultaneously for speed.
    // This is the #1 cause of DNS leaks - it bypasses NRPT and sends queries
    // to physical adapter DNS servers (like Google 8.8.8.8 or ISP DNS).
    let _ = std::process::Command::new("reg")
        .args([
            "add",
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
            "/v",
            "DisableSmartNameResolution",
            "/t",
            "REG_DWORD",
            "/d",
            "1",
            "/f",
        ])
        .output();
    // Also disable via the newer Group Policy path
    let _ = std::process::Command::new("reg")
        .args([
            "add",
            r"HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
            "/v",
            "DisableParallelAandAAAA",
            "/t",
            "REG_DWORD",
            "/d",
            "1",
            "/f",
        ])
        .output();

    // 3. Set VPN adapter to highest priority
    let _ = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-NetAdapter -Name 'MaviVPN*' | Set-NetIPInterface -InterfaceMetric 1",
        ])
        .output();

    // 4. Suppress DNS registration on physical adapters to prevent them from being used
    let _ = std::process::Command::new("powershell").args(["-NoProfile", "-Command",
        "Get-NetAdapter | Where-Object { $_.Name -notlike 'MaviVPN*' -and $_.Status -eq 'Up' } | ForEach-Object { Set-DnsClient -InterfaceIndex $_.ifIndex -RegisterThisConnectionsAddress $false -ErrorAction SilentlyContinue }"
    ]).output();

    // 5. Flush DNS cache and re-register to pick up the new NRPT rules
    let _ = std::process::Command::new("ipconfig")
        .args(["/flushdns"])
        .output();
    let _ = std::process::Command::new("ipconfig")
        .args(["/registerdns"])
        .output();

    // 6. Restart DNS Client service to ensure NRPT + SMHNR changes take effect
    let _ = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Restart-Service -Name Dnscache -Force -ErrorAction SilentlyContinue",
        ])
        .output();

    info!("DNS leak prevention configured: NRPT + SMHNR disabled");
}

/// Cleans up NRPT rules and restores DNS settings on exit.
pub fn remove_nrpt_dns_rule() {
    // 1. Remove NRPT rules
    let cmd = format!("Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq '{}' }} | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue", NRPT_COMMENT);
    let _ = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &cmd])
        .output();

    // 2. Re-enable Smart Multi-Homed Name Resolution
    let _ = std::process::Command::new("reg")
        .args([
            "delete",
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
            "/v",
            "DisableSmartNameResolution",
            "/f",
        ])
        .output();
    let _ = std::process::Command::new("reg")
        .args([
            "delete",
            r"HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
            "/v",
            "DisableParallelAandAAAA",
            "/f",
        ])
        .output();

    // 3. Restore DNS registration on physical adapters
    let _ = std::process::Command::new("powershell").args(["-NoProfile", "-Command",
        "Get-NetAdapter | Where-Object { $_.Name -notlike 'MaviVPN*' -and $_.Status -eq 'Up' } | ForEach-Object { Set-DnsClient -InterfaceIndex $_.ifIndex -RegisterThisConnectionsAddress $true -ErrorAction SilentlyContinue }"
    ]).output();

    // 4. Flush DNS cache
    let _ = std::process::Command::new("ipconfig")
        .args(["/flushdns"])
        .output();

    // 5. Restart DNS Client service to restore normal behavior
    let _ = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Restart-Service -Name Dnscache -Force -ErrorAction SilentlyContinue",
        ])
        .output();

    info!("DNS leak prevention removed, normal DNS restored");
}
