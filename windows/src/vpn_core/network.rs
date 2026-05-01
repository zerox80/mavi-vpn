use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::time::Instant;
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
            let msg = format!("[FAIL] {} â†’ {} {}", display, stdout, stderr);
            warn!(cmd = %msg);
            false
        }
        Err(e) => {
            let msg = format!("[ERR] {} â†’ {}", display, e);
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
            let msg = format!("[FAIL] {} â†’ {} {}", display, stdout, stderr);
            warn!(cmd = %msg);
            false
        }
        Err(e) => {
            let msg = format!("[ERR] {} â†’ {}", display, e);
            warn!(cmd = %msg);
            false
        }
    }
}

fn wait_for_adapter_alias(adapter_index: u32, requested_name: &str) -> Result<String> {
    let script = format!(
        "$ErrorActionPreference = 'Stop'; \
        for ($i = 0; $i -lt 300; $i++) {{ \
            $adapter = Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object InterfaceIndex -eq {adapter_index} | Select-Object -First 1; \
            if ($adapter) {{ \
                if ($adapter.Status -eq 'Disabled') {{ $adapter | Enable-NetAdapter -Confirm:$false -ErrorAction Stop | Out-Null }}; \
                Write-Output $adapter.Name; exit 0 \
            }}; \
            Start-Sleep -Milliseconds 100 \
        }}; \
        exit 1"
    );

    let started = Instant::now();
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()?;

    if !out.status.success() {
        anyhow::bail!(
            "Adapter '{}' (if={}) did not appear in Windows networking within 30 seconds.",
            requested_name,
            adapter_index
        );
    }

    let alias = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if alias.is_empty() {
        anyhow::bail!(
            "Adapter '{}' (if={}) appeared without a usable Windows alias.",
            requested_name,
            adapter_index
        );
    }

    if alias == requested_name {
        info!(
            "WinTUN adapter '{}' is visible/enabled in Windows (if={}, waited {} ms)",
            alias,
            adapter_index,
            started.elapsed().as_millis()
        );
    } else {
        info!(
            "WinTUN adapter requested as '{}' is visible in Windows as '{}' (if={}, waited {} ms)",
            requested_name,
            alias,
            adapter_index,
            started.elapsed().as_millis()
        );
    }
    Ok(alias)
}

fn wait_for_ipv4_address(adapter_index: u32, ip: Ipv4Addr) -> bool {
    let ip_str = ip.to_string();
    let script = format!(
        "for ($i = 0; $i -lt 50; $i++) {{ \
            $addr = Get-NetIPAddress -InterfaceIndex {adapter_index} -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object IPAddress -eq '{ip_str}' | Select-Object -First 1; \
            if ($addr) {{ Write-Output 'ok'; exit 0 }}; \
            Start-Sleep -Milliseconds 100 \
        }}; \
        exit 1"
    );

    std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .map(|out| out.status.success() && String::from_utf8_lossy(&out.stdout).contains("ok"))
        .unwrap_or(false)
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
    _dns_v6: Option<Ipv6Addr>,
) -> Result<Option<String>> {
    let requested_adapter_name = adapter.get_name().unwrap_or_else(|_| "MaviVPN".to_string());
    let adapter_index = adapter.get_adapter_index()?;
    let if_str = adapter_index.to_string();
    let ip_str = ip.to_string();
    let mask_str = netmask.to_string();
    let gw_str = gateway.to_string();
    let adapter_name = wait_for_adapter_alias(adapter_index, &requested_adapter_name)?;

    info!(
        "Configuring adapter '{}' (if={}) ip={} mask={} gw={} dns={}",
        adapter_name, adapter_index, ip, netmask, gateway, dns
    );

    // 1. Ensure adapter is administratively up once it is visible in the OS.
    // 2. Set IPv4 address â€” positional syntax is the most reliable across Windows versions.
    //    "netsh interface ipv4 set address <name> static <ip> <mask>"
    //    Do NOT set gateway here â€” we add split routes manually.
    let address_started = Instant::now();
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
            &gw_str,
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
                &gw_str,
            ],
        );
    }

    // Verify the IP was actually set
    if wait_for_ipv4_address(adapter_index, ip) {
        info!(
            "IP {} confirmed on adapter in {} ms",
            ip,
            address_started.elapsed().as_millis()
        );
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

    // 4. Set stable public DNS on the VPN adapter.
    //
    // The server-provided DNS can be unreachable or incompatible with Windows'
    // resolver, causing ERR_NAME_NOT_RESOLVED while the tunnel is connected.
    // Prefer known-good resolvers without installing a global NRPT "." rule.
    run_cmd(
        "netsh",
        &[
            "interface",
            "ipv4",
            "set",
            "dnsservers",
            &adapter_name,
            "static",
            "1.1.1.1",
            "primary",
            "validate=no",
        ],
    );
    run_cmd(
        "netsh",
        &[
            "interface",
            "ipv4",
            "add",
            "dnsservers",
            &adapter_name,
            "8.8.8.8",
            "index=2",
            "validate=no",
        ],
    );
    run_cmd(
        "netsh",
        &[
            "interface",
            "ipv6",
            "set",
            "dnsservers",
            &adapter_name,
            "static",
            "2606:4700:4700::1111",
            "primary",
            "validate=no",
        ],
    );
    run_cmd(
        "netsh",
        &[
            "interface",
            "ipv6",
            "add",
            "dnsservers",
            &adapter_name,
            "2001:4860:4860::8888",
            "index=2",
            "validate=no",
        ],
    );

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

    // 6. Host exception FIRST â€” must run before split routes so that
    //    Get-NetRoute still sees the real physical default route.
    let route_started = Instant::now();
    let endpoint_route = add_host_route_exception_fixed(endpoint);

    // 7. Split routes 0.0.0.0/1 + 128.0.0.0/1 â€” override default route without deleting it.
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
            info!(
                "Split routes confirmed (gateway {}, {} ms)",
                gw_str,
                route_started.elapsed().as_millis()
            );
        } else {
            warn!("Split routes NOT visible! Check 'route print' output");
        }
    }

    // 8. DNS preference: prefer the VPN adapter without installing a global
    // NRPT "." rule. A global rule can strand Windows name resolution on the
    // VPN DNS server and cause ERR_NAME_NOT_RESOLVED while connected.
    configure_vpn_dns_preference(&adapter_name, adapter_index);

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
    let cmd = "foreach ($prefix in @('::/1','8000::/1')) { \
        Get-NetRoute -DestinationPrefix $prefix -ErrorAction SilentlyContinue \
        | Where-Object { (Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -IncludeHidden -ErrorAction SilentlyContinue).Name -like 'MaviVPN*' } \
        | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue | Out-Null \
    }";
    let _ = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", cmd])
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

    let (ip_version, empty_next_hop) = match server_ip {
        IpAddr::V4(_) => ("4", "0.0.0.0"),
        IpAddr::V6(_) => ("6", "::"),
    };

    let ps = format!(
        "$gw = Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object {{ $_.InterfaceAlias -notlike 'MaviVPN*' -and $_.InterfaceAlias -notlike '*WireGuard*' -and $_.NextHop -ne '0.0.0.0' }} | Sort-Object InterfaceMetric, RouteMetric | Select-Object -First 1; \
        if ($gw) {{ \
            $hop = $gw.NextHop; \
            $ifIdx = $gw.InterfaceIndex; \
            if ($hop -and $hop -ne '{}') {{ \
                New-NetRoute -DestinationPrefix '{}' -InterfaceIndex $ifIdx -NextHop $hop -RouteMetric 1 -ErrorAction SilentlyContinue | Out-Null; \
                Write-Output $hop \
            }} else {{ \
                New-NetRoute -DestinationPrefix '{}' -InterfaceIndex $ifIdx -RouteMetric 1 -ErrorAction SilentlyContinue | Out-Null; \
                Write-Output 'On-Link' \
            }} \
        }}",
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

fn nrpt_cleanup_script() -> String {
    r#"
$ErrorActionPreference = 'SilentlyContinue'
$comment = '__NRPT_COMMENT__'

function Test-MaviVpnNrptRule {
    param($Rule)
    if ($null -eq $Rule) { return $false }
    if ($Rule.Comment -eq $comment) { return $true }

    # MaviVPN installs a global "." NRPT rule. After an interrupted shutdown this
    # can strand DNS on the VPN resolver, so startup/repair cleanup removes it
    # even if Windows did not preserve the Comment field.
    $namespaces = @($Rule.Namespace) | ForEach-Object { "$_" }
    if ($namespaces -contains '.') { return $true }

    return $false
}

Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
    Where-Object { Test-MaviVpnNrptRule $_ } |
    Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue

$policyRoots = @(
    'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNSClient\DnsPolicyConfig',
    'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig'
)

foreach ($root in $policyRoots) {
    if (-not (Test-Path $root)) { continue }
    Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
        $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        $name = "$($props.Name)"
        $namespace = "$($props.Namespace)"
        $ruleComment = "$($props.Comment)"
        if ($ruleComment -eq $comment -or $name -eq '.' -or $namespace -eq '.') {
            Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name DisableSmartNameResolution -ErrorAction SilentlyContinue
Remove-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name DisableParallelAandAAAA -ErrorAction SilentlyContinue

Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notlike 'MaviVPN*' -and $_.InterfaceDescription -notlike '*WireGuard*' } |
    ForEach-Object { Set-DnsClient -InterfaceIndex $_.ifIndex -RegisterThisConnectionsAddress $true -ErrorAction SilentlyContinue }

Clear-DnsClientCache -ErrorAction SilentlyContinue
"#
    .replace("__NRPT_COMMENT__", NRPT_COMMENT)
}

/// Prefer the VPN adapter's DNS without installing a global NRPT rule.
fn configure_vpn_dns_preference(adapter_name: &str, adapter_index: u32) {
    let started = Instant::now();
    let escaped_adapter_name = adapter_name.replace('\'', "''");

    let script = format!(
        "Add-DnsClientNrptRule -Namespace '.' -NameServers '1.1.1.1','8.8.8.8' -Comment '{}' -ErrorAction SilentlyContinue; \
        Get-NetIPInterface -InterfaceIndex {} -AddressFamily IPv4 -ErrorAction SilentlyContinue | Set-NetIPInterface -InterfaceMetric 1 -ErrorAction SilentlyContinue; \
        Get-NetIPInterface -InterfaceIndex {} -AddressFamily IPv6 -ErrorAction SilentlyContinue | Set-NetIPInterface -InterfaceMetric 1 -ErrorAction SilentlyContinue; \
        Get-NetAdapter -Name '{}' -ErrorAction SilentlyContinue | Set-NetIPInterface -InterfaceMetric 1 -ErrorAction SilentlyContinue; \
        New-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name DisableSmartNameResolution -PropertyType DWord -Value 1 -Force -ErrorAction SilentlyContinue | Out-Null; \
        Clear-DnsClientCache -ErrorAction SilentlyContinue; \
        Register-DnsClient -ErrorAction SilentlyContinue; \
        Start-Service -Name Dnscache -ErrorAction SilentlyContinue",
        NRPT_COMMENT,
        adapter_index,
        adapter_index,
        escaped_adapter_name
    );
    let _ = run_powershell_cmd("Configure VPN DNS preference", &script);

    info!(
        "VPN DNS preference configured without global NRPT ({} ms)",
        started.elapsed().as_millis()
    );
}

/// Cleans up NRPT rules and restores DNS settings on exit.
pub fn remove_nrpt_dns_rule() {
    let cmd = nrpt_cleanup_script();
    let _ = run_powershell_cmd("Remove DNS leak prevention", &cmd);

    info!("DNS leak prevention removed, normal DNS restored");
}

/// Emergency cleanup for startup, service stop/shutdown, repair commands, and uninstallers.
/// This is intentionally idempotent: every operation tolerates missing routes/rules.
pub fn cleanup_stale_network_state() {
    info!("Cleaning stale MaviVPN network state");
    cleanup_routes(None);
    remove_nrpt_dns_rule();
}
