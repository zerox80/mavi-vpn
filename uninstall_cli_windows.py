#!/usr/bin/env python3
"""
Mavi VPN â€“ CLI Uninstaller (Windows)

Removes:
  MaviVPNService         Windows Service
  mavi-vpn-client.exe    CLI client
  mavi-vpn-service.exe   Service binary

Usage:
  python uninstall_cli_windows.py
"""

import os
import sys
import subprocess
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

NO_COLOR = not sys.stdout.isatty() or bool(os.environ.get("NO_COLOR"))

def c(code, text):    return text if NO_COLOR else f"\033[{code}m{text}\033[0m"
def info(msg):        print(c("1;36", "  â†’"), msg)
def ok(msg):          print(c("1;32", "  âœ“"), msg)
def warn(msg):        print(c("1;33", "  !"), msg)
def err(msg):         print(c("1;31", "  âœ—"), msg)
def step(msg):        print(c("1;37", f"\n[{msg}]"))

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(cmd, check=False):
    info(f"Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    return subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True)

def ask(question, default="y"):
    yn = "Y/n" if default == "y" else "y/N"
    answer = input(c("1;37", f"  ? {question} [{yn}]: ")).strip().lower()
    return (answer in ("y", "yes", "j", "ja")) if answer else (default == "y")

def repair_network_state():
    """Remove stale MaviVPN routes and DNS policy left by interrupted sessions."""
    ps = r"""
route delete 0.0.0.0 mask 128.0.0.0 2>$null | Out-Null
route delete 128.0.0.0 mask 128.0.0.0 2>$null | Out-Null
$persisted = Join-Path $env:ProgramData 'mavi-vpn\last_host_route.txt'
if (Test-Path $persisted) {
    $prefix = (Get-Content $persisted -Raw -ErrorAction SilentlyContinue).Trim()
    if ($prefix) {
        Remove-NetRoute -DestinationPrefix $prefix -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    }
    Remove-Item $persisted -Force -ErrorAction SilentlyContinue
}
foreach ($prefix in @('::/1','8000::/1')) {
    Get-NetRoute -DestinationPrefix $prefix -ErrorAction SilentlyContinue |
        Where-Object { (Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -IncludeHidden -ErrorAction SilentlyContinue).Name -like 'MaviVPN*' } |
        Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
}
Get-DnsClientNrptRule -ErrorAction SilentlyContinue |
    Where-Object { $_.Comment -eq 'MaviVPN' -or (@($_.Namespace) -contains '.') } |
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
        if ("$($props.Comment)" -eq 'MaviVPN' -or "$($props.Name)" -eq '.' -or "$($props.Namespace)" -eq '.') {
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
Register-DnsClient -ErrorAction SilentlyContinue
Start-Service -Name Dnscache -ErrorAction SilentlyContinue
"""
    info("Cleaning stale MaviVPN routes and DNS policy...")
    r = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
        capture_output=True,
        text=True,
    )
    if r.returncode == 0:
        ok("Network repair cleanup completed")
    else:
        warn("Network repair cleanup may be incomplete; try running as Administrator.")

# ---------------------------------------------------------------------------
# Service helpers
# ---------------------------------------------------------------------------

def stop_and_remove_service():
    """Stop service, kill processes, delete service registration."""
    r = subprocess.run(["sc", "query", "MaviVPNService"], capture_output=True, text=True)
    if r.returncode != 0:
        repair_network_state()
        ok("MaviVPNService not registered â€“ skipping.")
        return False

    info("MaviVPNService found.")

    if "RUNNING" in r.stdout:
        info("Stopping MaviVPNService...")
        subprocess.run(["net", "stop", "MaviVPNService"], capture_output=True)
        for _ in range(20):
            r2 = subprocess.run(["sc", "query", "MaviVPNService"], capture_output=True, text=True)
            if "STOPPED" in r2.stdout or r2.returncode != 0:
                break
            time.sleep(0.5)
        ok("Service stopped")

    repair_network_state()

    # Kill any remaining processes
    for proc in ["mavi-vpn-service.exe", "mavi-vpn-client.exe"]:
        subprocess.run(["taskkill", "/F", "/IM", proc], capture_output=True)

    time.sleep(1)

    # Delete service registration
    subprocess.run(["sc", "delete", "MaviVPNService"], capture_output=True)
    ok("Windows Service removed")
    return True

# ---------------------------------------------------------------------------
# PATH helpers
# ---------------------------------------------------------------------------

def remove_from_path(dir_to_remove):
    """Remove a directory from the system or user PATH via registry."""
    import winreg

    dir_str = str(dir_to_remove).rstrip("\\")

    for scope_name, hkey, subkey in [
        ("System", winreg.HKEY_LOCAL_MACHINE,
         r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
        ("User", winreg.HKEY_CURRENT_USER, r"Environment"),
    ]:
        try:
            with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
                current, _ = winreg.QueryValueEx(key, "Path")
                parts = [p for p in current.split(";") if p.strip()]
                new_parts = [p for p in parts if p.strip().rstrip("\\").lower() != dir_str.lower()]
                if len(new_parts) < len(parts):
                    winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, ";".join(new_parts))
                    ok(f"Removed from {scope_name} PATH: {dir_str}")
        except (FileNotFoundError, PermissionError):
            pass

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if sys.platform != "win32":
        err("This script is for Windows only.")
        err("For Linux use: python uninstall_cli_linux.py")
        sys.exit(1)

    print()
    print(c("1;36", "  â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—"))
    print(c("1;36", "  â•‘   Mavi VPN â€“ CLI Uninstaller (Windows)    â•‘"))
    print(c("1;36", "  â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•"))
    print()

    removed_anything = False

    # â”€â”€ Windows Service â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    step("Windows Service")
    if ask("Stop and remove MaviVPNService?"):
        if stop_and_remove_service():
            removed_anything = True

    # â”€â”€ Binaries â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    step("Binaries")
    default_dir = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "MaviVPN"

    # Try to find actual install location
    install_dir = None
    for candidate in [default_dir, Path(os.environ.get("LOCALAPPDATA", "")) / "MaviVPN"]:
        if candidate.exists() and (candidate / "mavi-vpn-client.exe").exists():
            install_dir = candidate
            break

    if install_dir is None:
        # Ask user
        raw = input(c("1;37", f"  ? Install directory [{default_dir}]: ")).strip()
        install_dir = Path(raw) if raw else default_dir

    binaries = ["mavi-vpn-client.exe", "mavi-vpn-service.exe"]
    found = [install_dir / b for b in binaries if (install_dir / b).exists()]

    if found:
        info(f"Found in: {install_dir}")
        for f in found:
            info(f"  {f.name}")
        if ask("Remove binaries?"):
            for f in found:
                try:
                    f.unlink()
                    ok(f"Removed: {f}")
                except PermissionError:
                    err(f"Cannot remove {f} â€“ file in use or missing permissions.")
                    warn("Try running as Administrator.")
            removed_anything = True

            # Remove directory if empty
            try:
                remaining = list(install_dir.iterdir())
                if not remaining:
                    install_dir.rmdir()
                    ok(f"Removed empty directory: {install_dir}")
            except OSError:
                pass
    else:
        ok(f"No binaries found in {install_dir} â€“ skipping.")

    # â”€â”€ PATH cleanup â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    step("PATH cleanup")
    if ask("Remove MaviVPN directory from system/user PATH?"):
        try:
            remove_from_path(install_dir)
            removed_anything = True
        except Exception as e:
            warn(f"Could not update PATH: {e}")

    # â”€â”€ Done â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    print()
    if removed_anything:
        ok("CLI uninstallation complete!")
    else:
        warn("Nothing was removed.")


if __name__ == "__main__":
    main()
