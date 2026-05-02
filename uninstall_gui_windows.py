#!/usr/bin/env python3
"""
Mavi VPN - GUI Uninstaller (Windows)

Removes:
  mavi-vpn-gui.exe   Tauri GUI binary
  Desktop shortcut    Mavi VPN.lnk
  NSIS installation   (via built-in uninstaller)

Usage:
  python uninstall_gui_windows.py
"""

import ctypes
import os
import sys
import subprocess
from pathlib import Path

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

NO_COLOR = not sys.stdout.isatty() or bool(os.environ.get("NO_COLOR"))


def c(code, text):
    return text if NO_COLOR else f"\033[{code}m{text}\033[0m"


def info(msg):
    print(c("1;36", "  ->"), msg)


def ok(msg):
    print(c("1;32", "  [OK]"), msg)


def warn(msg):
    print(c("1;33", "  [!]"), msg)


def err(msg):
    print(c("1;31", "  [X]"), msg)


def step(msg):
    print(c("1;37", f"\n### {msg} ###"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def run_elevated(exe: str, args: str = ""):
    """Launch an executable with UAC elevation (RunAs)."""
    info(f"Requesting admin elevation for: {exe}")
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", str(exe), args, "", 1  # SW_SHOWNORMAL
    )
    return ret > 32


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
# NSIS uninstaller detection
# ---------------------------------------------------------------------------

def find_nsis_uninstaller():
    """Search the Windows registry for NSIS uninstaller."""
    try:
        import winreg
    except ImportError:
        return None

    # NSIS registers under Uninstall in the registry
    uninstall_keys = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]

    for hkey, subkey in uninstall_keys:
        try:
            with winreg.OpenKey(hkey, subkey) as key:
                i = 0
                while True:
                    try:
                        name = winreg.EnumKey(key, i)
                        i += 1
                        if "mavi" not in name.lower():
                            continue
                        with winreg.OpenKey(key, name) as entry:
                            try:
                                uninstall_str, _ = winreg.QueryValueEx(entry, "UninstallString")
                                if uninstall_str and Path(uninstall_str.strip('"')).exists():
                                    return uninstall_str.strip('"')
                            except FileNotFoundError:
                                pass
                    except OSError:
                        break
        except OSError:
            pass

    return None


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
        err("For Linux use: python uninstall_gui_linux.py")
        sys.exit(1)

    print()
    print(c("1;36", "  +-------------------------------------------+"))
    print(c("1;36", "  |   Mavi VPN - GUI Uninstaller (Windows)    |"))
    print(c("1;36", "  +-------------------------------------------+"))
    print()

    removed_anything = False

    step("Network repair")
    repair_network_state()

    # -- NSIS uninstaller -------------------------------------------------------
    step("NSIS uninstaller")
    nsis_uninstaller = find_nsis_uninstaller()

    if nsis_uninstaller:
        info(f"Found NSIS uninstaller: {nsis_uninstaller}")
        if ask("Run NSIS uninstaller? (recommended)"):
            if is_admin():
                subprocess.run([nsis_uninstaller], check=False)
            else:
                info("NSIS uninstaller needs admin rights - requesting elevation...")
                if not run_elevated(nsis_uninstaller):
                    warn("UAC elevation was cancelled or failed.")
            ok("NSIS uninstaller started")
            removed_anything = True
            # NSIS handles everything - skip manual removal
            _offer_cli_uninstall()
            print()
            ok("GUI uninstallation complete!")
            return
    else:
        ok("No NSIS installation found - trying manual removal.")

    # -- Manual removal ---------------------------------------------------------
    step("GUI binary")
    prog_dir = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "MaviVPN"
    local_dir = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "MaviVPN"

    install_dir = None
    for candidate in [prog_dir, local_dir]:
        if (candidate / "mavi-vpn-gui.exe").exists():
            install_dir = candidate
            break

    if install_dir is None:
        raw = input(c("1;37", f"  ? Install directory [{prog_dir}]: ")).strip()
        install_dir = Path(raw) if raw else prog_dir

    gui_exe = install_dir / "mavi-vpn-gui.exe"
    if gui_exe.exists():
        if ask(f"Remove GUI binary ({gui_exe})?"):
            try:
                gui_exe.unlink()
                ok(f"Removed: {gui_exe}")
                removed_anything = True
            except PermissionError:
                err(f"Cannot remove {gui_exe} - file in use or missing permissions.")
                warn("Try running as Administrator.")
    else:
        ok(f"GUI binary not found in {install_dir} - skipping.")

    # Remove directory if empty (and no CLI binaries left)
    if install_dir.exists():
        try:
            remaining = list(install_dir.iterdir())
            if not remaining:
                install_dir.rmdir()
                ok(f"Removed empty directory: {install_dir}")
        except OSError:
            pass

    # -- Desktop shortcut -------------------------------------------------------
    step("Desktop shortcut")
    shortcut = Path.home() / "Desktop" / "Mavi VPN.lnk"
    if shortcut.exists():
        if ask(f"Remove desktop shortcut ({shortcut})?"):
            shortcut.unlink()
            ok(f"Removed: {shortcut}")
            removed_anything = True
    else:
        ok("Desktop shortcut not found - skipping.")

    # -- PATH cleanup -----------------------------------------------------------
    step("PATH cleanup")
    if ask("Remove MaviVPN directory from system/user PATH?"):
        try:
            remove_from_path(install_dir)
            removed_anything = True
        except Exception as e:
            warn(f"Could not update PATH: {e}")

    # -- Optionally also remove CLI/service -------------------------------------
    _offer_cli_uninstall()

    # -- Done -------------------------------------------------------------------
    print()
    if removed_anything:
        ok("GUI uninstallation complete!")
    else:
        warn("Nothing was removed.")


def _offer_cli_uninstall():
    step("CLI / Service")
    cli_script = ROOT / "uninstall_cli_windows.py"

    # Check if service exists
    r = subprocess.run(["sc", "query", "MaviVPNService"], capture_output=True)
    service_exists = r.returncode == 0

    if cli_script.exists() and service_exists:
        if ask("Also uninstall CLI and Windows Service?", default="n"):
            subprocess.run([sys.executable, str(cli_script)])
    else:
        ok("CLI service not installed or uninstaller not found - skipping.")


if __name__ == "__main__":
    main()
