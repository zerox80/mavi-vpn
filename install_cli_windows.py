#!/usr/bin/env python3
"""
Mavi VPN – CLI Installer (Windows)

Builds and installs:
  mavi-vpn-client.exe   CLI client
  mavi-vpn-service.exe  Background Windows Service

Usage:
  python install_cli_windows.py
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

NO_COLOR = not sys.stdout.isatty() or bool(os.environ.get("NO_COLOR"))

def c(code, text):    return text if NO_COLOR else f"\033[{code}m{text}\033[0m"
def info(msg):        print(c("1;36", "  →"), msg)
def ok(msg):          print(c("1;32", "  ✓"), msg)
def warn(msg):        print(c("1;33", "  !"), msg)
def err(msg):         print(c("1;31", "  ✗"), msg)
def step(msg):        print(c("1;37", f"\n[{msg}]"))

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent

def run(cmd, cwd=None, check=True):
    info(f"Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    result = subprocess.run(cmd, cwd=cwd or ROOT, shell=isinstance(cmd, str))
    if check and result.returncode != 0:
        err(f"Command failed (exit {result.returncode})")
        sys.exit(result.returncode)
    return result

def ask(question, default="y"):
    yn = "Y/n" if default == "y" else "y/N"
    answer = input(c("1;37", f"  ? {question} [{yn}]: ")).strip().lower()
    return (answer in ("y", "yes", "j", "ja")) if answer else (default == "y")

def require_cmd(name):
    if not shutil.which(name):
        err(f"'{name}' not found in PATH. Please install it first.")
        sys.exit(1)

# ---------------------------------------------------------------------------
# Service helpers
# ---------------------------------------------------------------------------

def _stop_and_remove_service():
    """Stop service, kill all MaviVPN processes, delete service registration."""
    import time

    # 1. Stop the Windows Service
    r = subprocess.run(["sc", "query", "MaviVPNService"], capture_output=True)
    if r.returncode == 0:
        warn("Stopping MaviVPNService...")
        subprocess.run(["net", "stop", "MaviVPNService"], capture_output=True)
        for _ in range(20):
            r2 = subprocess.run(["sc", "query", "MaviVPNService"], capture_output=True, text=True)
            if "STOPPED" in r2.stdout or r2.returncode != 0:
                break
            time.sleep(0.5)
        subprocess.run(["sc", "delete", "MaviVPNService"], capture_output=True)

    # 2. Kill ANY remaining mavi-vpn processes that hold file locks
    for proc in ["mavi-vpn-service.exe", "mavi-vpn-client.exe"]:
        subprocess.run(["taskkill", "/F", "/IM", proc], capture_output=True)

    time.sleep(1)
    ok("Old processes stopped and service removed")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if sys.platform != "win32":
        err("This script is for Windows only.")
        err("For Linux use: python install_cli_linux.py")
        sys.exit(1)

    print()
    print(c("1;36", "  ╔══════════════════════════════════════╗"))
    print(c("1;36", "  ║   Mavi VPN – CLI Installer (Windows)  ║"))
    print(c("1;36", "  ╚══════════════════════════════════════╝"))
    print()

    require_cmd("cargo")

    # ── Build ───────────────────────────────────────────────────────────────
    step("Building CLI + Service")
    run(["cargo", "build", "--release", "-p", "windows-vpn"])

    client  = ROOT / "target" / "release" / "mavi-vpn-client.exe"
    service = ROOT / "target" / "release" / "mavi-vpn-service.exe"

    if not client.exists() or not service.exists():
        err("Build finished but binaries not found.")
        sys.exit(1)

    ok("Build successful")

    # ── Stop + unregister existing service before touching files ─────────────
    step("Stopping existing service")
    _stop_and_remove_service()

    # ── Install directory ────────────────────────────────────────────────────
    step("Installing binaries")
    default_dir = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "MaviVPN"
    raw = input(c("1;37", f"  ? Install directory [{default_dir}]: ")).strip()
    install_dir = Path(raw) if raw else default_dir

    install_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(client,  install_dir / "mavi-vpn-client.exe")
    shutil.copy2(service, install_dir / "mavi-vpn-service.exe")
    ok(f"Installed to {install_dir}")

    # ── PATH ─────────────────────────────────────────────────────────────────
    if ask("Add install directory to system PATH?"):
        run(f'setx /M PATH "%PATH%;{install_dir}"', check=False)
        ok("PATH updated (restart terminal to take effect)")

    # ── Windows Service ───────────────────────────────────────────────────────
    print()
    print(c("0;37",
        "  The Windows Service runs in the background and handles the VPN tunnel.\n"
        "  CLI and GUI communicate with it via IPC – no admin needed after install."
    ))
    if ask("Install and start MaviVPNService (requires Administrator)?"):
        svc = install_dir / "mavi-vpn-service.exe"

        # Service was already stopped+removed above; this is a no-op safety call.
        _stop_and_remove_service()

        r = run([str(svc), "install"], check=False)
        if r.returncode == 0:
            ok("Service installed")
            r2 = run(["net", "start", "MaviVPNService"], check=False)
            if r2.returncode == 0:
                ok("Service started")
            else:
                warn("Service registered but could not be started.")
                warn("Try:  net start MaviVPNService  (as Administrator)")
        else:
            warn("Service install failed – are you running as Administrator?")
            print(c("0;37", f"\n  Run manually as Admin:\n    {svc} install\n    net start MaviVPNService"))

    # ── Done ──────────────────────────────────────────────────────────────────
    print()
    ok("CLI installation complete!")
    print(c("0;37", f"\n  Usage:"))
    print(c("0;37", f"    {install_dir}\\mavi-vpn-client.exe        (interactive)"))
    print(c("0;37", f"    {install_dir}\\mavi-vpn-client.exe start   (connect)"))
    print(c("0;37", f"    {install_dir}\\mavi-vpn-client.exe stop    (disconnect)"))
    print(c("0;37", f"    {install_dir}\\mavi-vpn-client.exe status  (check status)"))


if __name__ == "__main__":
    main()
