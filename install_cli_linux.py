#!/usr/bin/env python3
"""
Mavi VPN – CLI Installer (Linux)

Builds and installs:
  mavi-vpn   VPN CLI + daemon binary

Supports both direct CLI mode and daemon mode (for GUI).
Optionally installs a systemd service for auto-start.

Usage:
  python install_cli_linux.py
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
    info(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd or ROOT)
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

def is_root():
    return os.geteuid() == 0

def sudo(*cmd):
    """Run a command with sudo if not already root."""
    return run(([] if is_root() else ["sudo"]) + list(cmd))

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if not sys.platform.startswith("linux"):
        err("This script is for Linux only.")
        err("For Windows use: python install_cli_windows.py")
        sys.exit(1)

    print()
    print(c("1;36", "  ╔══════════════════════════════════════╗"))
    print(c("1;36", "  ║   Mavi VPN – CLI Installer (Linux)    ║"))
    print(c("1;36", "  ╚══════════════════════════════════════╝"))
    print()

    require_cmd("cargo")

    # ── Permissions fix ──────────────────────────────────────────────────────
    target_dir = ROOT / "target"
    if target_dir.exists() and not os.access(target_dir, os.W_OK):
        info("Fixing target directory permissions (likely owned by root)...")
        user = os.environ.get("SUDO_USER") or os.environ.get("USER")
        chown_paths = [str(target_dir)]
        if (ROOT / "Cargo.lock").exists():
            chown_paths.append(str(ROOT / "Cargo.lock"))
        sudo("chown", "-R", f"{user}:{user}", *chown_paths)

    # ── Build ────────────────────────────────────────────────────────────────
    step("Building CLI")
    run(["cargo", "build", "--release", "-p", "linux-vpn"])

    binary = ROOT / "target" / "release" / "mavi-vpn"
    if not binary.exists():
        err("Build finished but binary not found.")
        sys.exit(1)

    ok("Build successful")

    # ── Install binary ────────────────────────────────────────────────────────
    step("Installing binary")
    default_dest = "/usr/local/bin/mavi-vpn"
    raw = input(c("1;37", f"  ? Install to [{default_dest}]: ")).strip()
    dest = Path(raw) if raw else Path(default_dest)

    dest.parent.mkdir(parents=True, exist_ok=True)
    sudo("install", "-m", "755", str(binary), str(dest))
    ok(f"Binary installed to {dest}")

    # ── systemd service ───────────────────────────────────────────────────────
    if not shutil.which("systemctl"):
        warn("systemctl not found – skipping service setup.")
    else:
        print()
        print(c("0;37",
            "  The systemd service runs the daemon as root on boot.\n"
            "  Once active, GUI and CLI work without sudo."
        ))
        if ask("Install systemd service?"):
            service_src = ROOT / "linux" / "mavi-vpn.service"
            if not service_src.exists():
                warn(f"Service file not found: {service_src} – skipping.")
            else:
                sudo("cp", str(service_src), "/etc/systemd/system/mavi-vpn.service")
                sudo("systemctl", "daemon-reload")
                ok("systemd service installed")

                if ask("Enable service (auto-start on boot)?"):
                    sudo("systemctl", "enable", "mavi-vpn")
                    ok("Service enabled")

                if ask("Start service now?"):
                    sudo("systemctl", "start", "mavi-vpn")
                    ok("Service started")
                    run(["systemctl", "status", "mavi-vpn", "--no-pager"], check=False)

    # ── Done ──────────────────────────────────────────────────────────────────
    print()
    ok("CLI installation complete!")
    print(c("0;37", "\n  Direct mode (no daemon):"))
    print(c("0;37",  "    sudo mavi-vpn                     connect interactively"))
    print(c("0;37",  "    sudo mavi-vpn -c /path/config.json"))
    print(c("0;37", "\n  Daemon mode (for GUI):"))
    print(c("0;37",  "    sudo mavi-vpn daemon &            start daemon"))
    print(c("0;37",  "    mavi-vpn start                    connect via daemon"))
    print(c("0;37",  "    mavi-vpn stop                     disconnect"))
    print(c("0;37",  "    mavi-vpn status"))


if __name__ == "__main__":
    main()
