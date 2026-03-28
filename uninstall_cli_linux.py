#!/usr/bin/env python3
"""
Mavi VPN – CLI Uninstaller (Linux)

Removes:
  mavi-vpn          VPN CLI + daemon binary
  mavi-vpn.service  systemd service (if installed)

Usage:
  python uninstall_cli_linux.py
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

def ask(question, default="y"):
    yn = "Y/n" if default == "y" else "y/N"
    answer = input(c("1;37", f"  ? {question} [{yn}]: ")).strip().lower()
    return (answer in ("y", "yes", "j", "ja")) if answer else (default == "y")

def is_root():
    return os.geteuid() == 0

def sudo(*cmd):
    """Run a command with sudo if not already root."""
    full = ([] if is_root() else ["sudo"]) + list(cmd)
    info(f"Running: {' '.join(full)}")
    result = subprocess.run(full)
    return result

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if not sys.platform.startswith("linux"):
        err("This script is for Linux only.")
        err("For Windows use: python uninstall_cli_windows.py")
        sys.exit(1)

    print()
    print(c("1;36", "  ╔════════════════════════════════════════╗"))
    print(c("1;36", "  ║   Mavi VPN – CLI Uninstaller (Linux)    ║"))
    print(c("1;36", "  ╚════════════════════════════════════════╝"))
    print()

    removed_anything = False

    # ── systemd service ──────────────────────────────────────────────────────
    if shutil.which("systemctl"):
        step("systemd service")
        svc_file = Path("/etc/systemd/system/mavi-vpn.service")
        r = subprocess.run(
            ["systemctl", "is-active", "mavi-vpn"],
            capture_output=True, text=True,
        )
        svc_active = r.stdout.strip() == "active"
        svc_exists = svc_file.exists()

        if svc_active:
            info("mavi-vpn.service is currently running.")
            if ask("Stop service?"):
                sudo("systemctl", "stop", "mavi-vpn")
                ok("Service stopped")

        if svc_exists:
            if ask("Disable and remove systemd service?"):
                sudo("systemctl", "disable", "mavi-vpn")
                sudo("rm", "-f", str(svc_file))
                sudo("systemctl", "daemon-reload")
                ok("systemd service removed")
                removed_anything = True
        else:
            ok("No systemd service found – skipping.")
    else:
        warn("systemctl not found – skipping service removal.")

    # ── Binary ───────────────────────────────────────────────────────────────
    step("Binary")
    default_path = "/usr/local/bin/mavi-vpn"
    binary = Path(default_path)

    # Also check if it's installed elsewhere via which
    which_path = shutil.which("mavi-vpn")
    if which_path and str(Path(which_path).resolve()) != str(binary.resolve()):
        binary = Path(which_path)
        info(f"Found mavi-vpn at: {binary}")

    if binary.exists():
        if ask(f"Remove binary ({binary})?"):
            sudo("rm", "-f", str(binary))
            ok(f"Binary removed: {binary}")
            removed_anything = True
    else:
        ok("Binary not found – skipping.")

    # ── Config files (optional) ──────────────────────────────────────────────
    step("Configuration")
    config_dirs = [
        Path.home() / ".config" / "mavi-vpn",
        Path("/etc/mavi-vpn"),
    ]
    for cfg in config_dirs:
        if cfg.exists():
            if ask(f"Remove config directory ({cfg})?", default="n"):
                if cfg == Path("/etc/mavi-vpn"):
                    sudo("rm", "-rf", str(cfg))
                else:
                    shutil.rmtree(cfg)
                ok(f"Removed: {cfg}")
                removed_anything = True

    if not any(cfg.exists() for cfg in config_dirs):
        ok("No config directories found – skipping.")

    # ── Done ─────────────────────────────────────────────────────────────────
    print()
    if removed_anything:
        ok("CLI uninstallation complete!")
    else:
        warn("Nothing was removed.")


if __name__ == "__main__":
    main()
