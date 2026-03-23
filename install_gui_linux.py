#!/usr/bin/env python3
"""
Mavi VPN – GUI Installer (Linux)

Builds the Tauri GUI and installs it.
cargo-tauri is installed automatically if not present.

Install priority:
  1. .rpm  (Fedora/RHEL)
  2. .deb  (Debian/Ubuntu)
  3. .AppImage
  4. raw binary fallback

Creates a .desktop entry for the app menu.

Usage:
  python install_gui_linux.py
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

ROOT    = Path(__file__).resolve().parent
GUI_DIR = ROOT / "gui"
BUNDLE  = GUI_DIR / "src-tauri" / "target" / "release" / "bundle"

def run(cmd, cwd=None, check=True):
    info(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd or ROOT)
    if check and result.returncode != 0:
        err(f"Command failed (exit {result.returncode})")
        sys.exit(result.returncode)
    return result

def run_capture(cmd, cwd=None):
    return subprocess.run(cmd, cwd=cwd or ROOT, capture_output=True, text=True)

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
    return run(([] if is_root() else ["sudo"]) + list(cmd))

def ensure_tauri_cli():
    step("Checking cargo-tauri")
    result = run_capture(["cargo", "tauri", "--version"])
    if result.returncode == 0:
        ok(f"cargo-tauri found: {result.stdout.strip()}")
        return
    warn("cargo-tauri not found – installing (this takes a few minutes)...")
    run(["cargo", "install", "tauri-cli"])
    ok("cargo-tauri installed")

def find_bundle(pattern):
    """Return first file matching a glob in the bundle dir, or None."""
    return next(BUNDLE.glob(pattern), None) if BUNDLE.exists() else None

DESKTOP_ENTRY = """\
[Desktop Entry]
Name=Mavi VPN
Comment=QUIC-based VPN client
Exec={exec}
Icon=network-vpn
Terminal=false
Type=Application
Categories=Network;
StartupNotify=true
"""

def create_desktop_entry(exec_path: str):
    if not ask("Create .desktop entry (app menu shortcut)?"):
        return
    desktop_dir = Path.home() / ".local" / "share" / "applications"
    desktop_dir.mkdir(parents=True, exist_ok=True)
    dest = desktop_dir / "mavi-vpn.desktop"
    dest.write_text(DESKTOP_ENTRY.format(exec=exec_path))
    dest.chmod(0o644)
    ok(f".desktop entry: {dest}")
    if shutil.which("update-desktop-database"):
        run(["update-desktop-database", str(desktop_dir)], check=False)

def post_install_message(binary_path: str = "mavi-vpn-gui"):
    print()
    ok("GUI installation complete!")
    print()
    warn("The VPN daemon must be running before connecting via the GUI.")
    print(c("0;37", "  Start daemon:   sudo mavi-vpn daemon &"))
    print(c("0;37", "  Via systemd:    sudo systemctl start mavi-vpn"))
    print(c("0;37", f"  Launch GUI:     {binary_path}"))
    print()
    print(c("0;37", "  No CLI yet? Run:  python install_cli_linux.py"))

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if not sys.platform.startswith("linux"):
        err("This script is for Linux only.")
        err("For Windows use: python install_gui_windows.py")
        sys.exit(1)

    if not GUI_DIR.exists():
        err("gui/ directory not found. Run from the project root.")
        sys.exit(1)

    print()
    print(c("1;36", "  ╔══════════════════════════════════════╗"))
    print(c("1;36", "  ║   Mavi VPN – GUI Installer (Linux)    ║"))
    print(c("1;36", "  ╚══════════════════════════════════════╝"))
    print()

    require_cmd("cargo")
    ensure_tauri_cli()

    # ── Build ────────────────────────────────────────────────────────────────
    step("Building GUI (Release)")
    run(["cargo", "tauri", "build"], cwd=GUI_DIR)

    binary = GUI_DIR / "src-tauri" / "target" / "release" / "mavi-vpn-gui"

    # ── Install – try package managers first ─────────────────────────────────
    step("Installing")

    # Fedora/RHEL – RPM
    rpm = find_bundle("rpm/*.rpm")
    if rpm and shutil.which("rpm") and ask(f"Install via RPM ({rpm.name})?"):
        sudo("rpm", "-i", "--force", str(rpm))
        ok("Installed via rpm")
        post_install_message()
        return

    # Debian/Ubuntu – DEB
    deb = find_bundle("deb/*.deb")
    if deb and ask(f"Install via dpkg ({deb.name})?"):
        if shutil.which("apt"):
            sudo("apt", "install", "-y", str(deb))
        else:
            sudo("dpkg", "-i", str(deb))
        ok("Installed via dpkg")
        post_install_message()
        return

    # AppImage
    appimage = find_bundle("appimage/*.AppImage")
    if appimage and ask(f"Install AppImage ({appimage.name})?"):
        default_dir = Path.home() / ".local" / "bin"
        raw = input(c("1;37", f"  ? Install to [{default_dir}]: ")).strip()
        dest_dir = Path(raw) if raw else default_dir
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / "mavi-vpn-gui"
        shutil.copy2(appimage, dest)
        dest.chmod(0o755)
        ok(f"AppImage installed to {dest}")
        create_desktop_entry(str(dest))
        post_install_message(str(dest))
        return

    # Raw binary fallback
    if not binary.exists():
        err("No binary found after build.")
        sys.exit(1)

    default_dest = "/usr/local/bin/mavi-vpn-gui"
    raw = input(c("1;37", f"  ? Install binary to [{default_dest}]: ")).strip()
    dest = Path(raw) if raw else Path(default_dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    sudo("install", "-m", "755", str(binary), str(dest))
    ok(f"Binary installed to {dest}")
    create_desktop_entry(str(dest))
    post_install_message(str(dest))


if __name__ == "__main__":
    main()
