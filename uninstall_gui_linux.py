#!/usr/bin/env python3
"""
Mavi VPN – GUI Uninstaller (Linux)

Removes:
  mavi-vpn-gui      Tauri GUI binary (RPM/DEB/AppImage/raw)
  .desktop entry    App menu shortcut
  Icon              hicolor theme icon

Usage:
  python uninstall_gui_linux.py
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

def ask(question, default="y"):
    yn = "Y/n" if default == "y" else "y/N"
    answer = input(c("1;37", f"  ? {question} [{yn}]: ")).strip().lower()
    return (answer in ("y", "yes", "j", "ja")) if answer else (default == "y")

def is_root():
    return os.geteuid() == 0

def sudo(*cmd):
    full = ([] if is_root() else ["sudo"]) + list(cmd)
    info(f"Running: {' '.join(full)}")
    return subprocess.run(full)

def run_capture(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)

def detect_distro():
    """Detect Linux distribution family via /etc/os-release."""
    try:
        with open("/etc/os-release") as f:
            text = f.read().lower()
    except FileNotFoundError:
        return None
    if any(d in text for d in ("fedora", "rhel", "centos", "rocky", "alma")):
        return "fedora"
    if any(d in text for d in ("debian", "ubuntu", "mint", "pop!_os", "pop_os")):
        return "debian"
    if any(d in text for d in ("arch", "manjaro", "endeavouros", "garuda")):
        return "arch"
    if any(d in text for d in ("opensuse", "suse")):
        return "suse"
    return None

# ---------------------------------------------------------------------------
# Package manager removal
# ---------------------------------------------------------------------------

def try_remove_package():
    """Try to remove the GUI via the system package manager. Returns True if handled."""
    distro = detect_distro()

    # Check RPM-based
    if distro in ("fedora", "suse") or shutil.which("rpm"):
        r = run_capture(["rpm", "-qa", "--queryformat", "%{NAME}\\n"])
        if r.returncode == 0:
            pkgs = [p for p in r.stdout.splitlines() if "mavi" in p.lower()]
            if pkgs:
                pkg = pkgs[0]
                info(f"Found RPM package: {pkg}")
                if ask(f"Uninstall via rpm ({pkg})?"):
                    sudo("rpm", "-e", pkg)
                    ok(f"Package {pkg} removed")
                    return True

    # Check DEB-based
    if distro == "debian" or shutil.which("dpkg"):
        r = run_capture(["dpkg", "-l"])
        if r.returncode == 0:
            pkgs = [
                line.split()[1]
                for line in r.stdout.splitlines()
                if line.startswith("ii") and "mavi" in line.lower()
            ]
            if pkgs:
                pkg = pkgs[0]
                info(f"Found DEB package: {pkg}")
                if ask(f"Uninstall via apt ({pkg})?"):
                    if shutil.which("apt"):
                        sudo("apt", "remove", "-y", pkg)
                    else:
                        sudo("dpkg", "-r", pkg)
                    ok(f"Package {pkg} removed")
                    return True

    # Check Arch/pacman
    if distro == "arch" or shutil.which("pacman"):
        r = run_capture(["pacman", "-Qs", "mavi"])
        if r.returncode == 0 and r.stdout.strip():
            pkgs = [
                line.split("/")[1].split()[0]
                for line in r.stdout.splitlines()
                if line.startswith("local/")
            ]
            if pkgs:
                pkg = pkgs[0]
                info(f"Found pacman package: {pkg}")
                if ask(f"Uninstall via pacman ({pkg})?"):
                    sudo("pacman", "-R", "--noconfirm", pkg)
                    ok(f"Package {pkg} removed")
                    return True

    return False

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if not sys.platform.startswith("linux"):
        err("This script is for Linux only.")
        err("For Windows use: python uninstall_gui_windows.py")
        sys.exit(1)

    print()
    print(c("1;36", "  ╔════════════════════════════════════════╗"))
    print(c("1;36", "  ║   Mavi VPN – GUI Uninstaller (Linux)    ║"))
    print(c("1;36", "  ╚════════════════════════════════════════╝"))
    print()

    removed_anything = False

    # ── Package manager removal ──────────────────────────────────────────────
    step("Package manager")
    pkg_removed = try_remove_package()
    if pkg_removed:
        removed_anything = True

    # ── Manual binary removal ────────────────────────────────────────────────
    if not pkg_removed:
        step("GUI binary")
        candidates = [
            Path("/usr/local/bin/mavi-vpn-gui"),
            Path.home() / ".local" / "bin" / "mavi-vpn-gui",
        ]

        # Also check via which
        which_path = shutil.which("mavi-vpn-gui")
        if which_path:
            wp = Path(which_path).resolve()
            if wp not in [c.resolve() for c in candidates if c.exists()]:
                candidates.insert(0, wp)

        found = [p for p in candidates if p.exists()]
        if found:
            for binary in found:
                if ask(f"Remove binary ({binary})?"):
                    if str(binary).startswith("/usr"):
                        sudo("rm", "-f", str(binary))
                    else:
                        binary.unlink()
                    ok(f"Removed: {binary}")
                    removed_anything = True
        else:
            ok("No GUI binary found – skipping.")

    # ── Desktop entry ────────────────────────────────────────────────────────
    step("Desktop integration")

    # User-local .desktop
    user_desktop = Path.home() / ".local" / "share" / "applications" / "mavi-vpn.desktop"
    if user_desktop.exists():
        if ask(f"Remove desktop entry ({user_desktop})?"):
            user_desktop.unlink()
            ok(f"Removed: {user_desktop}")
            removed_anything = True

    # System-wide .desktop files
    import glob as _glob
    sys_desktop_files = (
        _glob.glob("/usr/share/applications/*avi*VPN*.desktop")
        + _glob.glob("/usr/share/applications/*mavi*.desktop")
    )
    for df in sys_desktop_files:
        if ask(f"Remove system desktop entry ({df})?"):
            sudo("rm", "-f", df)
            ok(f"Removed: {df}")
            removed_anything = True

    # ── Icon ─────────────────────────────────────────────────────────────────
    icon = Path.home() / ".local" / "share" / "icons" / "hicolor" / "128x128" / "apps" / "mavi-vpn-gui.png"
    if icon.exists():
        if ask(f"Remove icon ({icon})?"):
            icon.unlink()
            ok(f"Removed: {icon}")
            removed_anything = True

    # ── Refresh desktop caches ───────────────────────────────────────────────
    if removed_anything:
        if shutil.which("gtk-update-icon-cache"):
            icon_dir = Path.home() / ".local" / "share" / "icons" / "hicolor"
            if icon_dir.exists():
                subprocess.run(["gtk-update-icon-cache", "-f", "-t", str(icon_dir)], check=False)
            sys_icon_dir = Path("/usr/share/icons/hicolor")
            if sys_icon_dir.exists():
                sudo("gtk-update-icon-cache", "-f", "-t", str(sys_icon_dir))
        if shutil.which("update-desktop-database"):
            user_apps = Path.home() / ".local" / "share" / "applications"
            if user_apps.exists():
                subprocess.run(["update-desktop-database", str(user_apps)], check=False)
            sudo("update-desktop-database", "/usr/share/applications")
        ok("Desktop caches refreshed")

    # ── Optionally also remove CLI/daemon ────────────────────────────────────
    step("CLI / Daemon")
    cli_script = ROOT / "uninstall_cli_linux.py"
    if cli_script.exists() and shutil.which("mavi-vpn"):
        if ask("Also uninstall CLI daemon (mavi-vpn)?", default="n"):
            subprocess.run([sys.executable, str(cli_script)])
    else:
        ok("CLI daemon not installed or uninstaller not found – skipping.")

    # ── Done ─────────────────────────────────────────────────────────────────
    print()
    if removed_anything:
        ok("GUI uninstallation complete!")
    else:
        warn("Nothing was removed.")


if __name__ == "__main__":
    main()
