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
BUNDLE  = ROOT / "target" / "release" / "bundle"

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

# ---------------------------------------------------------------------------
# System dependency installation
# ---------------------------------------------------------------------------

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

# Tauri 2 system deps + build toolchain per distro family.
# webkit2gtk 4.1 is required by Tauri 2 / wry.
GUI_SYSTEM_DEPS = {
    "fedora": [
        # Tauri 2 / WebView
        "webkit2gtk4.1-devel",
        "openssl-devel",
        "gtk3-devel",
        "libappindicator-gtk3-devel",
        "librsvg2-devel",
        # Build toolchain
        "gcc", "gcc-c++", "make", "pkg-config", "cmake", "perl",
        # Tauri bundler helpers (fuse2 needed by linuxdeploy AppImage)
        "file", "curl", "wget", "fuse",
        # Runtime (VPN networking)
        "iproute",
    ],
    "debian": [
        "libwebkit2gtk-4.1-dev",
        "libssl-dev",
        "libgtk-3-dev",
        "libayatana-appindicator3-dev",
        "librsvg2-dev",
        "build-essential", "pkg-config", "cmake", "perl",
        "file", "curl", "wget", "libfuse2",
        "iproute2",
    ],
    "arch": [
        "webkit2gtk-4.1",
        "openssl",
        "gtk3",
        "libappindicator-gtk3",
        "librsvg",
        "base-devel", "cmake", "perl",
        "file", "curl", "wget",
        "iproute2",
    ],
    "suse": [
        "webkit2gtk3-devel",
        "libopenssl-devel",
        "gtk3-devel",
        "libappindicator3-devel",
        "librsvg-devel",
        "gcc", "gcc-c++", "make", "pkg-config", "cmake", "perl",
        "file", "curl", "wget",
        "iproute2",
    ],
}

_PKG_INSTALL_CMD = {
    "fedora": ["dnf", "install", "-y"],
    "debian": ["apt-get", "install", "-y"],
    "arch":   ["pacman", "-S", "--needed", "--noconfirm"],
    "suse":   ["zypper", "install", "-y"],
}

def install_system_deps(dep_table):
    """Detect distro and install required system packages."""
    step("System dependencies")

    distro = detect_distro()
    if not distro:
        warn("Could not detect Linux distribution.")
        warn("Please install Tauri 2 system deps manually:")
        warn("  https://v2.tauri.app/start/prerequisites/#linux")
        if not ask("Continue anyway?", default="n"):
            sys.exit(1)
        return

    pkgs = dep_table.get(distro, [])
    if not pkgs:
        warn(f"No package list for '{distro}'. Continuing – build may fail.")
        return

    info(f"Detected distro family: {distro}")
    info(f"Packages: {', '.join(pkgs)}")

    if ask("Install system dependencies?"):
        sudo(*(_PKG_INSTALL_CMD[distro] + pkgs))
        ok("System dependencies installed")
    else:
        warn("Skipped. Build may fail if deps are missing.")

def ensure_rust():
    """Check for cargo; offer rustup install if missing."""
    if shutil.which("cargo"):
        return
    err("'cargo' not found.")
    if ask("Install Rust via rustup?"):
        run(["sh", "-c", "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"])
        # Source the env so cargo is available in this session
        cargo_bin = Path.home() / ".cargo" / "bin"
        os.environ["PATH"] = f"{cargo_bin}:{os.environ['PATH']}"
        if not shutil.which("cargo"):
            err("Rust installed but cargo still not found. Please restart your shell and re-run.")
            sys.exit(1)
        ok("Rust installed")
    else:
        err("cargo is required. Install Rust: https://rustup.rs")
        sys.exit(1)

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
GenericName=VPN Client
Comment=QUIC-based VPN client with Keycloak SSO
Exec={exec}
Icon=mavi-vpn-gui
Terminal=false
Type=Application
Categories=Network;
Keywords=vpn;network;mavi;secure;quic;tunnel;
StartupNotify=true
StartupWMClass=mavi-vpn-gui
"""

def install_icon():
    """Kopiert das App-Icon ins hicolor-Theme (user-lokal), damit Icon=mavi-vpn-gui aufgelöst wird."""
    src = ROOT / "gui" / "src-tauri" / "icons" / "128x128.png"
    if not src.exists():
        return
    dest = Path.home() / ".local" / "share" / "icons" / "hicolor" / "128x128" / "apps" / "mavi-vpn-gui.png"
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
    icon_dir = Path.home() / ".local" / "share" / "icons" / "hicolor"
    if shutil.which("gtk-update-icon-cache"):
        subprocess.run(["gtk-update-icon-cache", "-f", "-t", str(icon_dir)], check=False)
    ok("Icon installiert")

def patch_system_desktop_entry():
    """Ergänzt Categories/Keywords in der vom Paket installierten .desktop-Datei."""
    import glob as _glob
    matches = _glob.glob("/usr/share/applications/*avi*VPN*.desktop") + \
              _glob.glob("/usr/share/applications/*mavi*.desktop")
    if not matches:
        warn("Keine .desktop-Datei in /usr/share/applications gefunden – übersprungen.")
        return
    path = matches[0]
    try:
        text = open(path).read()
        if "Keywords=" not in text:
            text += "Keywords=vpn;network;mavi;secure;quic;tunnel;\n"
        text = __import__("re").sub(r"Categories=.*", "Categories=Network;", text)
        if "GenericName=" not in text:
            text = text.replace("[Desktop Entry]\n", "[Desktop Entry]\nGenericName=VPN Client\n")
        if "StartupWMClass=" not in text:
            text += "StartupWMClass=mavi-vpn-gui\n"
        open(path, "w").write(text)
        ok(f".desktop gepatcht: {path}")
    except Exception as e:
        warn(f".desktop konnte nicht gepatcht werden: {e}")

def refresh_desktop_integration():
    """Aktualisiert Icon-Cache und Desktop-Datenbank damit GNOME die App sofort findet."""
    if shutil.which("gtk-update-icon-cache"):
        sudo("gtk-update-icon-cache", "-f", "-t", "/usr/share/icons/hicolor")
    if shutil.which("update-desktop-database"):
        sudo("update-desktop-database", "/usr/share/applications")
    ok("Desktop-Integration aktualisiert")

def create_desktop_entry(exec_path: str):
    if not ask("Create .desktop entry (app menu shortcut)?"):
        return
    install_icon()
    desktop_dir = Path.home() / ".local" / "share" / "applications"
    desktop_dir.mkdir(parents=True, exist_ok=True)
    dest = desktop_dir / "mavi-vpn.desktop"
    dest.write_text(DESKTOP_ENTRY.format(exec=exec_path))
    dest.chmod(0o644)
    ok(f".desktop entry: {dest}")
    if shutil.which("update-desktop-database"):
        subprocess.run(["update-desktop-database", str(desktop_dir)], check=False)
    ok("GNOME-Suche aktualisiert")

def ensure_daemon():
    """Prüft ob Daemon installiert ist, bietet Installation + Start an."""
    step("VPN Daemon")
    if shutil.which("mavi-vpn"):
        ok("mavi-vpn daemon binary gefunden")
    else:
        warn("mavi-vpn daemon nicht gefunden – GUI zeigt 'Service Offline' ohne ihn.")
        cli_script = ROOT / "install_cli_linux.py"
        if cli_script.exists() and ask("Daemon jetzt installieren (install_cli_linux.py)?"):
            run([sys.executable, str(cli_script)])
        else:
            warn("Daemon manuell installieren: python install_cli_linux.py")
            return

    if shutil.which("systemctl"):
        result = run_capture(["systemctl", "is-active", "mavi-vpn"])
        if result.stdout.strip() == "active":
            ok("mavi-vpn.service läuft bereits")
        elif ask("Daemon jetzt starten (sudo systemctl start mavi-vpn)?"):
            sudo("systemctl", "start", "mavi-vpn")
            ok("Daemon gestartet")

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

    ensure_rust()
    install_system_deps(GUI_SYSTEM_DEPS)
    ensure_tauri_cli()

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
    step("Building GUI (Release)")
    build_env = os.environ.copy()
    build_env["APPIMAGE_EXTRACT_AND_RUN"] = "1"
    info("Running: cargo tauri build")
    result = subprocess.run(["cargo", "tauri", "build"], cwd=GUI_DIR, env=build_env)
    if result.returncode != 0:
        err(f"Command failed (exit {result.returncode})")
        sys.exit(result.returncode)

    binary = ROOT / "target" / "release" / "mavi-vpn-gui"

    # ── Install – try package managers first ─────────────────────────────────
    step("Installing")

    # Fedora/RHEL – RPM
    rpm = find_bundle("rpm/*.rpm")
    if rpm and shutil.which("rpm") and ask(f"Install via RPM ({rpm.name})?"):
        sudo("rpm", "-i", "--force", str(rpm))
        ok("Installed via rpm")
        patch_system_desktop_entry()
        refresh_desktop_integration()
        ensure_daemon()
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
        patch_system_desktop_entry()
        refresh_desktop_integration()
        ensure_daemon()
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
        ensure_daemon()
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
    ensure_daemon()
    post_install_message(str(dest))


if __name__ == "__main__":
    main()
