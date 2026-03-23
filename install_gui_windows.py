#!/usr/bin/env python3
"""
Mavi VPN – GUI Installer (Windows)

Builds the Tauri GUI and installs it to Program Files.
cargo-tauri is installed automatically if not present.

Usage:
  python install_gui_windows.py
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

def run(cmd, cwd=None, check=True):
    info(f"Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    result = subprocess.run(cmd, cwd=cwd or ROOT, shell=isinstance(cmd, str))
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

def ensure_tauri_cli():
    step("Checking cargo-tauri")
    result = run_capture(["cargo", "tauri", "--version"])
    if result.returncode == 0:
        ok(f"cargo-tauri found: {result.stdout.strip()}")
        return
    warn("cargo-tauri not found – installing (this takes a few minutes)...")
    run(["cargo", "install", "tauri-cli"])
    ok("cargo-tauri installed")

def find_rc_exe():
    """Search Windows Kits for rc.exe and return its directory, or None."""
    kits_root = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Windows Kits" / "10" / "bin"
    if not kits_root.exists():
        return None
    # Newest SDK version first
    candidates = sorted(kits_root.iterdir(), reverse=True)
    for ver_dir in candidates:
        rc = ver_dir / "x64" / "rc.exe"
        if rc.exists():
            return rc.parent
    return None

def fix_icon_if_needed():
    """Regenerate icon.ico from icon.png if it's in old DIB format (causes RC2176)."""
    ico = GUI_DIR / "src-tauri" / "icons" / "icon.ico"
    png = GUI_DIR / "src-tauri" / "icons" / "icon.png"
    if not ico.exists() or not png.exists():
        return
    step("Checking icon.ico format")
    # Try importing Pillow; install it if missing
    try:
        from PIL import Image
    except ImportError:
        warn("Pillow not found – installing for icon conversion...")
        run([sys.executable, "-m", "pip", "install", "Pillow", "--quiet"])
        from PIL import Image
    # Re-save the .ico from the PNG to ensure modern DIB format
    img = Image.open(png)
    sizes = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)]
    imgs = []
    for s in sizes:
        imgs.append(img.resize(s, Image.LANCZOS))
    imgs[0].save(str(ico), format="ICO", sizes=[(i.width, i.height) for i in imgs],
                 append_images=imgs[1:])
    ok("icon.ico regenerated (modern DIB format)")


def ensure_windows_sdk():
    step("Checking Windows SDK (rc.exe)")
    rc_dir = find_rc_exe()
    if rc_dir:
        ok(f"rc.exe found: {rc_dir}")
        # Make sure it's on PATH for the cargo build subprocess
        os.environ["PATH"] = str(rc_dir) + os.pathsep + os.environ.get("PATH", "")
        return
    warn("rc.exe not found – installing Windows 10 SDK via winget...")
    if not shutil.which("winget"):
        err("winget not available. Install the Windows 10 SDK manually:")
        err("  https://developer.microsoft.com/windows/downloads/windows-sdk/")
        sys.exit(1)
    run(["winget", "install", "--id", "Microsoft.WindowsSDK.10.0.22000",
         "--accept-package-agreements", "--accept-source-agreements"])
    rc_dir = find_rc_exe()
    if rc_dir:
        os.environ["PATH"] = str(rc_dir) + os.pathsep + os.environ.get("PATH", "")
        ok(f"rc.exe ready: {rc_dir}")
    else:
        err("rc.exe still not found after SDK install. Restart the terminal and try again.")
        sys.exit(1)

def create_shortcut(target: Path):
    desktop  = Path.home() / "Desktop"
    shortcut = desktop / "Mavi VPN.lnk"
    ps = (
        f'$s=(New-Object -COM WScript.Shell).CreateShortcut("{shortcut}");'
        f'$s.TargetPath="{target}";'
        f'$s.Description="Mavi VPN";'
        f'$s.Save()'
    )
    r = run(["powershell", "-NoProfile", "-Command", ps], check=False)
    if r.returncode == 0:
        ok(f"Desktop shortcut created: {shortcut}")
    else:
        warn("Could not create shortcut (non-fatal)")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if sys.platform != "win32":
        err("This script is for Windows only.")
        err("For Linux use: python install_gui_linux.py")
        sys.exit(1)

    if not GUI_DIR.exists():
        err("gui/ directory not found. Run from the project root.")
        sys.exit(1)

    print()
    print(c("1;36", "  ╔══════════════════════════════════════╗"))
    print(c("1;36", "  ║   Mavi VPN – GUI Installer (Windows)  ║"))
    print(c("1;36", "  ╚══════════════════════════════════════╝"))
    print()

    require_cmd("cargo")
    ensure_tauri_cli()
    ensure_windows_sdk()
    fix_icon_if_needed()

    # ── Build ────────────────────────────────────────────────────────────────
    step("Building GUI (Release)")
    run(["cargo", "tauri", "build"], cwd=GUI_DIR)

    # cargo puts output in the workspace root target/ when gui/src-tauri is a
    # workspace member, otherwise in gui/src-tauri/target/release/.
    binary = _find_binary()
    if binary is None:
        err("Binary not found after build. Expected one of:")
        err(f"  {ROOT / 'target' / 'release' / 'mavi-vpn-gui.exe'}")
        err(f"  {GUI_DIR / 'src-tauri' / 'target' / 'release' / 'mavi-vpn-gui.exe'}")
        sys.exit(1)

    ok(f"Build successful: {binary}")

    # ── NSIS installer (preferred on Windows) ────────────────────────────────
    nsis = _find_nsis()
    if nsis and ask(f"Run NSIS installer ({nsis.name})? (recommended)"):
        step("Running NSIS installer")
        run([str(nsis)], check=False)
        ok("NSIS installer finished")
        _done_message(str(nsis.parent / "mavi-vpn-gui.exe"))
        return

    # ── Manual copy fallback ──────────────────────────────────────────────────
    step("Installing")
    default_dir = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "MaviVPN"
    raw = input(c("1;37", f"  ? Install to [{default_dir}]: ")).strip()
    dest_dir = Path(raw) if raw else default_dir
    dest_dir.mkdir(parents=True, exist_ok=True)

    dest = dest_dir / "mavi-vpn-gui.exe"
    shutil.copy2(binary, dest)
    ok(f"GUI installed to {dest}")

    # ── PATH ──────────────────────────────────────────────────────────────────
    if ask("Add install directory to system PATH?"):
        run(f'setx /M PATH "%PATH%;{dest_dir}"', check=False)
        ok("PATH updated (restart terminal to take effect)")

    # ── Shortcut ──────────────────────────────────────────────────────────────
    if ask("Create Desktop shortcut?"):
        create_shortcut(dest)

    _done_message(str(dest))


def _find_binary() -> "Path | None":
    """Find mavi-vpn-gui.exe in workspace root or local src-tauri target."""
    candidates = [
        ROOT / "target" / "release" / "mavi-vpn-gui.exe",
        GUI_DIR / "src-tauri" / "target" / "release" / "mavi-vpn-gui.exe",
    ]
    for p in candidates:
        if p.exists():
            return p
    return None


def _find_nsis() -> "Path | None":
    """Find the NSIS setup.exe produced by cargo tauri build."""
    bundle_dirs = [
        ROOT / "target" / "release" / "bundle" / "nsis",
        GUI_DIR / "src-tauri" / "target" / "release" / "bundle" / "nsis",
    ]
    for d in bundle_dirs:
        if d.exists():
            hit = next(d.glob("*_x64-setup.exe"), None) or next(d.glob("*.exe"), None)
            if hit:
                return hit
    return None


def _done_message(binary_path: str):
    print()
    ok("GUI installation complete!")
    print()
    warn("The VPN service must be running before connecting via the GUI.")
    print(c("0;37", "  Install service first:  python install_cli_windows.py"))
    print(c("0;37", f"\n  Launch GUI:  {binary_path}"))


if __name__ == "__main__":
    main()
