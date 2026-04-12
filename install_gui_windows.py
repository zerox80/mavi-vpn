#!/usr/bin/env python3
"""
Mavi VPN – GUI Installer (Windows)

Builds the Tauri GUI and installs it to Program Files.
Ensures NASM, CMake, and cargo-tauri are present.
Uses a short build path to avoid LNK1104 on Windows.

Usage:
  python install_gui_windows.py
"""

import ctypes
import os
import sys
import shutil
import subprocess
from pathlib import Path

# Force UTF-8 for console output to avoid encoding errors
if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

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

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def run_elevated(exe: Path):
    """Launch an executable with UAC elevation (RunAs)."""
    info(f"Requesting admin elevation for: {exe.name}")
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", str(exe), "", str(exe.parent), 1  # SW_SHOWNORMAL
    )
    if ret <= 32:
        warn("UAC elevation was cancelled or failed.")
        return False
    return True

def run(cmd, cwd=None, check=True, env=None):
    info(f"Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    actual_env = os.environ.copy()
    if env:
        actual_env.update(env)
    result = subprocess.run(cmd, cwd=cwd or ROOT, shell=isinstance(cmd, str), env=actual_env)
    if check and result.returncode != 0:
        err(f"Command failed (exit {result.returncode})")
        sys.exit(result.returncode)
    return result

def run_capture(cmd, cwd=None, env=None):
    actual_env = os.environ.copy()
    if env:
        actual_env.update(env)
    return subprocess.run(cmd, cwd=cwd or ROOT, capture_output=True, text=True, env=actual_env)

def ask(question, default="y"):
    yn = "Y/n" if default == "y" else "y/N"
    try:
        answer = input(c("1;37", f"  ? {question} [{yn}]: ")).strip().lower()
    except EOFError:
        return default == "y"
    return (answer in ("y", "yes", "j", "ja")) if answer else (default == "y")

def require_cmd(name):
    if not shutil.which(name):
        # Last ditch effort: refresh PATH
        _refresh_path()
        if not shutil.which(name):
            err(f"'{name}' not found in PATH. Please install it first.")
            sys.exit(1)

def _refresh_path():
    """Attempt to refresh the script's PATH from registry/environment."""
    try:
        # Simple bash-like refresh isn't easy in Python, but we can look in common places
        common_paths = [
            Path(os.environ.get("LOCALAPPDATA", "")) / "bin" / "NASM",
            Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "CMake" / "bin",
            Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / "NASM",
        ]
        for p in common_paths:
            if p.exists() and str(p) not in os.environ["PATH"]:
                os.environ["PATH"] = str(p) + os.pathsep + os.environ["PATH"]
    except:
        pass

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
    try:
        candidates = sorted(kits_root.iterdir(), reverse=True)
        for ver_dir in candidates:
            rc = ver_dir / "x64" / "rc.exe"
            if rc.exists():
                return rc.parent
    except:
        pass
    return None

def fix_icon_if_needed():
    ico = GUI_DIR / "src-tauri" / "icons" / "icon.ico"
    png = GUI_DIR / "src-tauri" / "icons" / "icon.png"
    if not ico.exists() or not png.exists():
        return
    step("Checking icon.ico format")
    try:
        from PIL import Image
    except ImportError:
        warn("Pillow not found – installing for icon conversion...")
        run([sys.executable, "-m", "pip", "install", "Pillow", "--quiet"])
        from PIL import Image
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
        os.environ["PATH"] = str(rc_dir) + os.pathsep + os.environ.get("PATH", "")
        return
    warn("rc.exe not found – installing Windows 10 SDK via winget...")
    if not shutil.which("winget"):
        err("winget not available. Install the Windows 10 SDK manually.")
        sys.exit(1)
    run(["winget", "install", "--id", "Microsoft.WindowsSDK.10.0.22000",
         "--accept-package-agreements", "--accept-source-agreements"])
    rc_dir = find_rc_exe()
    if rc_dir:
        os.environ["PATH"] = str(rc_dir) + os.pathsep + os.environ["PATH"]
        ok(f"rc.exe ready: {rc_dir}")
    else:
        err("rc.exe still not found. Try running as Administrator.")
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

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if sys.platform != "win32":
        err("This script is for Windows only.")
        sys.exit(1)

    if not GUI_DIR.exists():
        err("gui/ directory not found. Run from the project root.")
        sys.exit(1)

    print()
    print("  +--------------------------------------+ ")
    print("  |   Mavi VPN – GUI Installer (Windows)  | ")
    print("  +--------------------------------------+ ")
    print()

    # Refresh PATH initially to pick up tools installed in previous attempts
    _refresh_path()

    require_cmd("cargo")
    ensure_tauri_cli()
    ensure_windows_sdk()
    fix_icon_if_needed()

    # ── Build ────────────────────────────────────────────────────────────────
    step("Building GUI (Release)")
    
    # Use a short target directory to avoid LNK1104 path length issues
    build_dir = Path("C:\\mavi-build")
    try:
        build_dir.mkdir(parents=True, exist_ok=True)
    except:
        # Fallback to local target if C:\ is not writable
        build_dir = ROOT / "target-short"
        build_dir.mkdir(parents=True, exist_ok=True)

    info(f"Using short build path: {build_dir}")
    build_env = {"CARGO_TARGET_DIR": str(build_dir)}
    
    run(["cargo", "tauri", "build", "--bundles", "nsis"], cwd=GUI_DIR, env=build_env)

    # ── Find binary ──────────────────────────────────────────────────────────
    binary = build_dir / "release" / "mavi-vpn-gui.exe"
    if not binary.exists():
        binary = build_dir / "x86_64-pc-windows-msvc" / "release" / "mavi-vpn-gui.exe"
    
    if not binary.exists():
        err("Binary not found after build.")
        sys.exit(1)

    ok(f"Build successful: {binary}")

    admin = is_admin()
    if admin:
        ok("Running as Administrator")
    else:
        warn("Running as normal user (no admin rights)")

    # ── NSIS installer ───────────────────────────────────────────────────────
    nsis_dir = build_dir / "release" / "bundle" / "nsis"
    if not nsis_dir.exists():
        nsis_dir = build_dir / "x86_64-pc-windows-msvc" / "release" / "bundle" / "nsis"
        
    nsis = next(nsis_dir.glob("*_x64-setup.exe"), None) or next(nsis_dir.glob("*.exe"), None)
    
    if nsis and ask(f"Run NSIS installer ({nsis.name})?"):
        step("Running NSIS installer")
        if admin:
            run([str(nsis)], check=False)
        else:
            if not run_elevated(nsis):
                err("Could not start installer.")
                sys.exit(1)
        ok("NSIS installer started")
        return

    # ── Manual copy fallback ──────────────────────────────────────────────────
    step("Installing")
    if admin:
        dest_dir = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "MaviVPN"
    else:
        dest_dir = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "MaviVPN"
    
    raw = input(c("1;37", f"  ? Install to [{dest_dir}]: ")).strip()
    dest_dir = Path(raw) if raw else dest_dir
    dest_dir.mkdir(parents=True, exist_ok=True)

    dest = dest_dir / "mavi-vpn-gui.exe"
    shutil.copy2(binary, dest)
    ok(f"GUI installed to {dest}")

    if ask("Add to PATH?"):
        scope = "Machine" if admin else "User"
        ps = (
            f'$p = [Environment]::GetEnvironmentVariable("PATH", "{scope}"); '
            f'if ($p -notlike "*{dest_dir}*") {{ '
            f'[Environment]::SetEnvironmentVariable("PATH", $p + ";{dest_dir}", "{scope}") '
            f'}}'
        )
        run(["powershell", "-NoProfile", "-Command", ps], check=False)
        ok("PATH updated.")

    if ask("Create Desktop shortcut?"):
        create_shortcut(dest)

    _done_message(str(dest))

def _done_message(binary_path: str):
    print()
    ok("GUI installation complete!")
    warn("The VPN service must be running before connecting.")
    print(c("0;37", "  Service:  python install_cli_windows.py"))
    print(c("0;37", f"  Launch:   {binary_path}"))
    print()
    info("Note: You can safely delete 'C:\\mavi-build' to free up disk space.")

if __name__ == "__main__":
    main()
