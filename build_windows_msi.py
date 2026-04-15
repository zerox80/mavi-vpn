#!/usr/bin/env python3
"""
Mavi VPN – Unified MSI Builder

Builds the CLI client, background service, and GUI, then packages
everything into a single enterprise-ready .msi installer via WiX.

Usage:
    python build_windows_msi.py
"""
import os
import sys
import shutil
import subprocess
from pathlib import Path

# Force UTF-8 for console output to avoid encoding errors
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

ROOT = Path(__file__).resolve().parent
GUI_DIR = ROOT / "gui"
WIX_TEMPLATE = GUI_DIR / "src-tauri" / "wix" / "service.wxs"

def run(cmd, cwd=None, env=None):
    print(f"  -> Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd or ROOT, shell=isinstance(cmd, str), env=env)
    if result.returncode != 0:
        print(f"  X  Command failed (exit {result.returncode})")
        sys.exit(result.returncode)

def patch_wix_template(client_path: Path, service_path: Path):
    """Replace placeholders in service.wxs with absolute paths to the staged binaries."""
    text = WIX_TEMPLATE.read_text(encoding="utf-8")
    text = text.replace("__CLIENT_EXE_PATH__", str(client_path))
    text = text.replace("__SERVICE_EXE_PATH__", str(service_path))
    WIX_TEMPLATE.write_text(text, encoding="utf-8")
    print(f"  OK Patched {WIX_TEMPLATE.name} with absolute binary paths")

def restore_wix_template():
    """Restore placeholders so the repo stays clean."""
    text = WIX_TEMPLATE.read_text(encoding="utf-8")
    # Find absolute paths via known exe names and replace back to placeholders
    import re
    text = re.sub(r'Source="[^"]*mavi-vpn-client\.exe"', 'Source="__CLIENT_EXE_PATH__"', text)
    text = re.sub(r'Source="[^"]*mavi-vpn-service\.exe"', 'Source="__SERVICE_EXE_PATH__"', text)
    WIX_TEMPLATE.write_text(text, encoding="utf-8")

def main():
    if sys.platform != "win32":
        print("This script is for Windows only.")
        sys.exit(1)

    print()
    print("  +------------------------------------------+")
    print("  |     Mavi VPN - Unified MSI Builder        |")
    print("  +------------------------------------------+")
    print()

    # Use a short target directory to avoid LNK1104 path length issues on Windows
    build_dir = Path("C:\\mavi-build")
    try:
        build_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        build_dir = ROOT / "target-short"
        build_dir.mkdir(parents=True, exist_ok=True)

    build_env = os.environ.copy()
    build_env["CARGO_TARGET_DIR"] = str(build_dir)

    # ── Step 1: Build CLI & Service ──────────────────────────────────────
    print("[1/3] Building CLI & Service...")
    run(["cargo", "build", "--release", "-p", "windows-vpn"], env=build_env)

    # Locate release binaries
    release_dir = build_dir / "release"
    if not (release_dir / "mavi-vpn-client.exe").exists():
        release_dir = build_dir / "x86_64-pc-windows-msvc" / "release"

    client_exe = release_dir / "mavi-vpn-client.exe"
    service_exe = release_dir / "mavi-vpn-service.exe"

    if not client_exe.exists() or not service_exe.exists():
        print(f"  X  Error: Binaries not found in {release_dir}")
        sys.exit(1)

    # ── Step 2: Stage binaries & patch WiX template ──────────────────────
    print("\n[2/3] Staging binaries for WiX...")
    wix_bin = GUI_DIR / "src-tauri" / "wix_binaries"
    wix_bin.mkdir(parents=True, exist_ok=True)

    staged_client = wix_bin / "mavi-vpn-client.exe"
    staged_service = wix_bin / "mavi-vpn-service.exe"

    shutil.copy2(client_exe, staged_client)
    shutil.copy2(service_exe, staged_service)
    print("  OK Binaries staged.")

    # Patch service.wxs with absolute paths (works on any machine)
    patch_wix_template(staged_client.resolve(), staged_service.resolve())

    # ── Step 3: Build MSI ────────────────────────────────────────────────
    print("\n[3/3] Building Tauri MSI bundle...")
    try:
        run(["cargo", "tauri", "build", "--bundles", "msi"], cwd=GUI_DIR, env=build_env)
    finally:
        # Always restore placeholders so we don't commit absolute paths
        restore_wix_template()
        print("  OK Restored service.wxs template placeholders")

    msi_dir = build_dir / "release" / "bundle" / "msi"
    print()
    print("  ====================================================")
    print("  OK  Build complete! MSI installer:")
    print(f"      {msi_dir}")
    print("  ====================================================")

if __name__ == "__main__":
    main()
