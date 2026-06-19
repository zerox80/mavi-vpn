#!/usr/bin/env python3
"""
Mavi VPN – shared installer helpers (Linux).

Output formatting, command execution, distro detection and toolchain
installation (Rust, Node.js/npm, cargo-tauri, system packages) used by the
GUI/CLI installer scripts.
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
# Paths & command execution
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

def sudo_try(*cmd):
    """Privileged command that does NOT abort the script on failure.

    Returns True on success. Used when trying a series of candidate packages.
    """
    full = ([] if is_root() else ["sudo"]) + list(cmd)
    info(f"Running: {' '.join(full)}")
    return subprocess.run(full).returncode == 0

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

# Node.js + npm are required by the Tauri frontend build (`npm run build`).
# Package names differ per distro and Fedora ships only versioned packages
# (e.g. nodejs22) on recent releases, so we try candidates in order.
NODE_PKG_CANDIDATES = {
    "fedora": [["nodejs"], ["nodejs22"], ["nodejs20"], ["nodejs18"]],
    "debian": [["nodejs", "npm"]],
    "arch":   [["nodejs", "npm"]],
    "suse":   [["nodejs", "npm"], ["nodejs22"], ["nodejs20"]],
}

def have_node():
    return bool(shutil.which("node") and shutil.which("npm"))

def ensure_node():
    """Ensure Node.js + npm are installed (needed for the GUI frontend build)."""
    step("Checking Node.js / npm")
    if have_node():
        node_v = run_capture(["node", "--version"]).stdout.strip()
        npm_v = run_capture(["npm", "--version"]).stdout.strip()
        ok(f"Node.js {node_v} / npm {npm_v} found")
        return

    warn("Node.js / npm not found – required to build the GUI frontend.")
    distro = detect_distro()
    candidates = NODE_PKG_CANDIDATES.get(distro) if distro else None
    if not candidates:
        err("Could not auto-install Node.js for this distro.")
        err("Install Node.js 20+ and npm manually, then re-run:")
        err("  https://nodejs.org/en/download/package-manager")
        sys.exit(1)

    if not ask("Install Node.js + npm now?"):
        err("Node.js + npm are required to build the GUI. Aborting.")
        sys.exit(1)

    for pkgs in candidates:
        sudo_try(*(_PKG_INSTALL_CMD[distro] + pkgs))
        if have_node():
            break

    if not have_node():
        err("Node.js / npm still not available after install attempts.")
        err("Please install Node.js 20+ manually and re-run.")
        sys.exit(1)

    node_v = run_capture(["node", "--version"]).stdout.strip()
    npm_v = run_capture(["npm", "--version"]).stdout.strip()
    ok(f"Node.js {node_v} / npm {npm_v} installed")

def install_frontend_deps():
    """Install the GUI's npm dependencies so `npm run build` (vite) works."""
    step("Installing GUI frontend dependencies (npm)")
    if (GUI_DIR / "node_modules").exists():
        ok("node_modules already present")
        return
    cmd = ["npm", "ci"] if (GUI_DIR / "package-lock.json").exists() else ["npm", "install"]
    info(f"Running: {' '.join(cmd)} (in {GUI_DIR})")
    result = subprocess.run(cmd, cwd=GUI_DIR)
    if result.returncode != 0 and cmd[1] == "ci":
        warn("npm ci failed (lockfile out of sync?) – falling back to npm install")
        result = subprocess.run(["npm", "install"], cwd=GUI_DIR)
    if result.returncode != 0:
        err("npm dependency installation failed")
        sys.exit(result.returncode)
    ok("Frontend dependencies installed")

def ensure_tauri_cli():
    step("Checking cargo-tauri")
    result = run_capture(["cargo", "tauri", "--version"])
    if result.returncode == 0:
        ok(f"cargo-tauri found: {result.stdout.strip()}")
        return
    warn("cargo-tauri not found – installing (this takes a few minutes)...")
    run(["cargo", "install", "tauri-cli"])
    ok("cargo-tauri installed")
