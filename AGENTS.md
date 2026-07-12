# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

Mavi VPN is a Rust Cargo workspace that tunnels traffic over QUIC (via forked `quinn`/`h3`) by
default, with an optional HTTP/2 CONNECT-IP fallback over TLS/TCP. QUIC can be disguised as HTTP/3
for censorship resistance. It targets a Linux server plus Windows, Linux, and
Android clients, with an optional cross-platform Tauri GUI. `README.md` and `CODEWIKI.md` cover
features and deep internals; this file covers the things that bite you when building and editing.

## Crate name ≠ directory name

Cargo `-p` flags use the package name, which often differs from the folder. Get this wrong and you'll
target the wrong crate or get "package not found":

| Directory | Package name | Notes |
|---|---|---|
| `backend/` | `mavi-vpn` | The Linux VPN **server** |
| `linux/` | `linux-vpn` | Linux client/daemon |
| `windows/` | `windows-vpn` | Windows client + service; **only compiles on Windows** |
| `android/app/src/main/rust/` | `mavivpn` | JNI core (no hyphen) |
| `gui/src-tauri/` | `mavi-vpn-gui` | Tauri backend |
| `shared/` | `shared` | Protocol + shared logic, depended on by all |
| `quic-tester/` | `quic-tester` | DPI probe simulator |

Note `backend` and `linux` *both* produce a binary literally named `mavi-vpn`, but the server is
package `mavi-vpn` and the Linux client is package `linux-vpn`.

## Build, test, lint

```bash
# Tests — portable core only (no Tauri/WebView or OS service deps). Use this by default.
cargo test-core-workspace        # alias: -p shared -p mavivpn -p mavi-vpn -p quic-tester
cargo test -p shared             # focused single-crate runs
cargo test -p shared some_test_name   # a single test by name

# Linux client and (on Windows) the Windows client are not in the core alias:
cargo test -p linux-vpn
cargo test -p windows-vpn        # Windows host only

# GUI Rust backend: frontend assets MUST be built first — Tauri embeds them at compile time.
cd gui && npm ci && npm run build && cd ..
cargo test-gui-backend           # alias: -p mavi-vpn-gui

# Lint / format (CI runs clippy with -D warnings)
cargo fmt
cargo clippy --workspace --exclude windows-vpn --all-targets -- -D warnings   # Linux
cargo clippy -p windows-vpn --all-targets -- -D warnings                      # Windows host

# Frontend (gui/)
cd gui
npm test            # vitest
npm run lint        # eslint
npm run tauri -- dev      # run GUI in dev
npm run tauri -- build    # production bundle (MSI/NSIS/DEB/RPM)
```

Per-platform release builds: `cargo build --release -p linux-vpn` / `-p windows-vpn`. Android builds
through Gradle (`cd android && ./gradlew assembleDebug`, tests `./gradlew testDebugUnitTest`), which
invokes `cargo-ndk` automatically; install it with `cargo install cargo-ndk` and add the Android
rust targets first.

### CI constraints that fail PRs

- **500-line file limit.** `.github/workflows/lint.yml` fails if any `.rs/.kt/.py/.ts/.tsx/.js` file
  exceeds 500 lines. Split into modules rather than letting a file grow past it.
- **`-D warnings` clippy** across the workspace; `Cargo.toml` sets `unsafe_code = "warn"` and
  `clippy::all = "warn"` workspace-wide, so warnings become hard errors in CI.
- `windows-vpn` is excluded from the Linux clippy/test jobs (uses `wintun`, `windows-sys`, stdcall
  ABI) and gets its own `windows-latest` jobs.

## Architecture

### `shared/` is the protocol source of truth
Everything client/server agree on lives here, so changes ripple across all crates. Most important is
`ControlMessage` in `shared/src/lib.rs`, the control-plane handshake exchanged over a **QUIC
bidirectional stream** (length-prefixed `u32` + bincode):

1. In raw QUIC mode, the client opens a bidi stream and sends `Auth { token }` (static token, or a Keycloak JWT).
2. Server replies `Config { assigned_ip, gateway, dns, mtu, optional IPv6… }` or `Error { message }`.
3. The stream closes; in raw QUIC and HTTP/3 mode, subsequent packet data flows as QUIC datagrams,
   not streams. HTTP/2 mode maps setup and packet data to bounded MASQUE capsules instead.
4. Mid-session, a raw QUIC/HTTP/3 client may open a fresh bidi stream and send `Reauth { token }`,
   while an HTTP/2 client sends the equivalent reauthentication capsule. Both extend the session
   deadline without tearing down the tunnel and receive an acceptance result.

When adding a `ControlMessage` variant, **append it** — variant order is the bincode wire format, so
reordering breaks compatibility with older peers.

`shared/` also owns `masque.rs` (MASQUE connect-ip capsule framing for HTTP/3 and HTTP/2 modes), `icmp.rs`
(Packet-Too-Big generation), `ipc.rs` (GUI↔service IPC protocol), and the MTU logic below.

### MTU coupling (a frequent source of bugs)
HTTP/2 mode uses TCP/TLS and has no QUIC payload MTU; the derived payload rule below applies only to QUIC modes.
The operator turns exactly one knob: the inner **TUN MTU** (`VPN_MTU`, allowed range **1280–1360**,
default 1280). The outer **QUIC payload MTU is always derived** as `tun_mtu + QUIC_OVERHEAD_BYTES`
(+80) — never set independently. Server and client must agree on `tun_mtu` or the larger side emits
packets the smaller side rejects. See `resolve_tun_mtu*` and the `mtu` module in `shared/`.

### Per-platform clients share a shape
Each client crate (`linux/`, `windows/`, `android/.../rust/`) has its own `vpn_core` that drives the
selected tunnel transport (ECH GREASE, optional MASQUE framing, certificate pinning, connection-migration handling
on network change) plus platform-specific TUN + routing + DNS:
- `linux/` raw TUN via ioctl (`tun.rs`), routes/DNS in `network.rs`, and a `daemon.rs` IPC server.
- `windows/` WinTUN + a Windows Service (`bin/service.rs`) with NRPT DNS, plus PKCE OAuth (`oauth.rs`).
- `android/` Kotlin `VpnService` + Jetpack Compose UI calling the Rust JNI core in `lib.rs`.

The GUI and CLI talk to the privileged background service over **OS-native local IPC** (Unix socket
on Linux, Windows Named Pipe on Windows) — the GUI never touches the TUN directly.

### Server (`backend/`)
`main.rs` accept loop → per-connection handler in `handlers/`; `state/mod.rs` holds the v4+v6 IP pool and
a `DashMap` peer table; `routing.rs` runs the TUN reader/writer tasks. TLS cert + SHA-256 pin in
`cert.rs`, ECH keypair in `ech.rs`, Keycloak JWKS validation in `keycloak.rs`. Runs as a hardened,
non-privileged Docker container (`backend/docker-compose.yml`, `entrypoint.sh` does iptables NAT and
IPv6 forwarding) — it **cannot** set host sysctls, so IPv6 forwarding must be enabled on the host.

### Censorship-resistance modes (escalating)
Standard raw QUIC → CR mode (ALPN `h3` + fake nginx H3 page for unauthorized probes) → full MASQUE
connect-ip capsule framing. HTTP/2 CONNECT-IP is a separate TLS/TCP fallback and is mutually
exclusive with CR, HTTP/3 framing, and ECH. ECH (SNI spoofing via HPKE GREASE) layers on top of
the QUIC/HTTP/3 paths. `quic-tester/` acts as a DPI probe to verify the server looks like a plain
web server.

## Forked dependencies — always track the latest commit

The `zerox80` forks **must always follow the latest commit of their branch. Never pin them to a
fixed `rev`. Never. Under no circumstances.** `Cargo.toml` `[patch.crates-io]` therefore tracks
them by branch, not by revision:

- `quinn` / `quinn-proto` / `quinn-udp` → `git = "https://github.com/zerox80/quinn", branch = "main"`
- `h3` / `h3-quinn` / `h3-datagram` → `git = "https://github.com/zerox80/h3", branch = "main"`
- `h2` → `git = "https://github.com/zerox80/h2", branch = "master"`

If you ever see a `rev = "..."` on one of these, replace it with the branch above immediately.
To pull the newest commits into `Cargo.lock`, run
`cargo update -p quinn -p quinn-proto -p quinn-udp -p h3 -p h3-quinn -p h3-datagram -p h2`.

`.github/workflows/update-forks.yml` performs that refresh every day and on manual dispatch. It
builds the refreshed lockfile on Linux and Windows in read-only jobs, verifies that `h2` resolves
from `zerox80/h2`, and grants repository write access only to the final `Cargo.lock` commit job.
Keep every fork package in its update list and keep the fork-source verification intact.

Branch discipline that keeps the build green:
- Use `branch = "main"` for the `h3` fork, **not** `master`. The fork's `master` tracks upstream and
  still depends on `quinn 0.11`; `main` carries the QUIC 0.12 + datagram/ECH wiring. Tracking
  `master` pulls in a second `quinn 0.11` and breaks the Android core (`mavivpn`) build.
- The `h2` fork follows upstream's default `master` branch.
- `time` stays pinned to its rev — that is `time-rs/time`, not a `zerox80` fork, so it is out of
  scope for this rule.

The release profile uses `lto=true`, `codegen-units=1`, `panic="abort"`, `strip=true`.
