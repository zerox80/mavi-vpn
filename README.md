<p align="center">
  <img src="gui/src/logo.png" alt="Mavi VPN" width="120" />
</p>

<h1 align="center">Mavi VPN</h1>

<p align="center">
  <strong>High-performance, censorship-resistant VPN built with Rust</strong>
</p>

<p align="center">
  <a href="#-quick-start"><img src="https://img.shields.io/badge/Quick_Start-blue?style=flat-square" alt="Quick Start" /></a>
  <a href="https://github.com/zerox80/mavi-vpn/actions"><img src="https://img.shields.io/github/actions/workflow/status/zerox80/mavi-vpn/build.yml?style=flat-square&label=Build" alt="Build" /></a>
  <a href="https://github.com/zerox80/mavi-vpn/actions"><img src="https://img.shields.io/github/actions/workflow/status/zerox80/mavi-vpn/test.yml?style=flat-square&label=Tests" alt="Tests" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="MIT License" /></a>
  <img src="https://img.shields.io/badge/Rust-1.94+-orange?style=flat-square&logo=rust" alt="Rust" />
</p>

<img width="948" height="709" alt="image" src="https://github.com/user-attachments/assets/a56f2e27-9065-4115-80c4-81084605df61" />


---

Mavi VPN tunnels all network traffic over **QUIC** (via the [`quinn`](external/quinn) crate) to deliver secure, reliable, low-latency connectivity — even on unstable mobile networks. It supports **Windows**, **Linux**, and **Android** with native clients and an optional cross-platform **Tauri GUI**.

## Key Features

| Category | Feature | Details |
|---|---|---|
| **Censorship Resistance** | Layer 7 Obfuscation | VPN traffic masquerades as **HTTP/3** via ALPN `h3` |
| | Probe Resistance | Unauthorized connections receive a fake **nginx** welcome page (H3 200 OK) |
| | MASQUE / RFC 9484 | Optional `connect-ip` capsule framing for DPI-proof wire format |
| | Encrypted Client Hello | **ECH GREASE** + SNI spoofing via X25519/HPKE (RFC 9180) |
| | Certificate Pinning | SHA-256 cert fingerprint verification on all clients |
| **Performance** | Zero-Copy Path | `bytes`/`BytesMut` across the entire packet pipeline |
| | BBR Congestion Control | Optimized for high-bandwidth, high-latency mobile networks |
| | GSO/GRO | Generic Segmentation Offload to reduce syscall overhead |
| | 4 MB UDP Buffers | Auto-tuned OS-level socket buffers for burst resilience |
| | mimalloc | High-performance memory allocator on the server |
| **Mobile-First** | Seamless Roaming | QUIC connection migration — no handshake restart on IP change |
| | MTU Pinning (1280/1360) | Avoids PMTUD black holes; ICMP PTB signal generation (RFC 4443) |
| | Split Tunneling | Per-app VPN bypass on Android |
| **Auth** | Static Token | Simple pre-shared key authentication |
| | Keycloak OIDC | Enterprise SSO with JWT validation, PKCE, and JWKS rotation |
| **Network** | Dual-Stack | Full IPv4 + IPv6 support (NAT66 via ip6tables) |
| | DNS Isolation | NRPT rules on Windows; per-tunnel DNS on Linux/Android |

## Architecture

```mermaid
graph TD
    subgraph "Client — Windows / Linux / Android"
        GUI["Tauri GUI / CLI / Android App"]
        SVC["Background Service / Daemon / JNI Core"]
        TUN_C["Virtual TUN Adapter"]

        GUI <-->|"IPC (TCP 14433)"| SVC
        SVC <-->|"Packet I/O"| TUN_C
    end

    subgraph "Transport — UDP/QUIC"
        QUIC["QUIC Datagrams\n(or MASQUE connect-ip capsules)"]
    end

    subgraph "Server — Linux Docker Container"
        AUTH["Auth Handshake\n(Token / Keycloak JWT)"]
        HUB["Packet Routing Hub\n(DashMap peer table)"]
        TUN_S["Virtual TUN Adapter"]

        AUTH <--> QUIC
        HUB <--> QUIC
        HUB <-->|"Packet I/O"| TUN_S
    end

    SVC <-->|"QUIC payload ≤1360 bytes"| QUIC
    QUIC <-->|"QUIC payload ≤1360 bytes"| HUB
```

## Project Structure

```
mavi-vpn/
├── backend/            # Linux VPN server (Rust) — QUIC endpoint, IP pool, routing, Keycloak
│   ├── src/
│   │   ├── main.rs           # Entry point, connection accept loop
│   │   ├── config.rs         # CLI/env config (clap)
│   │   ├── state.rs          # AppState: IP pool (v4+v6), peer DashMap
│   │   ├── routing.rs        # TUN reader/writer tasks with local peer cache
│   │   ├── cert.rs           # TLS cert generation & SHA-256 PIN export
│   │   ├── ech.rs            # ECH key generation & ECHConfigList persistence
│   │   ├── keycloak.rs       # OIDC JWT validator with JWKS refresh
│   │   ├── handlers/         # Per-connection QUIC session handler
│   │   ├── network/          # TUN device creation, h3-quinn adapter
│   │   └── server/           # QUIC endpoint builder (BBR, timeouts, buffers)
│   ├── docker-compose.yml    # Full stack: VPN + optional Traefik + Keycloak
│   ├── entrypoint.sh         # iptables NAT, IPv6 forwarding, MSS clamping
│   └── .env.example          # All configuration variables documented
│
├── windows/            # Windows client (Rust) — WinTUN, Service/Client IPC
│   └── src/
│       ├── main.rs           # CLI client (start/stop/status)
│       ├── bin/service.rs    # Windows Service (WinTUN, routing, NRPT DNS)
│       ├── vpn_core.rs       # QUIC tunnel logic, ECH, MASQUE framing
│       └── oauth.rs          # PKCE OAuth2 flow for Keycloak
│
├── linux/              # Linux client (Rust) — TUN via /dev/net/tun, systemd
│   └── src/
│       ├── main.rs           # CLI + daemon mode + IPC client
│       ├── vpn_core.rs       # QUIC tunnel logic with network change detection
│       ├── daemon.rs         # IPC server (TCP 14433) for GUI integration
│       ├── network.rs        # Route setup, DNS config, cleanup
│       └── tun.rs            # Raw TUN device via ioctl
│
├── android/            # Android app (Kotlin + Rust JNI)
│   └── app/src/main/
│       ├── kotlin/           # Jetpack Compose UI, VpnService, NetworkCallback
│       └── rust/src/lib.rs   # JNI core: QUIC, cert pinning, connection migration
│
├── gui/                # Cross-platform Tauri v2 GUI (HTML/CSS/JS + Rust)
│   ├── src/                  # Frontend (vanilla HTML/CSS/JS)
│   └── src-tauri/            # Tauri backend (IPC bridge, system tray, WiX installer)
│
├── shared/             # Shared library (Rust)
│   └── src/
│       ├── lib.rs            # ControlMessage protocol (Auth → Config → Datagrams)
│       ├── icmp.rs           # ICMP "Packet Too Big" generation (RFC 792/4443)
│       ├── ipc.rs            # IPC protocol (SecureIpcRequest, Config, Response)
│       ├── masque.rs         # MASQUE connect-ip: capsules, varints, datagram framing
│       └── hex.rs            # Hex encode/decode utilities
│
├── external/quinn/     # Upstream quinn clone
├── quic-tester/        # DPI probe simulator — verifies censorship resistance
├── docs/               # INSTALLATION.md, NGINX_PROXY.md, whitepaper.tex
├── Dockerfile          # Multi-stage build (rust:1.94 → debian:trixie-slim)
└── .github/workflows/  # CI: build (Linux CLI, Android APK, Linux/Windows GUI), tests
```

## Quick Start

### Server Deployment (Docker)

```bash
cd backend
cp .env.example .env
nano .env                    # Set VPN_AUTH_TOKEN, VPN_PORT, etc.
docker-compose up -d --build
```

Retrieve the certificate PIN for clients:
```bash
cat data/cert_pin.txt
```

> **Port:** The server listens on UDP (default `10443`). Ensure your firewall allows this.

### Windows Client

**Automated (recommended):**
```powershell
# Run PowerShell as Administrator
python install_cli_windows.py      # Installs CLI + Windows Service
python install_gui_windows.py      # Installs Tauri GUI (optional)
```

**Usage:**
```powershell
mavi-vpn-client start     # Connect (prompts for config on first run)
mavi-vpn-client stop      # Disconnect
mavi-vpn-client status    # Check connection status
```

### Linux Client

**Automated (recommended):**
```bash
python3 install_cli_linux.py       # Installs CLI + optional systemd service
python3 install_gui_linux.py       # Installs Tauri GUI (deb/rpm/AppImage)
```

**Usage:**
```bash
sudo mavi-vpn                      # Interactive connect (direct mode)
sudo mavi-vpn daemon &             # Start IPC daemon (for GUI)
mavi-vpn start                     # Connect via daemon
mavi-vpn stop                      # Disconnect
mavi-vpn status                    # Check VPN status
```

### Android Client

1. Install **Rust** targets + `cargo-ndk`:
   ```bash
   cargo install cargo-ndk
   rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
   ```
2. Open the `android/` folder in **Android Studio**
3. Build → Build APK — the Rust core compiles automatically via Gradle

### Tauri GUI (Cross-Platform)

```bash
cd gui
npm install
npm run tauri -- dev       # Development
npm run tauri -- build     # Production (generates MSI/DEB/RPM)
```

## Censorship Resistance Modes

Mavi VPN offers three escalating levels of traffic obfuscation:

| Level | Mode | Wire Format | Activate |
|---|---|---|---|
| **0** | Standard | Raw QUIC datagrams | Default |
| **1** | CR Mode | QUIC + ALPN `h3` + probe resistance | `censorship_resistant: true` |
| **2** | HTTP/3 Framing | Full MASQUE connect-ip (RFC 9484) capsules | `http3_framing: true` |
| **+** | ECH | SNI spoofing + HPKE GREASE (RFC 9180) | Provide `ech_config` hex |

When CR Mode is enabled, the server responds to unauthorized connections with a fabricated HTTP/3 nginx welcome page. This makes the server indistinguishable from a regular web server to active probes and DPI systems.

**ECH** is supported on clients via `EchMode::Grease` — the real SNI is hidden behind a cover domain (e.g. `cloudflare-ech.com`). The server generates and persists the ECH keypair in `data/ech_config_hex.txt`.

## Authentication

### Static Token
Set `VPN_AUTH_TOKEN` on the server. Clients send this token during the QUIC handshake.

### Keycloak OIDC (Enterprise)
Full enterprise SSO with Keycloak:

1. Enable in server `.env`:
   ```bash
   VPN_KEYCLOAK_ENABLED=true
   VPN_KEYCLOAK_URL=https://auth.example.com
   VPN_KEYCLOAK_REALM=mavi-vpn
   VPN_KEYCLOAK_CLIENT_ID=mavi-client
   ```
2. Deploy Keycloak via the included `docker-compose`:
   ```bash
   COMPOSE_FILE=docker-compose.yml:keycloak/docker-compose.yml
   COMPOSE_PROFILES=traefik,keycloak
   ```
3. Clients authenticate via **browser-based PKCE OAuth2** — the CLI/GUI opens a local HTTP server on port `18923`, redirects to Keycloak, and captures the JWT automatically.

> The server validates JWTs using Keycloak's JWKS endpoint with automatic key rotation and constant-time `azp` comparison.

## Performance Tuning

| Setting | Value | Why |
|---|---|---|
| Inner TUN MTU | **1280** | IPv6 minimum — universally supported, avoids fragmentation |
| QUIC Payload | **1360** | Fits within 1460-MTU networks (e.g. Vodafone) without fragmentation |
| Congestion Control | **BBR** | Bandwidth-based, not loss-based — optimal for mobile/high-latency |
| UDP Socket Buffers | **4 MB** | Prevents kernel drops during GSO bursts |
| Allocator | **mimalloc** | Reduces memory allocation latency on the server |
| Release Profile | `lto=true, codegen-units=1, strip=true` | Maximally optimized binary |

## Configuration Reference

All server settings can be configured via environment variables or CLI flags:

| Variable | Default | Description |
|---|---|---|
| `VPN_BIND_ADDR` | `0.0.0.0:4433` | QUIC listen address |
| `VPN_AUTH_TOKEN` | *(required)* | Pre-shared authentication token |
| `VPN_NETWORK` | `10.8.0.0/24` | IPv4 client subnet (supports /8 to /30) |
| `VPN_NETWORK_V6` | `fd00::/64` | IPv6 client subnet (ULA) |
| `VPN_DNS` | `1.1.1.1` | DNS server pushed to clients |
| `VPN_MTU` | `1280` | TUN interface MTU |
| `VPN_CENSORSHIP_RESISTANT` | `false` | Enable Layer 7 obfuscation |
| `VPN_MSS_CLAMPING` | `false` | TCP MSS rewriting via iptables mangle |
| `VPN_ECH_PUBLIC_NAME` | `cloudflare-ech.com` | ECH cover SNI domain |
| `VPN_KEYCLOAK_ENABLED` | `false` | Enable Keycloak JWT auth |
| `VPN_KEYCLOAK_URL` | — | Keycloak server URL |
| `VPN_KEYCLOAK_REALM` | `mavi-vpn` | Keycloak realm name |
| `VPN_KEYCLOAK_CLIENT_ID` | `mavi-client` | Keycloak OIDC client ID |

## Testing

```bash
# Run unit tests (shared crate + backend)
cargo test -p shared --verbose
cargo test -p mavi-vpn --verbose
```

The `quic-tester/` tool simulates a DPI scanner to verify censorship resistance:
```bash
cargo run -p quic-tester -- <server:port>
# Expects HTTP/3 nginx response → confirms probe resistance is active
```

## Documentation

| Document | Description |
|---|---|
| [`docs/INSTALLATION.md`](docs/INSTALLATION.md) | Comprehensive installation guide for all platforms |
| [`docs/NGINX_PROXY.md`](docs/NGINX_PROXY.md) | Deploying behind an existing Nginx with wildcard SSL |
| [`CODEWIKI.md`](CODEWIKI.md) | Deep technical encyclopedia of the entire codebase |
| [`docs/whitepaper.tex`](docs/whitepaper.tex) | Academic whitepaper (LaTeX) |

## Roadmap

- [ ] **Socket Sharding** — `SO_REUSEPORT` for multi-core UDP scaling
- [ ] **eBPF Data Plane** — Kernel-level packet routing for zero-copy efficiency
- [ ] **iOS Support** — Rust core via C-FFI + `NEPacketTunnelProvider`
- [ ] **Server-side ECH** — Full ECH decryption when rustls adds support

## License

[MIT](LICENSE) — Copyright © 2026 [zerox80](https://github.com/zerox80)
