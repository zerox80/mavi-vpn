# Mavi VPN: The Ultimate Technical Encyclopedia (CodeWiki)

## 🌐 1. Project Overview & Vision
Mavi VPN establishes secure, private network connections between devices and a server. The solution supports a QUIC data plane for low-latency operation and an optional HTTP/2 CONNECT-IP data plane over TLS/TCP for networks where TCP is more usable. Its components include a high-performance Rust-based server, client applications for Android, Windows, and Linux, and shared communication logic, primarily implemented in **Rust** and **Kotlin**.

The QUIC communication layer uses the `quinn` library for encrypted UDP transport, streams, and datagrams. The HTTP/2 path uses TLS/TCP, RFC 8441 Extended CONNECT, and RFC 9297 capsules. Both paths share authentication, address assignment, packet validation, and TUN routing.

---

## 🏗 2. Mavi VPN Architecture
Mavi VPN is a high-performance, censorship-resistant VPN solution engineered for unreliable network conditions, particularly prevalent in mobile environments. Its architecture comprises a Rust-based server, clients for Android, Windows, and Linux, and shared libraries that facilitate communication. The transport is selectable: raw QUIC or HTTP/3/MASQUE over UDP, or HTTP/2 CONNECT-IP capsules over TLS/TCP.

The core communication mechanism leverages Rust for performance and memory safety. QUIC provides unreliable datagrams and connection migration; HTTP/2 provides reliable, ordered capsule delivery. The client transport selector keeps HTTP/2 mutually exclusive with censorship-resistant mode, HTTP/3 framing, and ECH.

### 🔹 2.1 Cross-Platform Client Architecture
The client applications are designed for cross-platform compatibility while accounting for platform-specific requirements. 
- **The Android client**, built with **Kotlin** and **Jetpack Compose**, orchestrates the VPN lifecycle and user interface. It integrates with a native Rust library via **JNI (Java Native Interface)** for QUIC or HTTP/2 tunneling and TUN device management.
- **The Windows client**, written in **Rust**, utilizes the **WinTUN** adapter for network interface management. 
This shared Rust core minimizes code duplication and ensures consistent VPN functionality across platforms. For further information on client architectures, see **Cross-Platform Client Architecture**.

---

## 🛡 3. Censorship Resistance Mechanisms
A central design principle of Mavi VPN is censorship resistance. The QUIC censorship-resistant mode disguises VPN traffic as standard **HTTP/3** traffic using **ALPN (Application-Layer Protocol Negotiation)**. HTTP/2 CONNECT-IP is a separate TCP fallback, not an HTTP/3 camouflage mode.

### 🎭 3.1 Layer 7 Obfuscation & ALPN
A core strategy for censorship resistance involves Layer 7 obfuscation, primarily through the use of HTTP/3 Application-Layer Protocol Negotiation (ALPN). When the censorship-resistant mode is enabled, the client's QUIC connection is configured to advertise only the **"h3" ALPN**. This makes the VPN traffic appear as standard HTTP/3 web traffic, a widely used protocol that is less likely to be blocked indiscriminately. This ALPN configuration is evident in the client's connection handshake within `android/app/src/main/rust/src/lib.rs` and is determined by the `censorship_resistant` flag set in the client's settings.

### 🧪 3.2 Probe Resistance & Mock Responses
Probe resistance is another critical component. If an unauthorized client attempts to connect to the Mavi VPN server in censorship-resistant mode and fails authentication, the server does not immediately terminate the connection or send a clear error message. Instead, it is designed to mimic a legitimate HTTP/3 server by sending mock **HTTP/3 frames** (such as SETTINGS, HEADERS, and DATA). This behavior, implemented in the server's connection handling logic in `backend/src/main.rs`, helps to prevent active probes from easily identifying and blocking the VPN service based on connection rejection patterns.

### 🔑 3.3 Certificate Pinning
**Certificate pinning** is employed to protect against man-in-the-middle attacks, which are often a tactic used by censors. Both the Android and Windows clients implement certificate pinning. 
- **Android**: Decodes a pre-configured **SHA256 hash** of the server's cert and uses it to create a `PinnedServerVerifier`. This verifier, detailed in `android/app/src/main/rust/src/lib.rs`, ensures that the client will only trust a server whose certificate matches the pinned hash exactly. 
- **Server**: Side computes and logs its SHA256 PIN, which can then be used by clients for this pinning, as shown in `backend/src/cert.rs`.
This prevent attackers from issuing fake certificates to intercept or impersonate the VPN server.

---

## 🏎 4. MTU and Network Performance Optimizations
A key strategy involves MTU (Maximum Transmission Unit) management. The operator chooses the inner TUN MTU in the range **1280..=1360**; for QUIC transports the outer payload MTU is derived as `VPN_MTU + 80`. HTTP/2 uses TLS/TCP and therefore has no QUIC payload MTU.

### 📐 4.1 The 1280/1360 Pinning Strategy
This configurable range aims to minimize packet fragmentation, which can degrade performance and reliability over diverse network paths.
- **Inner TUN MTU**: `1280..=1360` (1280 is the IPv6 minimum).
- **QUIC Payload MTU**: `VPN_MTU + 80` (1360 when `VPN_MTU=1280`).
By pinning these values, Mavi VPN avoids the "Black Hole" problem of Path MTU Discovery (PMTUD) where ICMP messages are blocked by ISPs.

### 🏎 4.2 Congestion Control: BBR
Congestion control plays a vital role in adapting to varying network capacities. Mavi VPN integrates advanced algorithms such as **BBR (Bottleneck Bandwidth and Round-trip propagation time)** within its QUIC implementation. BBR is designed to achieve higher throughput and lower latency compared to traditional loss-based algorithms like CUBIC. It directly observes network path characteristics (bottleneck bandwidth and min-RTT) rather than solely reacting to packet loss. 

### ⏩ 4.3 Segmentation Offload & GSO
To further enhance data transfer efficiency, Mavi VPN utilizes **Generic Segmentation Offload (GSO)**. This technique offloads the task of segmenting large data packets into smaller segments to the network interface card (NIC) or the kernel driver, reducing CPU overhead on the host system. This is particularly relevant for high-throughput scenarios, as discussed in **Advanced UDP Socket Interface (Quinn-UDP)**.

### 📡 4.4 ICMP "Packet Too Big" & PMTUD
Path MTU Discovery (PMTUD) is crucial for dynamically determining the largest MTU. Mavi VPN implements PMTUD by generating **ICMP "Packet Too Big"** messages (also known as "Destination Unreachable - Fragmentation Needed" for IPv4). When an oversized packet is dropped, the system generates an appropriate ICMP response, enabling the sender to adjust its transmission size. This mechanism is defined by the `generate_packet_too_big` function in `shared/src/icmp.rs`.

---

## 🖥 5. VPN Server Implementation
The server-side components of Mavi VPN facilitate secure and efficient communication by establishing and managing VPN tunnels. Written in **Rust**, the server handles raw QUIC, HTTP/3, and optional HTTP/2 connections, authenticates users, allocates IP addresses, and routes network traffic.

### 🐳 5.1 Dockerized Deployment
The server's lifecycle begins with building and containerization. A multi-stage `Dockerfile` (`backend/Dockerfile`) compiles the Rust application into an optimized binary and packages it with necessary runtime dependencies like `iptables` and `iproute2`. This ensures portability and simplifies deployment.

### 📜 5.2 Server Network Configuration (entrypoint.sh)
The `entrypoint.sh` script (`backend/entrypoint.sh`) dynamically configures the container's networking:
- **TUN Device**: Ensures `/dev/net/tun` exists and has correct permissions.
- **IP Forwarding**: Enables `ip_forward` in the kernel.
- **NAT Masquerading**: Configures `iptables -t nat -A POSTROUTING -o $DEFAULT_IFACE -j MASQUERADE` to allow clients to access the internet.
- **IPv6 Forwarding**: Configures `ip6tables` for full IPv6 NAT support.

### 🔐 5.3 Core Server Logic & Connection Handling (`main.rs`)
The core server logic manages client connections and data flow. It loads server configurations (bind addresses, auth token) and initializes an **`AppState`** (`backend/src/state/mod.rs`) to manage IP address pools.
- **Endpoints**: A `quinn::Endpoint` is configured with performance tunings, including `max_idle_timeout` and `BbrConfig`.
- **Packet Routing**: Dedicated asynchronous tasks read packets from the TUN device and forward them through QUIC datagrams or HTTP/2 `CAPSULE_DATAGRAM` capsules, and vice-versa.
- **Censorship Resistance**: Implements the "Fake Nginx" response logic if authentication fails.

### 👤 5.4 Client Authentication & IP Management
Assignments of virtual IPs is handled by the **`IpGuard`** mechanism.
- **Authentication**: This branch supports both **Token-Based Auth** and **Keycloak OIDC**.
- **IpGuard**: Ensures that assigned IPv4 and IPv6 addresses are automatically released back to the pool when a client disconnects. This RAII pattern prevents IP leaks.
- **IP Pools**: Managed in `backend/src/state/mod.rs` using `free_ips` and `free_ips_v6` vectors for O(1) complexity.

---

## 🧩 6. Advanced Authentication: Keycloak OIDC
*Status: Active feature on `main` (merged from `beta-keycloak`).*

This branch integrates enterprise-grade identity management via **Keycloak**.
- **OIDC Flow**: The server acts as a Resource Server. It fetches public certificates from Keycloak's **JWKS endpoint** on startup (fail-closed — the backend refuses to start if JWKS cannot be loaded, no static-token fallback when `VPN_KEYCLOAK_ENABLED=true`).
- **JWT Validation**: Every client connection is verified against the Keycloak realm. The server uses the `jsonwebtoken` crate (with `aws_lc_rs`) to verify the signature, issuer, and `exp`/`nbf` (30 s leeway). The `azp` (Authorized Party) claim is compared against the configured client ID in **constant time**; built-in audience validation is disabled because Keycloak access tokens default to `aud: account`.
- **In-band Reauth**: A live tunnel is **not** torn down when the original access token expires. QUIC clients present the fresh JWT over a new bidirectional QUIC stream (`ControlMessage::Reauth`); HTTP/2 clients use the `MAVI_REAUTH` capsule. The server re-validates it against JWKS, binds it to the original `sub`, and re-arms the session deadline in place.
- **Token Refresh Lifecycle**: Clients refresh **300 s before `exp`** (`REFRESH_SKEW_SECS`) and check every 30 s (`REFRESH_TICK`). Outcomes are classified as `Success`, `NetworkError` (5xx/transport — keep tunnel, retry), or `NeedsLogin` (4xx — refresh token dead, terminal stop + browser re-login). Refresh tokens are stored only in the OS keyring, never in config files or over IPC.
- **Server Force-Close**: If no successful reauth lands before `exp + 30 s` (`SESSION_EXPIRY_LEEWAY`), the server closes the QUIC connection with reason `b"session token expired"` so revoked/expired credentials cannot keep a session alive.
- **Auto-Imported Realm**: The Keycloak container mounts `backend/keycloak/mavi-vpn-realm.json` and starts with `--import-realm`, so on first start (empty DB) the `mavi-vpn` realm is created automatically with the `mavi-client` public PKCE client, the `vpn-user` realm role, and token lifespans tuned for the VPN refresh cycle (10 min access token / 1 h SSO idle / 24 h SSO max). Operators only need to create users in the Keycloak admin console; the realm and client setup is automated. The import is idempotent — restarts skip it once the realm exists.
- **Benefits**: Centralized MFA, user session management, and granular access control via Keycloak's administration console. Optional fail-closed policy via `VPN_KEYCLOAK_REQUIRED_ROLE` / `VPN_KEYCLOAK_REQUIRED_SCOPE`.

---

## 📱 7. Android VPN Client Deep-Dive
The Android application manages the user interface and integrates with the native Rust core via **JNI**.

### 🏗 7.1 Lifecycle Management
The application's entry point, `MainActivity.kt`, handles user interactions:
- **Consent**: Uses `VpnService.prepare` to gain user consent.
- **Battery Optimization**: Prompts users to exempt the app from optimization to prevent background termination.
- **Persistence**: Settings are saved via `getSharedPreferences`.

### 🛠 7.2 MaviVpnService.kt
The service acts as the bridge to the Rust core.
- **Foreground Service**: Runs with a persistent notification and `WakeLock`.
- **Network Callbacks**: Registers `ConnectivityManager.NetworkCallback` to detect Wi-Fi/LTE switches.
- **Split Tunneling**: Allows specific apps to bypass the VPN using `VpnService.Builder.addAllowedApplication()`.

### 🦀 7.3 JNI Rust Core (`lib.rs`)
The native Rust library handles:
- **QUIC Tunneling**: Establish connection with certificate pinning.
- **Seamless Roaming**: Detects network changes and performs **QUIC Connection Migration**. It sends a burst of packets to the server to immediately refresh the NAT mapping.
- **Tun Management**: Reads/writes raw IP packets using **Tokio**'s asynchronous event loop.

---

## 🪟 8. Windows VPN Client Deep-Dive

### 📂 8.1 Unified Service Architecture
The Windows client uses a separated architecture:
- **WinTUN**: The modern Layer-3 TUN driver is utilized for minimal latency.
- **DNS Isolation (NRPT)**: The client injects **Name Resolution Policy Table** rules for the root domain `.`. This ensures all DNS traffic is locked to the VPN, preventing leaked DNS queries to local ISP servers.

### 🔄 8.2 WinTUN Setup & Routing
- **Driver Extraction**: The client extracts `wintun.dll` from its binary resources on the fly.
- **Routing Rules**: Sets `0.0.0.0/1` and `128.0.0.0/1`.
- **Host Route Exception**: Ensures the VPN server remains reachable via the physical gateway to prevent recursive routing loops.

---

## 📡 9. Core QUIC Protocol Integration (`quinn` internals)
Mavi VPN utilizes the `quinn` library, a pure-Rust implementation of the IETF QUIC protocol.

### 🔹 9.1 Library Architecture
- **Endpoints** (`endpoint.rs`): Central hub for all QUIC activity over a single UDP socket.
- **Connections** (`connection.rs`): Represents an established session.
- **Streams**: High-level API for reliable data transfer (`send_stream.rs` and `recv_stream.rs`).
- **Datagrams**: Unreliable, unordered transfer used for the VPN's IP packet tunnel.

### 🔹 9.2 Quinn-Proto: The Sans-IO State Machine
`quinn-proto` serves as the foundational, deterministic state machine. It handles:
- **Packet Decoding**: Decoding various headers (Initial, Long, Short).
- **Frame Serialization**: Handling Ack, Stream, ConnectionClose, and Datagram frames.
- **Congestion Control**: Pluggable backends for BBR, Cubic, and NewReno.
- **Cryptography**: Abstracted via traits to allow backends like `ring` and `rustls` (specifically **`aws-lc-rs`** for high performance).

### 🔹 9.3 Advanced UDP Socket Interface (Quinn-UDP)
`quinn-udp` provides specialized socket optimizations:
- **GSO/GRO**: Fragmentation offloading.
- **ECN**: Explicit Congestion Notification to signal network stress without dropping packets.
- **Disabled Fragmentation**: Ensures QUIC manages its own MTU logic at the application layer.

---

## 🧪 10. Diagnostic & Testing Suite

### 🛠 10.1 `quic-tester` Client
A specialized client designed for testing and simulating DPI scanners.
- **SSL Bypass**: Uses `SkipServerVerification` to connect to any server without certificate trust.
- **H3 Request Simulation**: Sends minimal GET requests and processes responses.
- **Nginx Check**: Verifies if the server response contains "nginx", confirming that the **Censorship Resistance** logic is active.

### 📊 10.2 Benchmarking & Fuzzing
The `quinn` library includes extensive testing:
- **Bulk Data Benchmarks**: Measures throughput and latency histograms.
- **Fuzz Testing**: Targets packet decoding and stream ID management to ensure protocol robustness.
- **No-Protection Mode**: Allows for Wireshark inspection of QUIC packets without encryption during debugging.

---

## 🔮 11. Technical Roadmap
1. **Socket Sharding**: Implementing `SO_REUSEPORT` for multi-core UDP scaling in the backend.
2. **eBPF Data Plane**: Moving packet routing into the Linux kernel for zero-copy efficiency.
3. **iOS Support**: Bringing the Rust Core to iOS via C-FFI and `NEPacketTunnelProvider`.

---

## 🛠 12. Production Deployment: Behind Nginx
For enterprise setups where an existing Nginx server handles wildcard certificates (443), Mavi VPN should be configured to run on port **11443**.

### 🔹 12.1 Configuration
- **Traefik**: Set `TRAEFIK_HTTPS_PORT=11443` and `TRAEFIK_ACME_RESOLVER=""`.
- **Nginx Proxy**: Use `proxy_pass http://127.0.0.1:11443` to bridge the traffic.

For a full Nginx configuration snippet, see [NGINX_PROXY.md](file:///c:/Daten1/mavi-vpn/docs/NGINX_PROXY.md).

---
**CodeWiki Generation Date**: 2026-03-21 
**Commit Identity**: Main Branch Technical Deep-Dive
**Author**: Antigravity Technical Documentation Subagent
