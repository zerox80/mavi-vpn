# Mavi VPN

Mavi VPN is a high-performance, censorship-resistant, modern VPN solution built with Rust and Kotlin. It leverages the QUIC protocol (via `quinn`) to provide secure, reliable, and low-latency connectivity over UDP, designed specifically for unstable mobile networks.

## Features

*   **Censorship Resistance**:
    *   **layer 7 Obfuscation**: Camouflages VPN traffic as standard HTTP/3 traffic.
    *   **Probe Resistance**: actively detects unauthorized probes and responds with fake HTTP 200 OK HTML pages (mimicking Nginx) instead of dropping packets or sending protocol errors.
    *   **Strict ALPN**: Uses `h3` ALPN negotiation to blend in with valid web traffic.
*   **High Performance**:
    *   **Core**: Built on `quinn` for robust QUIC implementation and `bytes` for zero-copy packet handling.
    *   **Congestion Control**: Uses BBR (Bottleneck Bandwidth and Round-trip propagation time) for optimal throughput and latency.
    *   **Optimization**: Enables Segmentation Offload (GSO) and tuned buffer sizes (1MB/512KB) to prevent bufferbloat.
*   **Mobile-First Design**:
    *   **Seamless Roaming**: Automatically handles network changes (e.g., Wi-Fi to 5G) without dropping the connection or requiring a handshake restart.
    *   **MTU Optimization**: Uses an Inner MTU of **1280** bytes to prevent fragmentation on all cellular networks. Wire MTU is set to **1360** bytes to accommodate headers.
    *   **Battery Efficient**: Uses non-blocking asynchronous I/O (`tokio`) to minimize resource usage.
*   **Dual Stack Support**: Full support for both IPv4 and IPv6 routing.
*   **Security**:
    *   **Encryption**: TLS 1.3 encryption provided by `rustls`.
    *   **Certificate Pinning**: The Android client enforces certificate pinning to prevent MitM attacks.
    *   **Token Authentication**: Simple but secure token-based authentication.
*   **Android Client**:
    *   Native Android application (Kotlin) with a Rust JNI backend.
    *   **Credential Persistence**: Automatically saves and restores connection details.
    *   **Auto-Reconnection**: Robust logic to recover from sleep or network loss.
*   **DNS Configuration**: Pushes custom DNS servers to clients (defaults to Cloudflare 1.1.1.1).

## Architecture

The project is organized as a Cargo Workspace:

*   **backend**: The VPN server implementation. Manages the TUN interface, handles QUIC connections, performs NAT, and enforces censorship resistance logic.
*   **shared**: Common protocol definitions (Control Messages, Configuration) shared between client and server.
*   **android**: The native Android application.
    *   `app/src/main/java`: Kotlin UI and Service logic.
    *   `app/src/main/rust`: Rust JNI layer handling low-level QUIC networking.

## Getting Started

### Prerequisites

*   Rust 1.75 or later
*   Android Studio (for mobile client)
*   Docker & Docker Compose (for server deployment)

### Running the Server

The easiest way to run the server is using Docker Compose.

1.  Navigate to the `backend` directory.
2.  Ensure you have a `.env` file or set the necessary environment variables.
3.  Run:
    ```bash
    docker-compose up -d --build
    ```

### Building the Android Client

1.  Open the `android` directory in Android Studio.
2.  Sync the project with Gradle.
3.  Build and run on an emulator or physical device.
4.  **Note**: Ensure the server's `VPN_CERT` (public key) pin is available to the client if pinning is enabled.

## Configuration

Server configuration is handled via environment variables (or `.env` file):

*   `VPN_BIND_ADDR`: Address to listen on (default: `0.0.0.0:4433`).
*   `VPN_AUTH_TOKEN`: Shared secret for client authentication. **Change this to a secure token.**
*   `VPN_NETWORK`: The IPv4 CIDR network range to assign (e.g., `10.8.0.0/24`).
*   `VPN_DNS`: The DNS server to push to clients (default: `1.1.1.1`).
*   `VPN_MTU`: The Inner MTU size. **Must be 1280** for mobile compatibility.
*   `VPN_CENSORSHIP_RESISTANT`: Set to `true` to enable Probe Resistance and `h3` ALPN masking.

## License

This project is licensed under MIT.
