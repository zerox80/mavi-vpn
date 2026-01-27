# Mavi VPN

Mavi VPN is a high performance, modern VPN solution built with Rust and Kotlin. It leverages the QUIC protocol to provide secure, reliable, and low-latency connectivity over UDP.

## Features

*   **High Performance**: Built on `quinn` for QUIC and `bytes` for zero-copy packet handling. Optimized for mobile networks with a default MTU of 1280 to prevent fragmentation.
*   **Seamless Network Switching**: Automatically handles network changes (e.g., Wi-Fi to 5G) without dropping the connection.
*   **Dual Stack Support**: Full support for both IPv4 and IPv6 routing.
*   **Secure**: uses TLS 1.3 encryption provided by `rustls` with Certificate Pinning for enhanced security.
*   **Modern Architecture**: Asynchronous, non-blocking I/O design using the `tokio` runtime.
*   **Multi-Platform**: Linux server backend and a native Android client connected via JNI.
*   **DNS Configuration**: capabilities to push custom DNS servers to clients (defaults to Cloudflare 1.1.1.1).

## Architecture

The project is organized as a Cargo Workspace:

*   **backend**: The VPN server implementation. Manages the TURN/TUN interface, handles QUIC connections, and routes packets.
*   **shared**: Common protocol definitions and configuration structures.
*   **android**: The native Android application. Uses Kotlin for the UI and Rust for the core networking logic via JNI.

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

The client adheres to the server's configuration and will automatically attempt to connect and handle network migrations.

## Configuration

Server configuration is handled via environment variables:

*   `VPN_BIND_ADDR`: Address to listen on (default: `0.0.0.0:4433` inside container).
*   `VPN_AUTH_TOKEN`: Shared secret for client authentication. **Change this to a secure token.**
*   `VPN_NETWORK`: The IPv4 CIDR network range to assign (e.g., `10.8.0.0/24`).
*   `VPN_DNS`: The DNS server to push to clients (default: `1.1.1.1`).
*   `VPN_MTU`: The MTU size used by the VPN interface.

## License

This project is licenced under MIT
