# Mavi VPN

Mavi VPN is a high performance modern VPN solution built with Rust and Kotlin. It uses the QUIC protocol to provide secure and reliable connectivity over UDP.

## proper Features

*   **High Performance**: Uses `quinn` for QUIC implementation and `bytes` for zero copy packet handling.
*   **Modern Architecture**: Asynchronous design using `tokio` runtime.
*   **Secure**: TLS 1.3 encryption provided by `rustls`.
*   **Multi Platform Support**: Linux server backend and native Android client.
*   **DNS Configuration**: Supports pushing custom DNS servers to clients (defaults to Cloudflare 1.1.1.1).

## Architecture

The project is organized as a Cargo Workspace with the following components:

*   **backend**: The VPN server implementation. It manages the TURN interface, handles QUIC connections, and routes packets between clients and the internet.
*   **shared**: Common protocol definitions and configuration structures shared between the server and clients.
*   **android**: The native Android application. It uses a Kotlin UI and connects to the core login via JNI.

## Getting Started

### Prerequisites

*   Rust 1.75 or later
*   Android Studio (for mobile client)
*   Docker (optional, for server deployment)

### Running the Server

1.  Navigate to the backend directory.
2.  Run the server using Cargo.
    ```bash
    cargo run --release
    ```

You can configure the server using environment variables or command line arguments.
*   `--bind-addr`: Address to listen on (default: 0.0.0.0:4433)
*   `--dns`: DNS server to push to clients (default: 1.1.1.1)

### Building the Android Client

1.  Open the `android` directory in Android Studio.
2.  Ensure the Rust Android Gradle plugin is configured correctly.
3.  Build and run on an emulator or physical device.

The Android client uses the `shared` crate to ensure protocol compatibility with the server.

## Configuration

The server supports the following configuration options:

*   **VPN_BIND_ADDR**: The socket address to listen on.
*   **VPN_AUTH_TOKEN**: Shared secret for client authentication.
*   **VPN_NETWORK**: The CIDR network range to assign IPs from.
*   **VPN_DNS**: The DNS server address to configure on clients.

## Performance

The codebase has been optimized for high throughput. It avoids unnecessary heap allocations in the hot path by utilizing reference counted byte buffers. This ensures minimal latency and CPU usage even under heavy load.

## License

This project is open source.
