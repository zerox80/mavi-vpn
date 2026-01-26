# Builder Stage
FROM rust:nightly-slim as builder
WORKDIR /app

# Copy workspace files
COPY Cargo.toml ./Cargo.toml
COPY shared ./shared
COPY backend ./backend

# Build from backend directory
WORKDIR /app/backend
RUN cargo build --release

# Runtime Stage
FROM debian:bookworm-slim
WORKDIR /app

# Install runtime dependencies for VPN/Networking
RUN apt-get update && apt-get install -y \
    iptables \
    iproute2 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/backend/target/release/mavi-vpn /app/mavi-vpn
COPY backend/entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh
RUN mkdir -p /app/data

ENTRYPOINT ["/app/entrypoint.sh"]
