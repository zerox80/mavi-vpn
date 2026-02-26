# Builder Stage
FROM rust:1.93-slim AS builder
WORKDIR /app

# Copy workspace files
# 1. Prepare Metadata for Caching
COPY Cargo.toml ./
# Remove non-server members from workspace for Docker build
RUN sed -i '/android\/app\/src\/main\/rust/d' Cargo.toml
RUN sed -i '/\"windows\"/d' Cargo.toml

COPY shared/Cargo.toml ./shared/Cargo.toml
COPY backend/Cargo.toml ./backend/Cargo.toml
COPY external ./external

# 2. Create Dummy Source to Cache Dependencies
RUN mkdir -p shared/src backend/src
RUN echo "fn main() {}" > backend/src/main.rs
RUN touch shared/src/lib.rs

# 3. Build Dependencies (Targeting the workspace)
WORKDIR /app/backend
RUN cargo build --release

# 4. Remove Dummy Artifacts
RUN rm -f /app/target/release/deps/mavi_vpn* /app/target/release/deps/mavi-vpn*
RUN rm -f /app/target/release/deps/shared*

WORKDIR /app

# 5. Copy Real Source
COPY shared ./shared
COPY backend ./backend

# Fix timestamp issue: Ensure source files are newer than dummy build artifacts
RUN touch shared/src/lib.rs backend/src/main.rs

# 6. Build Actual Application
WORKDIR /app/backend
RUN cargo build --release

# Runtime Stage
FROM debian:bookworm-slim
WORKDIR /app

# Install runtime dependencies for VPN/Networking
RUN apt-get update && apt-get install -y \
    iptables \
    iproute2 \
    procps \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/mavi-vpn /app/mavi-vpn
COPY backend/entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh
RUN mkdir -p /app/data

ENTRYPOINT ["/app/entrypoint.sh"]
