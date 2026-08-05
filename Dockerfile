# syntax=docker/dockerfile:1

# Builder Stage
FROM rust:1.97-slim AS builder
WORKDIR /app

# Install git for Cargo to fetch git dependencies
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

# Keep the checked-in workspace manifest and lockfile together. Rewriting the
# workspace member list would require Cargo to rewrite Cargo.lock and is
# therefore incompatible with --locked.
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/app/target,sharing=locked \
    cargo build --release --locked -p mavi-vpn && \
    cp /app/target/release/mavi-vpn /mavi-vpn

# Runtime Stage
FROM debian:trixie-slim
WORKDIR /app

# Install runtime dependencies for VPN/Networking
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    iproute2 \
    procps \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /mavi-vpn /app/mavi-vpn
COPY backend/entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh && mkdir -p /app/data

ENTRYPOINT ["/app/entrypoint.sh"]
