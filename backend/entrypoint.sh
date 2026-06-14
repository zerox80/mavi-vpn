#!/bin/bash
set -e

echo "Starting Mavi VPN Server..."

if [ "${VPN_KEYCLOAK_ENABLED:-false}" != "true" ]; then
    case "${VPN_AUTH_TOKEN:-}" in
        ""|"change_me"|"change-me"|"changeme")
            echo "Error: Set a non-default VPN_AUTH_TOKEN or enable VPN_KEYCLOAK_ENABLED=true." >&2
            exit 1
            ;;
    esac
fi

# The compose file mounts /dev/net/tun explicitly. Do not create device nodes
# from inside the container; that requires broader privileges than the server
# should need at runtime.
if [ ! -c /dev/net/tun ]; then
    echo "Error: /dev/net/tun is not available. Mount it with devices: /dev/net/tun:/dev/net/tun." >&2
    exit 1
fi

# Detect the default gateway interface
# This gets the route to Google DNS, extracts the device name (5th column)
DEFAULT_IFACE=$(ip route get 8.8.8.8 | awk -- '{print $5}')

if [ -z "$DEFAULT_IFACE" ]; then
    echo "Error: Could not detect default interface. Fallback to eth0."
    DEFAULT_IFACE="eth0"
fi

echo "Detected default interface: $DEFAULT_IFACE"
case "$DEFAULT_IFACE" in
    ""|*[!a-zA-Z0-9_.:-]*)
        echo "Error: Refusing unsafe default interface value: $DEFAULT_IFACE" >&2
        exit 1
        ;;
esac

# Enable IP Forwarding (ignore error if read-only)
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "Info: Skipping ip_forward setting (handled by docker or host)"

# Setup NAT (Masquerade)
VPN_NETWORK=${VPN_NETWORK:-"10.8.0.0/24"}
VPN_NETWORK_V6=${VPN_NETWORK_V6:-"fd00::/64"}
case "$VPN_NETWORK" in
    *[!0-9./]*|""|*/*/*)
        echo "Error: Refusing unsafe VPN_NETWORK value: $VPN_NETWORK" >&2
        exit 1
        ;;
esac
case "$VPN_NETWORK_V6" in
    *[!0-9a-fA-F:./]*|""|*/*/*)
        echo "Error: Refusing unsafe VPN_NETWORK_V6 value: $VPN_NETWORK_V6" >&2
        exit 1
        ;;
esac
# Clear and set rules (DO NOT FLUSH ENTIRE NAT TABLE IN HOST MODE)
# We only want to append our specific masquerade rule.

# IPv4 NAT
# Use -I (Insert) to be at the top of the chain to avoid being blocked by trailing DROP rules.
# Use tun+ wildcard to catch any TUN device name (tun0, tun1, etc.) assigned by the kernel.
iptables -t nat -C POSTROUTING -s "$VPN_NETWORK" -o "$DEFAULT_IFACE" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -I POSTROUTING -s "$VPN_NETWORK" -o "$DEFAULT_IFACE" -j MASQUERADE
iptables -C FORWARD -i tun+ -j ACCEPT 2>/dev/null || \
    iptables -I FORWARD -i tun+ -j ACCEPT
iptables -C FORWARD -o tun+ -j ACCEPT 2>/dev/null || \
    iptables -I FORWARD -o tun+ -j ACCEPT
iptables -C FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
    iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

if [ "${VPN_MSS_CLAMPING:-false}" = "true" ]; then
    # Derive the MSS from the tunnel MTU instead of hardcoding values for the
    # default MTU 1280: MSS = MTU - IP header - TCP header (40 for IPv4, 60 for IPv6).
    VPN_MTU=${VPN_MTU:-1280}
    case "$VPN_MTU" in
        *[!0-9]*|"")
            echo "Error: Refusing non-numeric VPN_MTU value: $VPN_MTU" >&2
            exit 1
            ;;
    esac
    if [ "$VPN_MTU" -lt 1280 ] || [ "$VPN_MTU" -gt 1360 ]; then
        echo "Error: VPN_MTU must be between 1280 and 1360, got: $VPN_MTU" >&2
        exit 1
    fi
    MSS_V4=$((VPN_MTU - 40))
    MSS_V6=$((VPN_MTU - 60))
    echo "Enabling TCP MSS clamping (MTU $VPN_MTU -> MSS $MSS_V4/$MSS_V6)..."
    iptables -t mangle -C FORWARD -i tun+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS_V4" 2>/dev/null || \
        iptables -t mangle -I FORWARD -i tun+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS_V4"
    ip6tables -t mangle -C FORWARD -i tun+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS_V6" 2>/dev/null || \
        ip6tables -t mangle -I FORWARD -i tun+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS_V6" 2>/dev/null || true
fi

# Client isolation: by default, VPN clients must not be able to reach each
# other. Client-to-client packets re-enter the kernel via the TUN device and
# are routed back out of it, so a tun+ -> tun+ FORWARD drop blocks them.
# Inserted last so it ends up at the top of the chain, ahead of the ACCEPTs.
if [ "${VPN_ALLOW_CLIENT_TO_CLIENT:-false}" != "true" ]; then
    echo "Blocking client-to-client traffic (set VPN_ALLOW_CLIENT_TO_CLIENT=true to allow)..."
    iptables -C FORWARD -i tun+ -o tun+ -j DROP 2>/dev/null || \
        iptables -I FORWARD -i tun+ -o tun+ -j DROP
    ip6tables -C FORWARD -i tun+ -o tun+ -j DROP 2>/dev/null || \
        ip6tables -I FORWARD -i tun+ -o tun+ -j DROP 2>/dev/null || true
fi

# IPv6 Support
echo "Enabling IPv6 Forwarding..."
sysctl -w net.ipv6.conf.all.forwarding=1 || echo "Failed to enable ipv6 forwarding (container might be restricted)"

# IPv6 NAT
if ! ip6tables -t nat -C POSTROUTING -s "$VPN_NETWORK_V6" -o "$DEFAULT_IFACE" -j MASQUERADE 2>/dev/null; then
    ip6tables -t nat -I POSTROUTING -s "$VPN_NETWORK_V6" -o "$DEFAULT_IFACE" -j MASQUERADE 2>/dev/null || echo "ip6tables NAT failed"
fi
ip6tables -C FORWARD -i tun+ -j ACCEPT 2>/dev/null || \
    ip6tables -I FORWARD -i tun+ -j ACCEPT 2>/dev/null || true
ip6tables -C FORWARD -o tun+ -j ACCEPT 2>/dev/null || \
    ip6tables -I FORWARD -o tun+ -j ACCEPT 2>/dev/null || true
ip6tables -C FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
    ip6tables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

echo "NAT configured: $VPN_NETWORK -> $DEFAULT_IFACE (IPv4)"
echo "NAT configured: $VPN_NETWORK_V6 -> $DEFAULT_IFACE (IPv6)"

# Verify tables
iptables -t nat -L -v -n
ip6tables -t nat -L -v -n

echo "Executing mavi-vpn binary..."
exec /app/mavi-vpn
