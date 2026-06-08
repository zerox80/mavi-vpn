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
    echo "Enabling TCP MSS clamping..."
    iptables -t mangle -C FORWARD -i tun+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240 2>/dev/null || \
        iptables -t mangle -I FORWARD -i tun+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240
    ip6tables -t mangle -C FORWARD -i tun+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1220 2>/dev/null || \
        ip6tables -t mangle -I FORWARD -i tun+ -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1220 2>/dev/null || true
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
