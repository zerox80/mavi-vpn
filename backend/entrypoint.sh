#!/bin/bash
set -e

echo "Starting Mavi VPN Server..."

# Ensure /dev/net/tun exists
if [ ! -c /dev/net/tun ]; then
    echo "Creating /dev/net/tun node..."
    mkdir -p /dev/net
    mknod /dev/net/tun c 10 200
    chmod 600 /dev/net/tun
fi

# Detect the default gateway interface
# This gets the route to Google DNS, extracts the device name (5th column)
DEFAULT_IFACE=$(ip route get 8.8.8.8 | awk -- '{print $5}')

if [ -z "$DEFAULT_IFACE" ]; then
    echo "Error: Could not detect default interface. Fallback to eth0."
    DEFAULT_IFACE="eth0"
fi

echo "Detected default interface: $DEFAULT_IFACE"

# Enable IP Forwarding (ignore error if read-only)
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "Info: Skipping ip_forward setting (handled by docker or host)"

# Setup NAT (Masquerade)
VPN_NETWORK=${VPN_NETWORK:-"10.8.0.0/24"}
VPN_NETWORK_V6=${VPN_NETWORK_V6:-"fd00::/64"}
# Clear and set rules (DO NOT FLUSH ENTIRE NAT TABLE IN HOST MODE)
# We only want to append our specific masquerade rule.

# IPv4 NAT
# Use -I (Insert) to be at the top of the chain to avoid being blocked by trailing DROP rules.
# Use tun+ wildcard to catch any TUN device name (tun0, tun1, etc.) assigned by the kernel.
iptables -t nat -C POSTROUTING -s $VPN_NETWORK -o $DEFAULT_IFACE -j MASQUERADE 2>/dev/null || \
    iptables -t nat -I POSTROUTING -s $VPN_NETWORK -o $DEFAULT_IFACE -j MASQUERADE
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
if ! ip6tables -t nat -C POSTROUTING -s $VPN_NETWORK_V6 -o $DEFAULT_IFACE -j MASQUERADE 2>/dev/null; then
    ip6tables -t nat -I POSTROUTING -s $VPN_NETWORK_V6 -o $DEFAULT_IFACE -j MASQUERADE 2>/dev/null || echo "ip6tables NAT failed"
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
