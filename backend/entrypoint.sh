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
# Clear and set rules (DO NOT FLUSH ENTIRE NAT TABLE IN HOST MODE)
# We only want to append our specific masquerade rule.

# IPv4 NAT
# Use -I (Insert) to be at the top of the chain to avoid being blocked by trailing DROP rules.
# Use tun+ wildcard to catch any TUN device name (tun0, tun1, etc.) assigned by the kernel.
iptables -t nat -I POSTROUTING -s $VPN_NETWORK -o $DEFAULT_IFACE -j MASQUERADE
iptables -I FORWARD -i tun+ -j ACCEPT
iptables -I FORWARD -o tun+ -j ACCEPT
iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

# IPv6 Support
echo "Enabling IPv6 Forwarding..."
sysctl -w net.ipv6.conf.all.forwarding=1 || echo "Failed to enable ipv6 forwarding (container might be restricted)"

# IPv6 NAT
ip6tables -t nat -I POSTROUTING -o $DEFAULT_IFACE -j MASQUERADE 2>/dev/null || echo "ip6tables NAT failed"
ip6tables -I FORWARD -i tun+ -j ACCEPT 2>/dev/null
ip6tables -I FORWARD -o tun+ -j ACCEPT 2>/dev/null
ip6tables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null

echo "NAT configured: $VPN_NETWORK -> $DEFAULT_IFACE (IPv4)"
echo "NAT configured: IPv6 -> $DEFAULT_IFACE"

# Verify tables
iptables -t nat -L -v -n
ip6tables -t nat -L -v -n

echo "Executing mavi-vpn binary..."
exec /app/mavi-vpn
