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
# Clear and set rules
iptables -t nat -F
iptables -t nat -A POSTROUTING -s "$VPN_NETWORK" -o "$DEFAULT_IFACE" -j MASQUERADE

echo "NAT configured: $VPN_NETWORK -> $DEFAULT_IFACE"

# Run the binary
echo "Executing mavi-vpn binary..."
exec /app/mavi-vpn
