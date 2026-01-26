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

# Enable IP Forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Setup NAT (Masquerade)
# Clear existing rules to prevent duplicates
iptables -t nat -F
# Use config from Env or default
VPN_NETWORK=${VPN_NETWORK:-"10.8.0.0/24"}
iptables -t nat -A POSTROUTING -s "$VPN_NETWORK" -o "$DEFAULT_IFACE" -j MASQUERADE

echo "NAT configured: $VPN_NETWORK -> $DEFAULT_IFACE"

# Trap SIGTERM/SIGINT for graceful shutdown
cleanup() {
    echo "Stopping Mavi VPN Server..."
    # Cleanup firewall rules
    if [ -n "$VPN_NETWORK" ] && [ -n "$DEFAULT_IFACE" ]; then
         iptables -t nat -D POSTROUTING -s "$VPN_NETWORK" -o "$DEFAULT_IFACE" -j MASQUERADE || true
    fi
    exit 0
}
trap cleanup SIGTERM SIGINT

# Execute the binary in background to allow trap to work
/app/mavi-vpn &
PID=$!
wait $PID
