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
VPN_TUN_DEVICE=${VPN_TUN_DEVICE:-"mavi0"}
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
case "$VPN_TUN_DEVICE" in
    ""|*[!a-zA-Z0-9_.:-]*)
        echo "Error: Refusing unsafe VPN_TUN_DEVICE value: $VPN_TUN_DEVICE" >&2
        exit 1
        ;;
esac
export VPN_TUN_DEVICE

# All host-namespace firewall state is isolated in named chains. This lets us
# replace stale rules on every start and remove exactly our own rules on exit.
delete_managed_chain() {
    binary=$1
    table=$2
    parent=$3
    chain=$4
    command -v "$binary" >/dev/null 2>&1 || return 0
    while "$binary" -t "$table" -C "$parent" -j "$chain" 2>/dev/null; do
        "$binary" -t "$table" -D "$parent" -j "$chain" 2>/dev/null || break
    done
    "$binary" -t "$table" -F "$chain" 2>/dev/null || true
    "$binary" -t "$table" -X "$chain" 2>/dev/null || true
}

cleanup_firewall() {
    delete_managed_chain iptables filter FORWARD MAVI_VPN_FORWARD
    delete_managed_chain iptables nat POSTROUTING MAVI_VPN_NAT
    delete_managed_chain iptables mangle FORWARD MAVI_VPN_MSS
    delete_managed_chain ip6tables filter FORWARD MAVI_VPN6_FORWARD
    delete_managed_chain ip6tables nat POSTROUTING MAVI_VPN6_NAT
    delete_managed_chain ip6tables mangle FORWARD MAVI_VPN6_MSS
}

# Clean up leftovers from an ungraceful previous container termination. The
# EXIT trap also covers setup failures after only some rules were installed.
cleanup_firewall
trap cleanup_firewall EXIT

# IPv4 NAT
iptables -t nat -N MAVI_VPN_NAT
iptables -t nat -A MAVI_VPN_NAT -s "$VPN_NETWORK" -o "$DEFAULT_IFACE" -j MASQUERADE
iptables -t nat -I POSTROUTING 1 -j MAVI_VPN_NAT

iptables -N MAVI_VPN_FORWARD
if [ "${VPN_ALLOW_CLIENT_TO_CLIENT:-false}" != "true" ]; then
    echo "Blocking client-to-client traffic (set VPN_ALLOW_CLIENT_TO_CLIENT=true to allow)..."
    iptables -A MAVI_VPN_FORWARD -i "$VPN_TUN_DEVICE" -o "$VPN_TUN_DEVICE" -j DROP
fi
iptables -A MAVI_VPN_FORWARD -i "$VPN_TUN_DEVICE" -j ACCEPT
iptables -A MAVI_VPN_FORWARD -o "$VPN_TUN_DEVICE" -j ACCEPT
iptables -I FORWARD 1 -j MAVI_VPN_FORWARD

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
    iptables -t mangle -N MAVI_VPN_MSS
    iptables -t mangle -A MAVI_VPN_MSS -i "$VPN_TUN_DEVICE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS_V4"
    iptables -t mangle -I FORWARD 1 -j MAVI_VPN_MSS
    if [ -e /proc/sys/net/ipv6/conf/all/forwarding ] && [ "${VPN_DISABLE_IPV6:-false}" != "true" ]; then
        ip6tables -t mangle -N MAVI_VPN6_MSS
        ip6tables -t mangle -A MAVI_VPN6_MSS -i "$VPN_TUN_DEVICE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS_V6"
        ip6tables -t mangle -I FORWARD 1 -j MAVI_VPN6_MSS
    fi
fi

echo "NAT configured: $VPN_NETWORK -> $DEFAULT_IFACE (IPv4)"

# ---------------------------------------------------------------------------
# IPv6 support (NAT66 for VPN clients on the ULA prefix $VPN_NETWORK_V6).
#
# On RA-based clouds (e.g. AWS Lightsail) the WAN gets its IPv6 address and
# default route from Router Advertisements. Turning the host into a router by
# enabling forwarding makes Linux stop accepting RAs (and drop the default
# route) unless accept_ra=2 is set on the WAN interface.
#
# This container is intentionally hardened (cap-based, non-privileged), so
# /proc/sys is read-only and it usually cannot write net sysctls itself. We
# therefore attempt the sysctls best-effort, then VERIFY the resulting kernel
# state and fail loudly with host-setup guidance instead of pretending IPv6
# works. ip6tables (NAT66/FORWARD) does work via netlink + CAP_NET_ADMIN.
# ---------------------------------------------------------------------------
if [ ! -e /proc/sys/net/ipv6/conf/all/forwarding ]; then
    echo "Info: IPv6 is disabled in this kernel; running IPv4-only."
elif [ "${VPN_DISABLE_IPV6:-false}" = "true" ]; then
    echo "Info: VPN_DISABLE_IPV6=true; skipping IPv6 setup (IPv4-only)."
else
    echo "Configuring IPv6 (WAN interface: $DEFAULT_IFACE)..."

    ip6tables -N MAVI_VPN6_FORWARD
    if [ "${VPN_ALLOW_CLIENT_TO_CLIENT:-false}" != "true" ]; then
        ip6tables -A MAVI_VPN6_FORWARD -i "$VPN_TUN_DEVICE" -o "$VPN_TUN_DEVICE" -j DROP
    fi
    ip6tables -A MAVI_VPN6_FORWARD -i "$VPN_TUN_DEVICE" -j ACCEPT
    ip6tables -A MAVI_VPN6_FORWARD -o "$VPN_TUN_DEVICE" -j ACCEPT
    ip6tables -I FORWARD 1 -j MAVI_VPN6_FORWARD

    # Keep accepting Router Advertisements even once forwarding is enabled, so
    # the WAN keeps its RA-derived global address and default route. Each is
    # guarded by its /proc entry and best-effort (the host may own these).
    if [ -e "/proc/sys/net/ipv6/conf/${DEFAULT_IFACE}/accept_ra" ]; then
        sysctl -w "net.ipv6.conf.${DEFAULT_IFACE}.accept_ra=2" >/dev/null 2>&1 || true
    fi
    if [ -e "/proc/sys/net/ipv6/conf/${DEFAULT_IFACE}/accept_ra_defrtr" ]; then
        sysctl -w "net.ipv6.conf.${DEFAULT_IFACE}.accept_ra_defrtr=1" >/dev/null 2>&1 || true
    fi
    if [ -e "/proc/sys/net/ipv6/conf/${DEFAULT_IFACE}/autoconf" ]; then
        sysctl -w "net.ipv6.conf.${DEFAULT_IFACE}.autoconf=1" >/dev/null 2>&1 || true
    fi

    # Give RA-based providers (Lightsail) time to bring up the global address
    # before deciding whether IPv6 routing is expected to work. Breaks as soon
    # as an address appears, so there is no delay when IPv6 is already up.
    VPN_IPV6_WAIT=${VPN_IPV6_WAIT:-30}
    case "$VPN_IPV6_WAIT" in
        *[!0-9]*|"") VPN_IPV6_WAIT=30 ;;
    esac
    have_global_v6=false
    waited=0
    while [ "$waited" -lt "$VPN_IPV6_WAIT" ]; do
        if ip -6 addr show dev "$DEFAULT_IFACE" scope global 2>/dev/null | grep -q 'inet6 '; then
            echo "IPv6 address detected on $DEFAULT_IFACE"
            have_global_v6=true
            break
        fi
        waited=$((waited + 1))
        sleep 1
    done

    if [ "$have_global_v6" != "true" ]; then
        echo "Warning: no global IPv6 on $DEFAULT_IFACE after ${VPN_IPV6_WAIT}s; continuing IPv4-only."
        echo "         (Set VPN_DISABLE_IPV6=true to skip this wait on IPv4-only hosts.)"
    else
        # Enable IPv6 forwarding. Do not trust the command's exit code -- the
        # container's /proc/sys may be read-only -- verify the result below.
        sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1 || true
        # Enabling forwarding can reset RA handling, so re-assert accept_ra=2.
        if [ -e "/proc/sys/net/ipv6/conf/${DEFAULT_IFACE}/accept_ra" ]; then
            sysctl -w "net.ipv6.conf.${DEFAULT_IFACE}.accept_ra=2" >/dev/null 2>&1 || true
        fi

        if [ "$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null)" != "1" ]; then
            echo "Error: IPv6 forwarding is not enabled (net.ipv6.conf.all.forwarding != 1)." >&2
            echo "       This hardened container cannot write host sysctls (/proc/sys is" >&2
            echo "       read-only without privileged mode), and $DEFAULT_IFACE has public" >&2
            echo "       IPv6, so enable forwarding on the HOST and restart the container:" >&2
            echo "         sudo sysctl -w net.ipv6.conf.all.forwarding=1" >&2
            echo "         sudo sysctl -w net.ipv6.conf.${DEFAULT_IFACE}.accept_ra=2" >&2
            echo "       Persist it in /etc/sysctl.d/99-mavi-vpn.conf (see docs/INSTALLATION.md)." >&2
            echo "       To intentionally run IPv4-only, set VPN_DISABLE_IPV6=true." >&2
            exit 1
        fi

        # NAT66 for the VPN ULA prefix -> WAN. Fail loudly if it cannot be added.
        ip6tables -t nat -N MAVI_VPN6_NAT
        ip6tables -t nat -A MAVI_VPN6_NAT -s "$VPN_NETWORK_V6" -o "$DEFAULT_IFACE" -j MASQUERADE
        ip6tables -t nat -I POSTROUTING 1 -j MAVI_VPN6_NAT

        echo "NAT66 configured: $VPN_NETWORK_V6 -> $DEFAULT_IFACE (IPv6)"
    fi

    # Diagnostics (printed at startup to make IPv6 state obvious).
    echo "----- IPv6 diagnostics -----"
    echo "Default interface: $DEFAULT_IFACE"
    echo "IPv6 forwarding:   $(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo unknown)"
    echo "$DEFAULT_IFACE accept_ra: $(cat "/proc/sys/net/ipv6/conf/${DEFAULT_IFACE}/accept_ra" 2>/dev/null || echo unknown)"
    ip -6 addr show dev "$DEFAULT_IFACE" || true
    ip -6 route show default || true
    ip6tables -t nat -S POSTROUTING | grep -- "$VPN_NETWORK_V6" || true
    echo "----------------------------"
fi

# Verify tables
iptables -t nat -L -v -n
ip6tables -t nat -L -v -n

echo "Executing mavi-vpn binary..."
SERVER_PID=""
forward_signal() {
    signal=$1
    trap - TERM INT
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill -s "$signal" "$SERVER_PID"
        wait "$SERVER_PID"
    fi
    exit 0
}
trap 'forward_signal TERM' TERM
trap 'forward_signal INT' INT

/app/mavi-vpn &
SERVER_PID=$!
set +e
wait "$SERVER_PID"
SERVER_STATUS=$?
set -e
exit "$SERVER_STATUS"
