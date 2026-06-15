package com.mavi.vpn

import android.net.VpnService
import android.os.Build
import android.util.Log
import com.mavi.vpn.service.NotificationHelper
import org.json.JSONObject

/** Raised when the server assigned an IPv6 address but the tunnel could not be
 *  configured for it. Carries the original cause so the caller can run its exact
 *  failure-path side effects (state reset + user notification) and rethrow. */
internal class Ipv6TunnelException(
    message: String,
    cause: Throwable?,
) : Exception(message, cause)

/** Clamps the server-advertised MTU to the range the TUN device supports,
 *  falling back to the conservative default when it is out of range. */
internal fun clampTunnelMtu(serverMtu: Int): Int = if (serverMtu in 1280..1360) serverMtu else 1280

/** Splits a comma-separated package list into trimmed, non-blank entries. */
internal fun parseSplitPackages(splitPackages: String): List<String> =
    splitPackages.split(",").map { it.trim() }.filter { it.isNotEmpty() }

/** Applies include/exclude split tunneling. Unknown modes are a no-op, and a
 *  failure on one package is logged without aborting the rest. */
internal fun applySplitTunneling(
    builder: VpnService.Builder,
    splitMode: String,
    splitPackages: String,
) {
    if (splitMode != "include" && splitMode != "exclude") {
        return
    }

    val packages = parseSplitPackages(splitPackages)
    Log.d("MaviVPN", "Applying Split Tunneling: Mode=$splitMode, Packages=$packages")

    for (pkg in packages) {
        try {
            if (splitMode == "include") {
                builder.addAllowedApplication(pkg)
            } else {
                builder.addDisallowedApplication(pkg)
            }
        } catch (e: Exception) {
            Log.w("MaviVPN", "Failed to add split tunneling for package '$pkg': ${e.message}")
        }
    }
}

/**
 * Configures [builder] from the server [config]: IPv4 address/route/DNS, optional
 * IPv6, whitelist route exclusions, split tunneling, session name, MTU and metering.
 *
 * Does not call [VpnService.Builder.establish] — the caller owns the lifecycle of
 * the resulting interface. Throws [Ipv6TunnelException] if an assigned IPv6 address
 * cannot be applied.
 */
internal fun configureTunnelBuilder(
    builder: VpnService.Builder,
    config: JSONObject,
    splitMode: String,
    splitPackages: String,
    notificationHelper: NotificationHelper,
) {
    val assignedIp = config.getString("assigned_ip")
    val netmask = config.optString("netmask", "255.255.255.0")
    builder.addAddress(assignedIp, netmaskToPrefixLength(netmask))
    builder.addRoute("0.0.0.0", 0)
    builder.addDnsServer(config.optString("dns_server", "8.8.8.8"))

    val hasIpv6 = try {
        applyAssignedIpv6Config(config, AndroidVpnBuilderAdapter(builder))
    } catch (e: Exception) {
        val message = "Failed to configure IPv6 tunnel: ${e.message}"
        Log.e("MaviVPN", message, e)
        throw Ipv6TunnelException(message, e)
    }

    applyWhitelistDomainExclusions(
        builder,
        whitelistDomainsFromConfig(config),
        hasIpv6,
        notificationHelper,
    )

    applySplitTunneling(builder, splitMode, splitPackages)

    builder.setSession("MaviVPN")
    builder.setMtu(clampTunnelMtu(config.optInt("mtu", 1280)))

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
        builder.setMetered(false)
    }
}
