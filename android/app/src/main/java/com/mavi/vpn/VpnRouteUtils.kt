package com.mavi.vpn

import android.net.IpPrefix
import android.net.VpnService
import android.os.Build
import android.util.Log
import com.mavi.vpn.service.NotificationHelper
import java.net.Inet4Address
import java.net.InetAddress

internal fun applyWhitelistDomainExclusions(
    builder: VpnService.Builder,
    domains: List<String>,
    ipv6Enabled: Boolean,
    notificationHelper: NotificationHelper,
) {
    if (domains.isEmpty()) {
        return
    }

    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
        val message = "Domain whitelist requires Android 13+ route exclusions; ignoring ${domains.size} domains."
        Log.w("MaviVPN", message)
        notificationHelper.updateNotification(1, "Mavi VPN", message)
        return
    }

    val addresses = linkedSetOf<InetAddress>()
    for (domain in domains) {
        try {
            InetAddress.getAllByName(domain).forEach { address ->
                if (address is Inet4Address || ipv6Enabled) {
                    addresses.add(address)
                }
            }
        } catch (e: Exception) {
            Log.w("MaviVPN", "Failed to resolve whitelist domain '$domain': ${e.message}")
        }
    }

    if (addresses.isEmpty()) {
        Log.w("MaviVPN", "No whitelist domains resolved to IP addresses; no route exclusions applied.")
        return
    }

    for (address in addresses) {
        val prefixLength = if (address is Inet4Address) 32 else 128
        try {
            builder.excludeRoute(IpPrefix(address, prefixLength))
            Log.i("MaviVPN", "Excluded whitelist route ${address.hostAddress}/$prefixLength")
        } catch (e: Exception) {
            Log.w("MaviVPN", "Failed to exclude whitelist route ${address.hostAddress}: ${e.message}")
        }
    }
}

internal fun netmaskToPrefixLength(netmask: String): Int {
    return try {
        val parts = netmask.split(".")
        if (parts.size != 4) return 24
        val mask = parts.fold(0L) { acc, part ->
            val octet = part.toInt()
            if (octet < 0 || octet > 255) return 24
            (acc shl 8) or octet.toLong()
        }
        val prefix = java.lang.Long.bitCount(mask)
        val expected = if (prefix == 0) 0L else (0xFFFFFFFFL shl (32 - prefix)) and 0xFFFFFFFFL
        if (mask != expected) return 24
        prefix
    } catch (e: Exception) {
        24
    }
}
