package com.mavi.vpn

import android.net.InetAddresses
import android.os.Build
import androidx.annotation.RequiresApi
import java.net.Inet4Address
import java.net.InetAddress

/** Numeric-only parsing: the physical network never authorizes a VPN exception. */
@RequiresApi(Build.VERSION_CODES.Q)
internal fun whitelistAddresses(
    entries: List<String>,
    ipv6Enabled: Boolean,
    parseNumeric: (String) -> InetAddress = InetAddresses::parseNumericAddress,
): List<InetAddress> =
    entries
        .mapNotNull { entry ->
            val numeric =
                if (':' in entry) {
                ipv6Enabled && entry.count { it == ':' } >= 2 && entry.all { it in "0123456789abcdefABCDEF:." }
                } else {
                    val parts = entry.split('.')
                    parts.size == 4 &&
                        parts.all {
                            it.isNotEmpty() &&
                                it.all { c -> c in '0'..'9' } &&
                                (it == "0" || !it.startsWith('0')) &&
                                (it.toIntOrNull() ?: -1) in 0..255
                        }
                }
            if (!numeric) return@mapNotNull null
            try {
                parseNumeric(entry).takeIf { it is Inet4Address || ipv6Enabled }
            } catch (_: IllegalArgumentException) {
                null
            }
        }.distinct()
