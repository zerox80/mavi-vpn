package com.mavi.vpn

import android.net.VpnService
import org.json.JSONObject

internal interface VpnBuilderAdapter {
    fun addAddress(
        address: String,
        prefixLength: Int,
    )

    fun addRoute(
        address: String,
        prefixLength: Int,
    )

    fun addDnsServer(address: String)
}

internal class AndroidVpnBuilderAdapter(
    private val builder: VpnService.Builder,
) : VpnBuilderAdapter {
    override fun addAddress(
        address: String,
        prefixLength: Int,
    ) {
        builder.addAddress(address, prefixLength)
    }

    override fun addRoute(
        address: String,
        prefixLength: Int,
    ) {
        builder.addRoute(address, prefixLength)
    }

    override fun addDnsServer(address: String) {
        builder.addDnsServer(address)
    }
}

internal fun applyAssignedIpv6Config(
    config: JSONObject,
    builder: VpnBuilderAdapter,
): Boolean {
    if (!jsonHasNonBlankString(config, "assigned_ipv6")) {
        return false
    }

    val assignedIpv6 = config.getString("assigned_ipv6")
    val prefixLength = config.optInt("netmask_v6", 64)
    builder.addAddress(assignedIpv6, prefixLength)
    builder.addRoute("::", 0)

    if (jsonHasNonBlankString(config, "dns_server_v6")) {
        builder.addDnsServer(config.getString("dns_server_v6"))
    }

    return true
}
