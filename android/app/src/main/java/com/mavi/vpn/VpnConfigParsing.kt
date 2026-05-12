package com.mavi.vpn

import org.json.JSONArray
import org.json.JSONObject

internal fun jsonHasNonBlankString(
    config: JSONObject,
    key: String,
): Boolean = !config.isNull(key) && config.optString(key).isNotBlank()

internal fun whitelistDomainsFromConfig(config: JSONObject): List<String> {
    if (config.isNull("whitelist_domains")) {
        return emptyList()
    }

    val value = config.opt("whitelist_domains") ?: return emptyList()
    if (value !is JSONArray) {
        return emptyList()
    }

    return buildList {
        for (i in 0 until value.length()) {
            val domain = value.optString(i, "").trim().trimEnd('.')
            if (domain.isNotEmpty()) {
                add(domain)
            }
        }
    }.distinct()
}

internal fun includeSplitTunnelSelectionIsValid(
    mode: String,
    selectedPackages: Collection<String>,
): Boolean = mode != "include" || selectedPackages.any { it.isNotBlank() }
