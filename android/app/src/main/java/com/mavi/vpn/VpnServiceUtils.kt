package com.mavi.vpn

internal fun buildEndpoint(host: String, port: String): String {
    val trimmedHost = host.trim()
    if (trimmedHost.startsWith("[") && trimmedHost.contains("]")) {
        val suffix = trimmedHost.substringAfter("]", "")
        return if (suffix.startsWith(":")) trimmedHost else "$trimmedHost:$port"
    }

    val colonCount = trimmedHost.count { it == ':' }
    return when {
        colonCount == 0 -> "$trimmedHost:$port"
        colonCount == 1 -> trimmedHost
        else -> "[$trimmedHost]:$port"
    }
}
