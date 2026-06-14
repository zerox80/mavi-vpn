package com.mavi.vpn

internal fun isAuthFailure(message: String): Boolean {
    val normalized = message.lowercase()
    return normalized.contains("unauthorized") ||
        normalized.contains("auth_failed") ||
        normalized.contains("access denied") ||
        normalized.contains("invalid token") ||
        normalized.contains("invalid keycloak token")
}
