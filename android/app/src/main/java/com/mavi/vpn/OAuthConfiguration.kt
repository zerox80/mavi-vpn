package com.mavi.vpn

import android.util.Log
import java.net.URI

/** Validation and normalization policy for Keycloak and OAuth redirect URLs. */
internal object OAuthConfiguration {
    fun normalizeKeycloakBaseUrl(kcUrl: String): String = kcUrl.trim().trimEnd('/')

    fun validateKeycloakUrl(kcUrl: String): String? {
        val normalized = normalizeKeycloakBaseUrl(kcUrl)
        if (normalized.startsWith("https://")) {
            return null
        }
        if (normalized.startsWith("http://")) {
            val authority =
                normalized
                    .removePrefix("http://")
                    .split('/', '?', '#')
                    .firstOrNull()
                    .orEmpty()
            if (authority.contains('@')) {
                return "Keycloak URL must not contain userinfo; plain HTTP is only allowed for localhost"
            }
            val host =
                if (authority.startsWith("[")) {
                    authority.removePrefix("[").substringBefore(']')
                } else {
                    authority.substringBeforeLast(':', authority)
                }
            if (host == "localhost" || host == "127.0.0.1" || host == "::1") {
                return null
            }
            return "Keycloak URL must use https://; plain HTTP is only allowed for localhost"
        }
        return "Keycloak URL must start with https://"
    }

    fun validateOAuthRedirectUri(
        redirectUri: String,
        allowCustomScheme: Boolean,
    ): String? {
        val normalized = redirectUri.trim()
        val uri =
            try {
                URI(normalized)
            } catch (_: Exception) {
                return "OAuth redirect URI is invalid"
            }

        val scheme = uri.scheme?.lowercase()
        val hasHost = !uri.host.isNullOrBlank()
        val hasPath = !uri.rawPath.isNullOrBlank()
        val hasNoExtras = uri.rawQuery == null && uri.rawFragment == null

        if (scheme == "https" && hasHost && hasPath && hasNoExtras) {
            return null
        }

        if (
            allowCustomScheme &&
            isReverseDnsCustomScheme(scheme) &&
            hasHost &&
            hasPath &&
            hasNoExtras
        ) {
            return null
        }

        return if (allowCustomScheme) {
            "OAuth redirect URI must be https:// with host/path, " +
                "or a reverse-DNS custom scheme for debug builds"
        } else {
            "OAuth redirect URI must be a verified https:// App Link with host/path"
        }
    }

    fun validatedKeycloakBaseUrl(kcUrl: String): String? {
        val error = validateKeycloakUrl(kcUrl)
        if (error != null) {
            Log.e("OAuthHelper", error)
            return null
        }
        return normalizeKeycloakBaseUrl(kcUrl)
    }

    private fun isReverseDnsCustomScheme(scheme: String?): Boolean =
        scheme != null &&
            scheme != "http" &&
            scheme != "https" &&
            "." in scheme
}
