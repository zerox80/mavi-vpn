package com.mavi.vpn

import org.json.JSONObject
import java.net.URI
import java.util.Locale

/** Immutable issuer coordinates captured together with each credential. */
data class KeycloakAuthority(
    val baseUrl: String,
    val realm: String,
    val clientId: String,
) {
    internal fun toJson(): JSONObject =
        JSONObject()
            .put("url", baseUrl)
            .put("realm", realm)
            .put("client_id", clientId)

    companion object {
        fun from(
            url: String,
            realm: String,
            clientId: String,
        ): KeycloakAuthority? {
            if (realm.isBlank() || clientId.isBlank()) return null
            val base = OAuthConfiguration.normalizeKeycloakBaseUrl(url)
            if (OAuthConfiguration.validateKeycloakUrl(base) != null) return null
            return try {
                val uri = URI(base)
                if (uri.host.isNullOrBlank() ||
                    uri.rawUserInfo != null ||
                    uri.rawQuery != null ||
                    uri.rawFragment != null
                ) {
                    return null
                }
                val scheme = uri.scheme.lowercase(Locale.ROOT)
                val host = uri.host.lowercase(Locale.ROOT)
                val port =
                    when {
                        uri.port == -1 ||
                            scheme == "https" &&
                            uri.port == 443 ||
                            scheme == "http" &&
                            uri.port == 80 -> ""
                        else -> ":${uri.port}"
                    }
                KeycloakAuthority("$scheme://$host$port${uri.rawPath.orEmpty()}", realm, clientId)
            } catch (_: Exception) {
                null
            }
        }

        internal fun fromJson(json: JSONObject): KeycloakAuthority? =
            from(json.getString("url"), json.getString("realm"), json.getString("client_id"))
    }
}

data class KeycloakTokenSnapshot(
    val authority: KeycloakAuthority?,
    val generation: String,
    val tokens: OAuthTokens?,
)

internal data class PendingKeycloakLogin(
    val snapshot: KeycloakTokenSnapshot,
    val verifier: String,
)
