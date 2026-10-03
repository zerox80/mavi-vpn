package com.mavi.vpn.data

import android.content.SharedPreferences
import com.mavi.vpn.KeycloakAuthority
import com.mavi.vpn.KeycloakTokenSnapshot
import com.mavi.vpn.OAuthTokens
import com.mavi.vpn.PendingKeycloakLogin
import org.json.JSONObject
import java.security.MessageDigest
import java.util.UUID

/** One encrypted record binds both tokens to their authority and login generation. */
internal class KeycloakSessionPreferences(
    private val prefs: SharedPreferences,
    private val secrets: SecureStringPreferences,
) {
    companion object {
        // Activity and VPN service can use separate PrefsManager instances.
        private val lock = Any()
        private const val SESSION = "keycloak_session_v2"
        private const val PENDING = "keycloak_pending_v2"
        private const val GENERATION = "keycloak_generation_v2"
    }

    private fun authority(): KeycloakAuthority? =
        KeycloakAuthority.from(
            prefs.getString("saved_kc_url", "").orEmpty(),
            prefs.getString("saved_kc_realm", "mavi-vpn").orEmpty(),
            prefs.getString("saved_kc_client_id", "mavi-client").orEmpty(),
        )

    fun snapshot(): KeycloakTokenSnapshot =
        synchronized(lock) {
            val authority = authority()
            val generation = prefs.getString(GENERATION, "").orEmpty()
            val tokens =
                try {
                    val record = JSONObject(secrets.getString(SESSION))
                    if (authority != null &&
                        generation.isNotBlank() &&
                        KeycloakAuthority.fromJson(record.getJSONObject("authority")) == authority &&
                        record.getString("generation") == generation
                    ) {
                        OAuthTokens(record.getString("access"), record.getString("refresh"))
                    } else {
                        null
                    }
                } catch (_: Exception) {
                    null
                }
            // Legacy saved_token/saved_refresh_token have no proven issuer.
            KeycloakTokenSnapshot(authority, generation, tokens)
        }

    fun replace(
        expected: KeycloakTokenSnapshot,
        tokens: OAuthTokens?,
        invalid: Boolean,
    ): Boolean =
        synchronized(lock) {
            val authority = expected.authority ?: return false
            if (snapshot() != expected) return false
            val record =
                tokens
                    ?.let {
                        JSONObject()
                            .put("authority", authority.toJson())
                            .put("generation", expected.generation)
                            .put("access", it.accessToken)
                            .put("refresh", it.refreshToken)
                            .toString()
                    }.orEmpty()
            secrets.setString(SESSION, record)
            prefs.edit().putBoolean("saved_keycloak_session_invalid", invalid).apply()
            true
        }

    fun updateAuthority(
        url: String,
        realm: String,
        clientId: String,
    ) = synchronized(lock) {
        val changed = authority() != KeycloakAuthority.from(url, realm, clientId)
        val editor =
            prefs
                .edit()
                .putString("saved_kc_url", url)
                .putString("saved_kc_realm", realm)
                .putString("saved_kc_client_id", clientId)
        if (changed) editor.putString(GENERATION, UUID.randomUUID().toString())
        editor.apply()
        if (changed) discardCredentials()
    }

    fun clear() =
        synchronized(lock) {
            prefs.edit().putString(GENERATION, UUID.randomUUID().toString()).apply()
            discardCredentials()
        }

    private fun discardCredentials() {
        secrets.setString(SESSION, "")
        secrets.setString(PENDING, "")
        // Clear legacy access and refresh together: neither may become a PSK.
        prefs
            .edit()
            .remove("saved_token")
            .remove("saved_refresh_token")
            .remove("saved_oauth_state")
            .remove("saved_oauth_code_verifier")
            .putBoolean("saved_keycloak_session_invalid", false)
            .apply()
    }

    fun beginLogin(
        authority: KeycloakAuthority,
        state: String,
        verifier: String,
    ): Boolean =
        synchronized(lock) {
            if (authority() != authority || state.isBlank() || verifier.isBlank()) return false
            clear()
            val snapshot = snapshot()
            secrets.setString(
                PENDING,
                JSONObject()
                    .put("authority", authority.toJson())
                    .put("generation", snapshot.generation)
                    .put("state", state)
                    .put("verifier", verifier)
                    .toString(),
            )
            true
        }

    fun consumeLogin(returnedState: String?): PendingKeycloakLogin? =
        synchronized(lock) {
            if (returnedState.isNullOrBlank()) return null
            val record =
                try {
                    JSONObject(secrets.getString(PENDING))
                } catch (_: Exception) {
                    return null
                }
            val snapshot = snapshot()
            try {
                if (snapshot.authority == null ||
                    snapshot.tokens != null ||
                    KeycloakAuthority.fromJson(record.getJSONObject("authority")) != snapshot.authority ||
                    record.getString("generation") != snapshot.generation ||
                    !MessageDigest.isEqual(
                        returnedState.toByteArray(Charsets.UTF_8),
                        record.getString("state").toByteArray(Charsets.UTF_8),
                    )
                ) {
                    return null
                }
                val verifier = record.getString("verifier")
                if (verifier.isBlank()) return null
                secrets.setString(PENDING, "")
                PendingKeycloakLogin(snapshot, verifier)
            } catch (_: Exception) {
                null
            }
        }
}
