package com.mavi.vpn

import android.content.Intent
import android.util.Log
import com.mavi.vpn.data.PrefsManager

internal data class VpnStartRequest(
    val ip: String,
    val port: String,
    val token: String,
    val pin: String,
    val splitMode: String,
    val splitPackages: String,
)

internal fun resolveVpnStartRequest(
    intent: Intent?,
    prefs: PrefsManager,
): VpnStartRequest {
    if (intent == null) {
        Log.i("MaviVPN", "Service restarted by System. Reloading credentials...")
        // Normal mode keeps its credential in savedPresharedKey, Keycloak mode in
        // savedToken. Pick the slot for the active mode so a system restart
        // reconnects with the matching credential.
        val token = if (prefs.savedUseKeycloak) prefs.savedToken else prefs.savedPresharedKey
        return VpnStartRequest(
            ip = prefs.savedIp,
            port = prefs.savedPort,
            token = token,
            pin = prefs.savedPin,
            splitMode = prefs.savedSplitMode,
            splitPackages = prefs.savedSplitPackages,
        )
    }

    val ip = intent.getStringExtra("IP") ?: ""
    val port = intent.getStringExtra("PORT") ?: "4433"
    val token = intent.getStringExtra("TOKEN") ?: ""
    val pin = intent.getStringExtra("PIN") ?: ""
    val splitMode = intent.getStringExtra("SPLIT_MODE") ?: ""
    val splitPackages = intent.getStringExtra("SPLIT_PACKAGES") ?: ""

    prefs.savedIp = ip
    prefs.savedPort = port
    val resolvedToken: String
    if (prefs.savedUseKeycloak) {
        // The worker thread may already hold a fresher access token; only seed
        // savedToken from the intent when it is currently empty.
        if (token.isNotBlank() && prefs.savedToken.isBlank()) {
            prefs.savedToken = token
        }
        resolvedToken = prefs.savedToken
    } else {
        prefs.savedPresharedKey = token
        resolvedToken = token
    }
    prefs.savedPin = pin
    prefs.savedSplitMode = splitMode
    prefs.savedSplitPackages = splitPackages

    return VpnStartRequest(
        ip = ip,
        port = port,
        token = resolvedToken,
        pin = pin,
        splitMode = splitMode,
        splitPackages = splitPackages,
    )
}

internal fun vpnStartHasCredentials(
    prefs: PrefsManager,
    currentToken: String,
): Boolean = if (prefs.savedUseKeycloak) {
    currentToken.isNotEmpty() || prefs.savedRefreshToken.isNotBlank()
} else {
    currentToken.isNotEmpty()
}
