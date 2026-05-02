package com.mavi.vpn

import android.content.Intent
import android.util.Log
import com.mavi.vpn.data.PrefsManager

internal data class VpnStartRequest(
    val ip: String,
    val port: String,
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
        return VpnStartRequest(
            ip = prefs.savedIp,
            port = prefs.savedPort,
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
    if (prefs.savedUseKeycloak) {
        if (token.isNotBlank() && prefs.savedToken.isBlank()) {
            prefs.savedToken = token
        }
    } else {
        prefs.savedToken = token
    }
    prefs.savedPin = pin
    prefs.savedSplitMode = splitMode
    prefs.savedSplitPackages = splitPackages

    return VpnStartRequest(
        ip = ip,
        port = port,
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
