package com.mavi.vpn

import android.util.Log
import com.mavi.vpn.data.PrefsManager
import kotlinx.coroutines.runBlocking

internal fun startKeycloakRefreshTicker(
    prefs: PrefsManager,
    tokenManager: KeycloakTokenManager,
    isSessionActive: () -> Boolean,
    onSessionExpired: () -> Unit,
): Thread? {
    if (!prefs.savedUseKeycloak) {
        return null
    }

    return Thread {
        while (isSessionActive()) {
            try {
                repeat(60) {
                    if (!isSessionActive()) {
                        return@Thread
                    }
                    Thread.sleep(1000)
                }

                when (val tokenResult = runBlocking { tokenManager.getUsableAccessToken(skewSeconds = 300) }) {
                    is TokenAcquireResult.Usable -> {
                        if (tokenResult.refreshed) {
                            Log.i("MaviVPN", "Refreshed Keycloak token while VPN session is active.")
                        }
                    }
                    is TokenAcquireResult.TemporaryFailure -> {
                        Log.w("MaviVPN", "Active-session Keycloak refresh temporarily failed: ${tokenResult.message}")
                    }
                    is TokenAcquireResult.NeedsLogin -> {
                        Log.e("MaviVPN", "Keycloak session expired during active VPN session: ${tokenResult.message}")
                        onSessionExpired()
                        return@Thread
                    }
                }
            } catch (_: InterruptedException) {
                return@Thread
            } catch (e: Exception) {
                Log.w("MaviVPN", "Active-session Keycloak refresh check failed: ${e.message}")
            }
        }
    }.also {
        it.name = "MaviVPN-KeycloakRefresh"
        it.start()
    }
}

internal fun stopKeycloakRefreshTicker(refreshTicker: Thread?) {
    if (refreshTicker == null) {
        return
    }

    try {
        refreshTicker.interrupt()
        refreshTicker.join(1000)
    } catch (_: Exception) {
    }
}
