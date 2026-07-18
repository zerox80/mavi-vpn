package com.mavi.vpn

import android.os.ParcelFileDescriptor
import android.util.Log
import com.mavi.vpn.data.PrefsManager
import com.mavi.vpn.nativelib.NativeLib
import com.mavi.vpn.service.NotificationHelper
import kotlinx.coroutines.runBlocking
import org.json.JSONObject

internal data class VpnSessionCallbacks(
    val isRunning: () -> Boolean,
    val setRunning: (Boolean) -> Unit,
    val setConnected: (Boolean) -> Unit,
    val attachInterface: (ParcelFileDescriptor?) -> Unit,
    val detachInterface: (ParcelFileDescriptor?) -> Unit,
    val releaseNativeHandle: (Long, Boolean) -> Unit,
)

/** Owns the blocking reconnect/handshake/TUN loop for one service generation. */
internal class VpnSessionWorker(
    private val vpnService: MaviVpnService,
    private val request: VpnStartRequest,
    private val prefs: PrefsManager,
    private val notificationHelper: NotificationHelper,
    private val tokenManager: KeycloakTokenManager,
    private val handleRegistry: SessionHandleRegistry,
    private val sessionGeneration: Long,
    private val callbacks: VpnSessionCallbacks,
) {
    fun createThread(): Thread = Thread { runSessionLoop() }

    private fun isCurrentSessionActive(): Boolean =
        callbacks.isRunning() && handleRegistry.isCurrent(sessionGeneration)

    private fun runSessionLoop() {
        Log.d("MaviVPN", "Starting VPN Thread")
        var currentToken = request.token
        var forcedRefreshCount = 0

        while (isCurrentSessionActive()) {
            try {
                var retryCount = 0
                // Handle adopted by THIS worker for the current attempt. Kept
                // in a local so we never read back a foreign generation's
                // handle from the shared registry.
                var acquiredHandle = 0L
                val crMode = prefs.savedCensorshipResistant

                while (isCurrentSessionActive()) {
                    if (prefs.savedUseKeycloak) {
                        when (
                            val tokenResult = runBlocking {
                                tokenManager.getUsableAccessToken(skewSeconds = 300)
                            }
                        ) {
                            is TokenAcquireResult.Usable -> {
                                currentToken = tokenResult.accessToken
                                if (tokenResult.refreshed) {
                                    Log.i("MaviVPN", "Successfully refreshed Keycloak token.")
                                }
                            }
                            is TokenAcquireResult.TemporaryFailure -> {
                                Log.w(
                                    "MaviVPN",
                                    "Keycloak refresh temporarily failed (${tokenResult.message}). Waiting before retry.",
                                )
                                Thread.sleep(3000)
                                continue
                            }
                            is TokenAcquireResult.NeedsLogin -> {
                                Log.e(
                                    "MaviVPN",
                                    "Keycloak session cannot be refreshed: ${tokenResult.message}",
                                )
                                callbacks.setRunning(false)
                                notificationHelper.updateNotification(
                                    1,
                                    "Mavi VPN",
                                    "Keycloak session expired. Please login again.",
                                )
                                break
                            }
                        }
                    }

                    if (!isCurrentSessionActive()) {
                        break
                    }

                    Log.d(
                        "MaviVPN",
                        "Attempting connection to ${request.ip}:${request.port} (Attempt ${++retryCount})",
                    )

                    if (retryCount > 1) {
                        notificationHelper.updateNotification(
                            1,
                            "Mavi VPN",
                            "Retrying connection to ${request.ip} (Attempt $retryCount)...",
                        )
                    }

                    val handle =
                        NativeLib.init(
                            vpnService,
                            currentToken,
                            buildEndpoint(request.ip, request.port),
                            request.pin,
                            crMode,
                            prefs.savedHttp3Framing,
                            prefs.savedHttp2Framing,
                            prefs.savedEchConfig,
                            prefs.savedVpnMtu,
                        )
                    // Valid 64-bit pointers on Android MTE/TBI can be negative when cast to a signed Long.
                    // NativeLib error codes are strictly in the range [-3, 0].
                    if (handle in -3L..0L) {
                        val initError = NativeLib.getLastInitError()
                        if (handle < 0L) {
                            val retryToken =
                                handleFatalHandshakeFailure(
                                    initError = initError,
                                    forcedRefreshCount = forcedRefreshCount,
                                    currentToken = currentToken,
                                    onRefreshAttempt = { forcedRefreshCount++ },
                                )
                            if (retryToken != null) {
                                currentToken = retryToken
                                continue
                            }
                            callbacks.setConnected(false)
                            callbacks.setRunning(false)
                            notificationHelper.updateNotification(
                                1,
                                "Mavi VPN",
                                if (initError.isNotBlank()) {
                                    initError
                                } else {
                                    "Connection aborted. Check your configuration."
                                },
                            )
                            break
                        }

                        Log.e(
                            "MaviVPN",
                            "Handshake failed. ${if (initError.isNotBlank()) initError else "Retrying in 2 seconds..."}",
                        )
                        repeat(4) {
                            if (callbacks.isRunning()) Thread.sleep(500)
                        }
                        continue
                    }

                    retryCount = 0
                    forcedRefreshCount = 0
                    // Adopt the handle only if this worker is still the
                    // current session. If a stop/restart bumped the
                    // generation while init was blocking on the network,
                    // this handle is an orphan: stop+free it so its QUIC
                    // connection (and the server-side IP lease) is released
                    // instead of leaking, then let the loop unwind.
                    if (handleRegistry.tryAdopt(handle, sessionGeneration)) {
                        acquiredHandle = handle
                    } else {
                        Log.w("MaviVPN", "Discarding orphaned session handle from superseded start")
                        NativeLib.stop(handle)
                        NativeLib.free(handle)
                    }
                    break
                }

                if (!isCurrentSessionActive()) {
                    // Superseded after a successful adopt but before the loop
                    // started: free our own handle so it does not leak.
                    if (acquiredHandle != 0L) {
                        callbacks.releaseNativeHandle(acquiredHandle, true)
                    }
                    continue
                }

                runEstablishedSession(acquiredHandle)
            } catch (e: Exception) {
                Log.e("MaviVPN", "Critical error in VPN thread: ${e.message}")
                try {
                    Thread.sleep(500)
                } catch (_: Exception) {
                }
            }

            if (!isCurrentSessionActive()) {
                break
            }

            if (callbacks.isRunning()) {
                try {
                    Thread.sleep(500)
                } catch (_: Exception) {
                    // Ignore
                }
            }
        }
        if (handleRegistry.isCurrent(sessionGeneration)) {
            vpnService.stopSelf()
        }
    }

    /** Returns a freshly acquired token when the connection should be retried. */
    private fun handleFatalHandshakeFailure(
        initError: String,
        forcedRefreshCount: Int,
        currentToken: String,
        onRefreshAttempt: () -> Unit,
    ): String? {
        Log.e("MaviVPN", "Fatal handshake failure: $initError")
        if (!prefs.savedUseKeycloak || !isAuthFailure(initError)) {
            return null
        }
        if (prefs.savedRefreshToken.isBlank() || forcedRefreshCount >= 1) {
            Log.e("MaviVPN", "Server rejected token after forced refresh.")
            return null
        }

        Log.w(
            "MaviVPN",
            "Server rejected token. Forcing refresh due to possible clock skew or expiration mismatch.",
        )
        onRefreshAttempt()
        return when (val tokenResult = runBlocking { tokenManager.refreshAccessToken() }) {
            is TokenAcquireResult.Usable -> tokenResult.accessToken
            is TokenAcquireResult.TemporaryFailure -> {
                Log.w(
                    "MaviVPN",
                    "Forced Keycloak refresh temporarily failed (${tokenResult.message}). Waiting before retry.",
                )
                Thread.sleep(3000)
                currentToken
            }
            is TokenAcquireResult.NeedsLogin -> {
                Log.e("MaviVPN", "Forced Keycloak refresh failed: ${tokenResult.message}")
                null
            }
        }
    }

    private fun runEstablishedSession(handle: Long) {
        try {
            val configJson = NativeLib.getConfig(handle)
            Log.d("MaviVPN", "Config received from server")
            val root = JSONObject(configJson)
            val config = if (root.has("Config")) root.getJSONObject("Config") else root

            var localInterface: ParcelFileDescriptor? = null
            try {
                val builder = vpnService.Builder()
                try {
                    configureTunnelBuilder(
                        builder,
                        config,
                        request.splitMode,
                        request.splitPackages,
                        notificationHelper,
                    )
                } catch (e: Ipv6TunnelException) {
                    callbacks.setConnected(false)
                    callbacks.setRunning(false)
                    notificationHelper.updateNotification(
                        1,
                        "Mavi VPN",
                        "IPv6 VPN setup failed. Disconnecting.",
                    )
                    throw e
                }

                localInterface = builder.establish()
                callbacks.attachInterface(localInterface)

                if (localInterface != null) {
                    val fd = localInterface.fd
                    Log.d("MaviVPN", "Interface established. Starting Loop.")
                    callbacks.setConnected(true)
                    runNativeLoopWithRefresh(handle, fd)
                } else {
                    Log.e("MaviVPN", "Failed to establish VPN interface")
                }
            } finally {
                try {
                    localInterface?.close()
                } catch (_: Exception) {
                    // Ignore
                }
                callbacks.detachInterface(localInterface)
            }
        } catch (e: Exception) {
            Log.e("MaviVPN", "Error during VPN session: ${e.message}")
            e.printStackTrace()
        } finally {
            // Free our own handle exactly once and detach it from the
            // registry if it is still the current one.
            if (handle != 0L) {
                callbacks.releaseNativeHandle(handle, false)
            }
        }
    }

    private fun runNativeLoopWithRefresh(
        handle: Long,
        fd: Int,
    ) {
        // The callbacks run their native operation while the registry monitor
        // is held. Handle removal and free use the same monitor, so a late
        // ticker callback cannot cross the native handle's lifetime boundary.
        val refreshTicker =
            startKeycloakRefreshTicker(
                prefs = prefs,
                tokenManager = tokenManager,
                isSessionActive = ::isCurrentSessionActive,
                onTokenRefreshed = { newToken ->
                    handleRegistry.withHandleIfCurrent(sessionGeneration) {
                        NativeLib.updateToken(it, newToken)
                    }
                },
                onSessionExpired = {
                    callbacks.setRunning(false)
                    callbacks.setConnected(false)
                    notificationHelper.updateNotification(
                        1,
                        "Mavi VPN",
                        "Keycloak session expired. Please login again.",
                    )
                    handleRegistry.withHandleIfCurrent(sessionGeneration, NativeLib::stop)
                },
            )
        try {
            NativeLib.startLoop(handle, fd)
            Log.d("MaviVPN", "Native VPN loop exited")
            callbacks.setConnected(false)
        } finally {
            stopKeycloakRefreshTicker(refreshTicker)
        }
    }
}
