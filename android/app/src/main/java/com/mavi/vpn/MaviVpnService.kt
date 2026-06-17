package com.mavi.vpn

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.util.Log
import com.mavi.vpn.data.PrefsManager
import com.mavi.vpn.nativelib.NativeLib
import com.mavi.vpn.service.NotificationHelper
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import org.json.JSONObject

class MaviVpnService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null

    @Volatile private var thread: Thread? = null

    private var connectivityManager: ConnectivityManager? = null

    @Volatile private var networkCallback: ConnectivityManager.NetworkCallback? = null

    @Volatile private var isRunning = false
    private var wakeLock: PowerManager.WakeLock? = null
    private val vpnLock = Any()

    /** Single source of truth for the active native session handle + generation.
     *  Shares [vpnLock] so compound session operations stay atomic. */
    private val handleRegistry = SessionHandleRegistry(vpnLock)

    private lateinit var prefs: PrefsManager
    private lateinit var notificationHelper: NotificationHelper
    private lateinit var tokenManager: KeycloakTokenManager

    companion object {
        val isConnected = MutableStateFlow(false)
    }

    override fun onCreate() {
        super.onCreate()
        prefs = PrefsManager(this)
        notificationHelper = NotificationHelper(this)
        tokenManager = KeycloakTokenManager(PrefsKeycloakTokenStore(prefs))
    }

    override fun onStartCommand(
        intent: Intent?,
        flags: Int,
        startId: Int,
    ): Int {
        val action = intent?.action

        if (action == "STOP") {
            stopVpn()
            return START_NOT_STICKY
        }

        if (action == "CONNECT" || action == null) {
            val request = resolveVpnStartRequest(intent, prefs)
            val currentToken = prefs.savedToken
            val hasCredentials = vpnStartHasCredentials(prefs, currentToken)

            if (request.ip.isNotEmpty() && hasCredentials) {
                startVpn(
                    request.ip,
                    request.port,
                    currentToken,
                    request.pin,
                    request.splitMode,
                    request.splitPackages,
                )
                return START_STICKY
            } else {
                Log.e("MaviVPN", "Cannot restart: Credentials missing.")
            }
        }
        return START_NOT_STICKY
    }

    private fun startVpn(
        ip: String,
        port: String,
        token: String,
        certPin: String,
        splitMode: String,
        splitPackages: String,
    ) {
        val cleanup = invalidateCurrentSession()
        stopCurrentSession(cleanup)
        val sessionGeneration = cleanup.generation

        try {
            connectivityManager = getSystemService(ConnectivityManager::class.java)
            networkCallback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    Log.d("MaviVPN", "Network available: $network")
                    val handle = handleRegistry.handleIfCurrent(sessionGeneration)
                    if (handle != 0L) {
                        NativeLib.networkChanged(handle)
                    }
                }

                override fun onLost(network: Network) {
                    Log.d("MaviVPN", "Network lost: $network")
                }
            }
            connectivityManager?.registerDefaultNetworkCallback(networkCallback!!)
        } catch (e: Exception) {
            Log.e("MaviVPN", "Failed to register network callback", e)
        }

        val notification = notificationHelper.createNotification("Mavi VPN", "Connecting to $ip...")

        acquireWakeLock()

        isRunning = true
        startForeground(1, notification)

        thread = Thread {
            Log.d("MaviVPN", "Starting VPN Thread")
            var currentToken = token
            var forcedRefreshCount = 0
            val workerGeneration = sessionGeneration

            fun isCurrentSessionActive(): Boolean = isRunning && handleRegistry.isCurrent(workerGeneration)

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
                            when (val tokenResult = runBlocking { tokenManager.getUsableAccessToken(skewSeconds = 300) }) {
                                is TokenAcquireResult.Usable -> {
                                    currentToken = tokenResult.accessToken
                                    if (tokenResult.refreshed) {
                                        Log.i("MaviVPN", "Successfully refreshed Keycloak token.")
                                    }
                                }
                                is TokenAcquireResult.TemporaryFailure -> {
                                    Log.w("MaviVPN", "Keycloak refresh temporarily failed (${tokenResult.message}). Waiting before retry.")
                                    Thread.sleep(3000)
                                    continue
                                }
                                is TokenAcquireResult.NeedsLogin -> {
                                    Log.e("MaviVPN", "Keycloak session cannot be refreshed: ${tokenResult.message}")
                                    isRunning = false
                                    notificationHelper.updateNotification(1, "Mavi VPN", "Keycloak session expired. Please login again.")
                                    break
                                }
                            }
                        }

                        if (!isCurrentSessionActive()) {
                            break
                        }

                        Log.d("MaviVPN", "Attempting connection to $ip:$port (Attempt ${++retryCount})")

                        if (retryCount > 1) {
                            notificationHelper.updateNotification(1, "Mavi VPN", "Retrying connection to $ip (Attempt $retryCount)...")
                        }

                        val handle =
                            NativeLib.init(
                                this,
                                currentToken,
                                buildEndpoint(ip, port),
                                certPin,
                                crMode,
                                prefs.savedHttp3Framing,
                                prefs.savedEchConfig,
                                prefs.savedVpnMtu,
                            )
                        // Valid 64-bit pointers on Android MTE/TBI can be negative when cast to a signed Long.
                        // NativeLib error codes are strictly in the range [-3, 0].
                        if (handle in -3L..0L) {
                            val initError = NativeLib.getLastInitError()
                            if (handle < 0L) {
                                Log.e("MaviVPN", "Fatal handshake failure: $initError")
                                if (prefs.savedUseKeycloak && isAuthFailure(initError)) {
                                    if (prefs.savedRefreshToken.isNotBlank() && forcedRefreshCount < 1) {
                                        Log.w("MaviVPN", "Server rejected token. Forcing refresh due to possible clock skew or expiration mismatch.")
                                        forcedRefreshCount++
                                        when (val tokenResult = runBlocking { tokenManager.refreshAccessToken() }) {
                                            is TokenAcquireResult.Usable -> {
                                                currentToken = tokenResult.accessToken
                                                continue
                                            }
                                            is TokenAcquireResult.TemporaryFailure -> {
                                                Log.w("MaviVPN", "Forced Keycloak refresh temporarily failed (${tokenResult.message}). Waiting before retry.")
                                                Thread.sleep(3000)
                                                continue
                                            }
                                            is TokenAcquireResult.NeedsLogin -> {
                                                Log.e("MaviVPN", "Forced Keycloak refresh failed: ${tokenResult.message}")
                                            }
                                        }
                                    } else {
                                        Log.e("MaviVPN", "Server rejected token after forced refresh.")
                                    }
                                }
                                isConnected.value = false
                                isRunning = false
                                notificationHelper.updateNotification(
                                    1,
                                    "Mavi VPN",
                                    if (initError.isNotBlank()) initError else "Connection aborted. Check your configuration.",
                                )
                                break
                            }

                            Log.e("MaviVPN", "Handshake failed. ${if (initError.isNotBlank()) initError else "Retrying in 2 seconds..."}")
                            repeat(4) { if (isRunning) Thread.sleep(500) }
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
                        if (handleRegistry.tryAdopt(handle, workerGeneration)) {
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
                            handleRegistry.clearIfMatches(acquiredHandle)
                            NativeLib.stop(acquiredHandle)
                            NativeLib.free(acquiredHandle)
                        }
                        continue
                    }
                    val handle = acquiredHandle

                    try {
                        val configJson = NativeLib.getConfig(handle)
                        Log.d("MaviVPN", "Config received from server")
                        val root = JSONObject(configJson)
                        val config = if (root.has("Config")) root.getJSONObject("Config") else root

                        var localInterface: ParcelFileDescriptor? = null

                        try {
                            val builder = Builder()
                            try {
                                configureTunnelBuilder(builder, config, splitMode, splitPackages, notificationHelper)
                            } catch (e: Ipv6TunnelException) {
                                isConnected.value = false
                                isRunning = false
                                notificationHelper.updateNotification(1, "Mavi VPN", "IPv6 VPN setup failed. Disconnecting.")
                                throw e
                            }

                            localInterface = builder.establish()
                            synchronized(vpnLock) {
                                vpnInterface = localInterface
                            }

                            if (localInterface != null) {
                                val fd = localInterface.fd
                                Log.d("MaviVPN", "Interface established. Starting Loop.")
                                isConnected.value = true
                                val refreshTicker = startKeycloakRefreshTicker(
                                    prefs = prefs,
                                    tokenManager = tokenManager,
                                    isSessionActive = { isRunning && handleRegistry.isCurrent(workerGeneration) },
                                    onTokenRefreshed = { newToken -> NativeLib.updateToken(handle, newToken) },
                                    onSessionExpired = {
                                        isRunning = false
                                        isConnected.value = false
                                        notificationHelper.updateNotification(
                                            1,
                                            "Mavi VPN",
                                            "Keycloak session expired. Please login again.",
                                        )
                                        NativeLib.stop(handle)
                                    },
                                )
                                try {
                                    NativeLib.startLoop(handle, fd)
                                    Log.d("MaviVPN", "Native VPN loop exited")
                                    isConnected.value = false
                                } finally {
                                    stopKeycloakRefreshTicker(refreshTicker)
                                }
                            } else {
                                Log.e("MaviVPN", "Failed to establish VPN interface")
                            }
                        } finally {
                            try {
                                localInterface?.close()
                            } catch (e: Exception) {
                                // Ignore
                            }
                            synchronized(vpnLock) {
                                if (vpnInterface == localInterface) {
                                    vpnInterface = null
                                }
                            }
                        }
                    } catch (e: Exception) {
                        Log.e("MaviVPN", "Error during VPN session: ${e.message}")
                        e.printStackTrace()
                    } finally {
                        // Free our own handle exactly once and detach it from the
                        // registry if it is still the current one.
                        if (handle != 0L) {
                            handleRegistry.clearIfMatches(handle)
                            NativeLib.free(handle)
                        }
                    }
                } catch (e: Exception) {
                         Log.e("MaviVPN", "Critical error in VPN thread: ${e.message}")
                         try { Thread.sleep(500) } catch(_: Exception){}
                    }

                if (!isCurrentSessionActive()) {
                    break
                }

                if (isRunning) {
                    try {
                        Thread.sleep(500)
                    } catch (_: Exception) {
                        // Ignore
                    }
                }
            }
            if (handleRegistry.isCurrent(workerGeneration)) {
                stopSelf()
            }
        }.also { it.start() }
    }

    private fun stopVpn() {
        val cleanup = invalidateCurrentSession()
        stopCurrentSession(cleanup)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }

        releaseWakeLock()

        stopSelf()
    }

    private fun invalidateCurrentSession(): SessionCleanup {
        synchronized(vpnLock) {
            val invalidation = handleRegistry.invalidate()
            isRunning = false
            isConnected.value = false
            val cleanup = SessionCleanup(
                handle = invalidation.previousHandle,
                workerThread = thread,
                callback = networkCallback,
                vpnInterface = vpnInterface,
                generation = invalidation.generation,
            )
            thread = null
            networkCallback = null
            vpnInterface = null
            return cleanup
        }
    }

    private fun stopCurrentSession(cleanup: SessionCleanup) {
        if (cleanup.handle != 0L) {
            NativeLib.stop(cleanup.handle)
        }

        try {
            if (connectivityManager != null && cleanup.callback != null) {
                connectivityManager?.unregisterNetworkCallback(cleanup.callback)
            }
        } catch (e: Exception) {
            Log.w("MaviVPN", "Failed to unregister network callback: ${e.message}")
        }

        try {
            cleanup.vpnInterface?.close()
        } catch (e: Exception) {
            e.printStackTrace()
        }

        try {
            if (cleanup.workerThread != null && cleanup.workerThread != Thread.currentThread()) {
                cleanup.workerThread.join(3000)
            }
        } catch (_: Exception) {
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        releaseWakeLock()
    }

    private fun acquireWakeLock() {
        releaseWakeLock()
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "MaviVPN::ServiceWakeLock").apply {
            setReferenceCounted(false)
            acquire()
        }
    }

    private fun releaseWakeLock() {
        try {
            if (wakeLock?.isHeld == true) {
                wakeLock?.release()
            }
        } catch (e: Exception) {
            Log.w("MaviVPN", "Error releasing WakeLock: ${e.message}")
        }
        wakeLock = null
    }

}
