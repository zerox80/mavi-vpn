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

class MaviVpnService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null

    @Volatile private var thread: Thread? = null

    private var connectivityManager: ConnectivityManager? = null

    @Volatile private var networkCallback: ConnectivityManager.NetworkCallback? = null

    @Volatile private var vpnSessionHandle: Long = 0

    @Volatile private var vpnSessionGeneration: Long = 0

    @Volatile private var isRunning = false
    private var wakeLock: PowerManager.WakeLock? = null
    private val vpnLock = Any()

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
                    val handle = synchronized(vpnLock) {
                        if (vpnSessionHandle != 0L && vpnSessionGeneration == sessionGeneration) {
                            vpnSessionHandle
                        } else {
                            0L
                        }
                    }
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

            fun isCurrentSessionActive(): Boolean = isRunning && vpnSessionGeneration == workerGeneration

            while (isCurrentSessionActive()) {
                try {
                    var retryCount = 0
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
                        synchronized(vpnLock) {
                            vpnSessionHandle = handle
                        }
                        break
                    }

                    if (!isCurrentSessionActive()) continue
                    val handle = vpnSessionHandle

                    try {
                        val configJson = NativeLib.getConfig(handle)
                        Log.d("MaviVPN", "Config received from server")
                        val root = org.json.JSONObject(configJson)
                        val config = if (root.has("Config")) root.getJSONObject("Config") else root

                        var localInterface: ParcelFileDescriptor? = null

                        try {
                            val builder = Builder()
                            val assignedIp = config.getString("assigned_ip")
                            val netmask = config.optString("netmask", "255.255.255.0")
                            val prefixLength = netmaskToPrefixLength(netmask)

                            builder.addAddress(assignedIp, prefixLength)
                            builder.addRoute("0.0.0.0", 0)

                            val dns = config.optString("dns_server", "8.8.8.8")
                            builder.addDnsServer(dns)

                            if (config.has("assigned_ipv6")) {
                                val v6 = config.getString("assigned_ipv6")
                                val v6Prefix = config.optInt("netmask_v6", 64)
                                try {
                                    builder.addAddress(v6, v6Prefix)
                                    builder.addRoute("::", 0)
                                    if (config.has("dns_server_v6")) {
                                        builder.addDnsServer(config.getString("dns_server_v6"))
                                    }
                                } catch (e: Exception) {
                                    Log.w("MaviVPN", "Failed to add IPv6: ${e.message}")
                                }
                            }

                            if (splitMode == "include" || splitMode == "exclude") {
                                val packages =
                                    splitPackages.split(",").map { it.trim() }.filter { it.isNotEmpty() }
                                Log.d("MaviVPN", "Applying Split Tunneling: Mode=$splitMode, Packages=$packages")

                                for (pkg in packages) {
                                    try {
                                        if (splitMode == "include") {
                                            builder.addAllowedApplication(pkg)
                                        } else {
                                            builder.addDisallowedApplication(pkg)
                                        }
                                    } catch (e: Exception) {
                                        Log.w(
                                            "MaviVPN",
                                            "Failed to add split tunneling for package '$pkg': ${e.message}",
                                        )
                                    }
                                }
                            }

                            builder.setSession("MaviVPN")
                            val serverMtu = config.optInt("mtu", 1280)
                            val tunMtu = if (serverMtu in 1280..1360) serverMtu else 1280
                            builder.setMtu(tunMtu)

                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                                builder.setMetered(false)
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
                                    isSessionActive = { isRunning && vpnSessionGeneration == workerGeneration },
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
                        synchronized(vpnLock) {
                             if (vpnSessionHandle == handle) {
                                  NativeLib.free(handle)
                                  vpnSessionHandle = 0
                             } else if (handle != 0L) {
                                  NativeLib.free(handle)
                             }
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
            if (vpnSessionGeneration == workerGeneration && isRunning) {
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
            vpnSessionGeneration += 1
            isRunning = false
            isConnected.value = false
            val cleanup = SessionCleanup(
                handle = vpnSessionHandle,
                workerThread = thread,
                callback = networkCallback,
                vpnInterface = vpnInterface,
                generation = vpnSessionGeneration,
            )
            vpnSessionHandle = 0L
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

    private fun isAuthFailure(message: String): Boolean {
        val normalized = message.lowercase()
        return normalized.contains("unauthorized") ||
            normalized.contains("access denied") ||
            normalized.contains("invalid token") ||
            normalized.contains("invalid keycloak token")
    }

    private fun netmaskToPrefixLength(netmask: String): Int {
        return try {
            val parts = netmask.split(".")
            if (parts.size != 4) return 24
            val mask = parts.fold(0L) { acc, part ->
                val octet = part.toInt()
                if (octet < 0 || octet > 255) return 24
                (acc shl 8) or octet.toLong()
            }
            // Use Long.bitCount to avoid truncating the upper 32 bits with toInt().
            val prefix = java.lang.Long.bitCount(mask)
            val expected = if (prefix == 0) 0L else (0xFFFFFFFFL shl (32 - prefix)) and 0xFFFFFFFFL
            if (mask != expected) return 24
            prefix
        } catch (e: Exception) {
            24
        }
    }
}
