package com.mavi.vpn

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.os.Process
import com.mavi.vpn.data.PrefsManager
import com.mavi.vpn.native_lib.NativeLib
import com.mavi.vpn.service.NotificationHelper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext

class MaviVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    @Volatile private var thread: Thread? = null
    private var connectivityManager: ConnectivityManager? = null
    @Volatile private var networkCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile private var vpnSessionHandle: Long = 0
    @Volatile private var vpnSessionGeneration: Long = 0
    @Volatile private var connectRequestGeneration: Long = 0
    @Volatile private var isRunning = false
    private var wakeLock: PowerManager.WakeLock? = null
    private val vpnLock = Any()
    private val wakeLockLock = Any()
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    
    private lateinit var prefs: PrefsManager
    private lateinit var notificationHelper: NotificationHelper

    companion object {
        private const val CONNECT_WAKE_LOCK_TIMEOUT_MS = 60_000L
        private const val INITIAL_RETRY_DELAY_MS = 2_000L
        private const val MAX_RETRY_DELAY_MS = 30_000L

        /** Observable connection state for UI */
        val isConnected = MutableStateFlow(false)
        val keycloakTokenUpdates = MutableSharedFlow<String>(extraBufferCapacity = 1)
    }

    private data class SessionCleanup(
        val handle: Long,
        val workerThread: Thread?,
        val callback: ConnectivityManager.NetworkCallback?,
        val vpnInterface: ParcelFileDescriptor?,
        val generation: Long,
    )

    override fun onCreate() {
        super.onCreate()
        prefs = PrefsManager(this)
        Log.configure(this)
        notificationHelper = NotificationHelper(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action

        if (action == "STOP") {
            serviceScope.launch {
                stopVpn()
            }
            return START_NOT_STICKY
        }
        
        if (action == "CONNECT" || action == null) {
            val ip: String
            val port: String
            val token: String
            val pin: String
            val splitMode: String
            val splitPackages: String

            if (intent != null) {
                ip = intent.getStringExtra("IP") ?: ""
                port = intent.getStringExtra("PORT") ?: "4433"
                token = intent.getStringExtra("TOKEN") ?: ""
                pin = intent.getStringExtra("PIN") ?: ""
                splitMode = intent.getStringExtra("SPLIT_MODE") ?: ""
                splitPackages = intent.getStringExtra("SPLIT_PACKAGES") ?: ""
                
                prefs.savedIp = ip
                prefs.savedPort = port
                prefs.savedToken = token
                prefs.savedPin = pin
                prefs.savedSplitMode = splitMode
                prefs.savedSplitPackages = splitPackages
            } else {
                Log.i("MaviVPN", "Service restarted by System. Reloading credentials...")
                ip = prefs.savedIp
                port = prefs.savedPort
                token = prefs.savedToken
                pin = prefs.savedPin
                splitMode = prefs.savedSplitMode
                splitPackages = prefs.savedSplitPackages
            }

            queueVpnStart(ip, port, token, pin, splitMode, splitPackages)
            return START_STICKY
        }

        return START_NOT_STICKY
    }

    private fun queueVpnStart(ip: String, port: String, token: String, certPin: String, splitMode: String, splitPackages: String) {
        val requestGeneration = synchronized(vpnLock) {
            connectRequestGeneration += 1
            connectRequestGeneration
        }

        serviceScope.launch {
            val currentToken = resolveStartupToken(token)
            if (!isLatestConnectRequest(requestGeneration)) {
                Log.i("MaviVPN", "Ignoring stale VPN start request.")
                return@launch
            }

            if (currentToken == null) {
                stopSelf()
            } else if (ip.isNotEmpty() && currentToken.isNotEmpty()) {
                startVpn(ip, port, currentToken, certPin, splitMode, splitPackages)
            } else {
                Log.e("MaviVPN", "Cannot restart: Credentials missing.")
                stopSelf()
            }
        }
    }

    private fun isLatestConnectRequest(requestGeneration: Long): Boolean {
        return synchronized(vpnLock) {
            connectRequestGeneration == requestGeneration
        }
    }

    private suspend fun resolveStartupToken(token: String): String? {
        if (!prefs.savedUseKeycloak || OAuthHelper.isAccessTokenUsable(token)) {
            return prefs.savedToken
        }

        // Try one refresh before startup without blocking the Service main thread.
        val refreshed = OAuthHelper.refreshToken(
            prefs.savedRefreshToken,
            prefs.savedKcUrl,
            prefs.savedKcRealm,
            prefs.savedKcClientId
        )

        return when (refreshed) {
            is RefreshResult.Success -> {
                prefs.savedToken = refreshed.tokens.accessToken
                prefs.savedRefreshToken = refreshed.tokens.refreshToken
                keycloakTokenUpdates.tryEmit(refreshed.tokens.accessToken)
                refreshed.tokens.accessToken
            }
            is RefreshResult.NetworkError -> {
                Log.w("MaviVPN", "Stored Keycloak token expired, but network is offline. Will let VPN reconnect loop try later.")
                // Do not clear tokens; the reconnect loop can refresh once network returns.
                prefs.savedToken
            }
            is RefreshResult.Error -> {
                Log.i("MaviVPN", "Keycloak refresh rejected (session expired/revoked). Clearing session.")
                prefs.savedToken = ""
                prefs.savedRefreshToken = ""
                keycloakTokenUpdates.tryEmit("")
                null
            }
        }
    }

    private suspend fun startVpn(ip: String, port: String, token: String, certPin: String, splitMode: String, splitPackages: String) {
        val cleanup = invalidateCurrentSession()
        stopCurrentSession(cleanup)
        val sessionGeneration = cleanup.generation
        if (!isCurrentSessionGeneration(sessionGeneration)) {
            return
        }

        try {
            connectivityManager = getSystemService(ConnectivityManager::class.java)
            networkCallback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    Log.d("MaviVPN", "Network available: $network")
                    synchronized(vpnLock) {
                        if (vpnSessionHandle != 0L && vpnSessionGeneration == sessionGeneration) {
                            NativeLib.networkChanged(vpnSessionHandle)
                        }
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
        
        acquireWakeLock(CONNECT_WAKE_LOCK_TIMEOUT_MS)

        isRunning = true
        startForeground(1, notification)

        thread = Thread {
            Process.setThreadPriority(Process.THREAD_PRIORITY_DISPLAY)
            Log.d("MaviVPN", "Starting VPN Thread")
            var currentToken = token
            var forcedRefreshCount = 0
            val workerGeneration = sessionGeneration

            fun isCurrentSessionActive(): Boolean {
                return isRunning && vpnSessionGeneration == workerGeneration
            }
            
            while (isCurrentSessionActive()) {
                try {
                    var retryCount = 0
                    var retryDelayMs = INITIAL_RETRY_DELAY_MS
                    var activeHandle = 0L
                    val crMode = prefs.savedCensorshipResistant
                        
                    while (isCurrentSessionActive()) {
                        if (prefs.savedUseKeycloak && !OAuthHelper.isAccessTokenUsable(currentToken, skewSeconds = 300)) {
                            Log.i("MaviVPN", "Keycloak token expires soon. Attempting refresh in background.")
                            acquireWakeLock(CONNECT_WAKE_LOCK_TIMEOUT_MS)
                            val refreshed = runBlocking {
                                OAuthHelper.refreshToken(prefs.savedRefreshToken, prefs.savedKcUrl, prefs.savedKcRealm, prefs.savedKcClientId)
                            }

                            when (refreshed) {
                                is RefreshResult.Success -> {
                                    currentToken = refreshed.tokens.accessToken
                                    prefs.savedToken = refreshed.tokens.accessToken
                                    prefs.savedRefreshToken = refreshed.tokens.refreshToken
                                    keycloakTokenUpdates.tryEmit(refreshed.tokens.accessToken)
                                    Log.i("MaviVPN", "Successfully refreshed Keycloak token.")
                                }
                                is RefreshResult.NetworkError -> {
                                    Log.w("MaviVPN", "Refresh skipped due to network (${refreshed.error}). Waiting before retry.")
                                    releaseWakeLock()
                                    Thread.sleep(3000)
                                    continue // Try again! We don't drop the connection
                                }
                                is RefreshResult.Error -> {
                                    Log.e("MaviVPN", "Refresh failed: ${refreshed.message}. Keycloak session expired. Stopping reconnect loop.")
                                    prefs.savedToken = ""
                                    prefs.savedRefreshToken = ""
                                    keycloakTokenUpdates.tryEmit("")
                                    isRunning = false
                                    releaseWakeLock()
                                    break
                                }
                            }
                        }

                        if (!isCurrentSessionActive()) {
                            break
                        }

                        Log.d("MaviVPN", "Attempting connection to $ip:$port (Attempt ${++retryCount})")
                        acquireWakeLock(CONNECT_WAKE_LOCK_TIMEOUT_MS)
                        
                        if (retryCount > 1) {
                            notificationHelper.updateNotification(1, "Mavi VPN", "Retrying connection to $ip (Attempt $retryCount)...")
                        }

                        val handle = NativeLib.init(this, currentToken, buildEndpoint(ip, port), certPin, crMode, prefs.savedHttp3Framing, prefs.savedEchConfig, prefs.savedVpnMtu, prefs.savedEnableLogging)
                        // Valid 64-bit pointers on Android MTE/TBI can be negative when cast to a signed Long.
                        // NativeLib error codes are strictly in the range [-3, 0].
                        if (handle in -3L..0L) {
                            val initError = NativeLib.getLastInitError()
                            if (handle < 0L) {
                                Log.e("MaviVPN", "Fatal handshake failure: $initError")
                                if (prefs.savedUseKeycloak && isAuthFailure(initError)) {
                                    if (prefs.savedRefreshToken.isNotBlank() && forcedRefreshCount < 1) {
                                        Log.w("MaviVPN", "Server rejected token. Forcing refresh due to possible clock skew or expiration mismatch.")
                                        currentToken = ""
                                        forcedRefreshCount++
                                        continue
                                    } else {
                                        prefs.savedToken = ""
                                        prefs.savedRefreshToken = ""
                                        keycloakTokenUpdates.tryEmit("")
                                    }
                                }
                                isConnected.value = false
                                isRunning = false
                                notificationHelper.updateNotification(
                                    1,
                                    "Mavi VPN",
                                    if (initError.isNotBlank()) initError else "Connection aborted. Check your configuration."
                                )
                                releaseWakeLock()
                                break
                            }

                            Log.e("MaviVPN", "Handshake failed. ${if (initError.isNotBlank()) initError else "Retrying in ${retryDelayMs / 1000} seconds..."}")
                            releaseWakeLock()
                            sleepWhileActive(retryDelayMs) { isCurrentSessionActive() }
                            retryDelayMs = (retryDelayMs * 2).coerceAtMost(MAX_RETRY_DELAY_MS)
                            continue
                        }
                        
                        retryCount = 0
                        retryDelayMs = INITIAL_RETRY_DELAY_MS
                        forcedRefreshCount = 0
                        val acceptedHandle = synchronized(vpnLock) {
                            if (isRunning && vpnSessionGeneration == workerGeneration) {
                                vpnSessionHandle = handle
                                activeHandle = handle
                                true
                            } else {
                                false
                            }
                        }
                        if (!acceptedHandle) {
                            NativeLib.stop(handle)
                            NativeLib.free(handle)
                        }
                        break
                    }

                    val handle = activeHandle
                    if (handle == 0L) {
                        if (!isCurrentSessionActive()) {
                            break
                        }
                        continue
                    }

                    try {
                        if (!isCurrentSessionActive()) {
                            continue
                        }
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
                                 val packages = splitPackages.split(",").map { it.trim() }.filter { it.isNotEmpty() }
                                 Log.d("MaviVPN", "Applying Split Tunneling: Mode=$splitMode, Packages=$packages")
                                 
                                 for (pkg in packages) {
                                     try {
                                          if (splitMode == "include") {
                                              builder.addAllowedApplication(pkg)
                                          } else {
                                              builder.addDisallowedApplication(pkg)
                                          }
                                     } catch (e: Exception) {
                                          Log.w("MaviVPN", "Failed to add split tunneling for package '$pkg': ${e.message}")
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
                                 releaseWakeLock()
                                 NativeLib.startLoop(handle, fd)
                                 Log.d("MaviVPN", "Native VPN loop exited")
                                 isConnected.value = false
                             } else {
                                 Log.e("MaviVPN", "Failed to establish VPN interface")
                             }
                        } finally {
                             try { localInterface?.close() } catch(e: Exception) {}
                             synchronized(vpnLock) {
                                  if (vpnInterface == localInterface) {
                                       vpnInterface = null
                                  }
                             }
                        }
                    } catch (e: Exception) {
                        Log.e("MaviVPN", "Error during VPN session: ${e.message}", e)
                    } finally {
                        releaseWakeLock()
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
                    try { Thread.sleep(500) } catch(_: Exception){}
                }
            }
            if (vpnSessionGeneration == workerGeneration && isRunning) {
                stopSelf()
            }
        }.also { it.start() }
    }

    private suspend fun stopVpn() {
        val cleanup = invalidateCurrentSession()
        stopCurrentSession(cleanup)
        if (!isCurrentSessionGeneration(cleanup.generation)) {
            return
        }
        
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
            connectRequestGeneration += 1
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

    private fun isCurrentSessionGeneration(generation: Long): Boolean {
        return synchronized(vpnLock) {
            vpnSessionGeneration == generation
        }
    }

    private suspend fun stopCurrentSession(cleanup: SessionCleanup) {
        withContext(Dispatchers.IO) {
            stopCurrentSessionBlocking(cleanup, joinTimeoutMs = 3_000)
        }
    }

    private fun stopCurrentSessionBlocking(cleanup: SessionCleanup, joinTimeoutMs: Long) {
        if (cleanup.handle != 0L) {
            synchronized(vpnLock) {
                NativeLib.stop(cleanup.handle)
            }
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
            Log.w("MaviVPN", "Failed to close VPN interface: ${e.message}", e)
        }

        try {
            if (joinTimeoutMs > 0 && cleanup.workerThread != null && cleanup.workerThread != Thread.currentThread()) {
                cleanup.workerThread.join(joinTimeoutMs)
            }
        } catch (_: Exception) {
        }
    }

    private fun buildEndpoint(host: String, port: String): String {
        val trimmedHost = host.trim()
        if (trimmedHost.startsWith("[") && trimmedHost.contains("]")) {
            val suffix = trimmedHost.substringAfter("]", "")
            return if (suffix.startsWith(":")) trimmedHost else "$trimmedHost:$port"
        }

        val colonCount = trimmedHost.count { it == ':' }
        return when {
            colonCount == 0 -> "$trimmedHost:$port"
            colonCount == 1 -> trimmedHost
            else -> "[$trimmedHost]:$port"
        }
    }

    override fun onDestroy() {
        val cleanup = invalidateCurrentSession()
        stopCurrentSessionBlocking(cleanup, joinTimeoutMs = 0)
        serviceScope.cancel()
        releaseWakeLock()
        super.onDestroy()
    }

    private fun acquireWakeLock(timeoutMs: Long) {
        synchronized(wakeLockLock) {
            releaseWakeLockLocked()
            val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "MaviVPN::ConnectWakeLock").apply {
                setReferenceCounted(false)
                acquire(timeoutMs)
            }
        }
    }

    private fun releaseWakeLock() {
        synchronized(wakeLockLock) {
            releaseWakeLockLocked()
        }
    }

    private fun releaseWakeLockLocked() {
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
        return normalized.contains("unauthorized")
            || normalized.contains("access denied")
            || normalized.contains("invalid token")
            || normalized.contains("invalid keycloak token")
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

    private fun sleepWhileActive(totalMs: Long, isActive: () -> Boolean) {
        var remainingMs = totalMs
        while (remainingMs > 0 && isActive()) {
            val chunkMs = remainingMs.coerceAtMost(500L)
            try {
                Thread.sleep(chunkMs)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return
            }
            remainingMs -= chunkMs
        }
    }
}
