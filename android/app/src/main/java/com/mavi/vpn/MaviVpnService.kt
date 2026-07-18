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
            val hasCredentials = vpnStartHasCredentials(prefs, request.token)

            if (request.ip.isNotEmpty() && hasCredentials) {
                startVpn(request)
                return START_STICKY
            } else {
                Log.e("MaviVPN", "Cannot restart: Credentials missing.")
            }
        }
        return START_NOT_STICKY
    }

    private fun startVpn(request: VpnStartRequest) {
        val cleanup = invalidateCurrentSession()
        stopCurrentSession(cleanup)
        val sessionGeneration = cleanup.generation

        registerNetworkCallback(sessionGeneration)

        val notification =
            notificationHelper.createNotification("Mavi VPN", "Connecting to ${request.ip}...")
        acquireWakeLock()

        isRunning = true
        startForeground(1, notification)

        val callbacks =
            VpnSessionCallbacks(
                isRunning = { isRunning },
                setRunning = { isRunning = it },
                setConnected = { isConnected.value = it },
                attachInterface = ::attachVpnInterface,
                detachInterface = ::detachVpnInterface,
                releaseNativeHandle = ::releaseNativeHandle,
            )
        val sessionThread =
            VpnSessionWorker(
                vpnService = this,
                request = request,
                prefs = prefs,
                notificationHelper = notificationHelper,
                tokenManager = tokenManager,
                handleRegistry = handleRegistry,
                sessionGeneration = sessionGeneration,
                callbacks = callbacks,
            ).createThread()
        thread = sessionThread
        sessionThread.start()
    }

    private fun registerNetworkCallback(sessionGeneration: Long) {
        try {
            connectivityManager = getSystemService(ConnectivityManager::class.java)
            networkCallback =
                object : ConnectivityManager.NetworkCallback() {
                    override fun onAvailable(network: Network) {
                        Log.d("MaviVPN", "Network available: $network")
                        handleRegistry.withHandleIfCurrent(sessionGeneration, NativeLib::networkChanged)
                    }

                    override fun onLost(network: Network) {
                        Log.d("MaviVPN", "Network lost: $network")
                    }
                }
            connectivityManager?.registerDefaultNetworkCallback(networkCallback!!)
        } catch (e: Exception) {
            Log.e("MaviVPN", "Failed to register network callback", e)
        }
    }

    private fun attachVpnInterface(localInterface: ParcelFileDescriptor?) {
        synchronized(vpnLock) {
            vpnInterface = localInterface
        }
    }

    private fun detachVpnInterface(localInterface: ParcelFileDescriptor?) {
        synchronized(vpnLock) {
            if (vpnInterface == localInterface) {
                vpnInterface = null
            }
        }
    }

    private fun stopVpn() {
        tearDownVpnSession()
        stopSelf()
    }

    private fun tearDownVpnSession() {
        val cleanup = invalidateCurrentSession()
        stopCurrentSession(cleanup)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }

        releaseWakeLock()
    }

    private fun invalidateCurrentSession(): SessionCleanup {
        synchronized(vpnLock) {
            val invalidation = handleRegistry.invalidate()
            if (invalidation.previousHandle != 0L) {
                // The worker frees this handle after its native loop exits. Do
                // the stop while retaining the same monitor used by callbacks
                // and free, so this pointer cannot be freed concurrently.
                NativeLib.stop(invalidation.previousHandle)
            }
            isRunning = false
            isConnected.value = false
            val cleanup =
                SessionCleanup(
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

    /**
     * Detaches and frees a worker-owned handle while holding the shared native
     * handle monitor. Native callbacks use the same monitor through
     * [SessionHandleRegistry.withHandleIfCurrent].
     */
    private fun releaseNativeHandle(
        handle: Long,
        stopFirst: Boolean = false,
    ) {
        synchronized(vpnLock) {
            handleRegistry.clearIfMatches(handle)
            if (stopFirst) {
                NativeLib.stop(handle)
            }
            NativeLib.free(handle)
        }
    }

    /**
     * Called by the system when the user revokes this VPN's permission from
     * Settings. The default [VpnService] implementation just calls
     * [stopSelf], which would skip our own teardown (native session handle,
     * TUN fd, network callback, wake lock) entirely - so this must run the
     * same path as a manual Stop.
     */
    override fun onRevoke() {
        Log.i("MaviVPN", "VPN permission revoked by the system; tearing down session")
        stopVpn()
    }

    override fun onDestroy() {
        tearDownVpnSession()
        super.onDestroy()
    }

    private fun acquireWakeLock() {
        releaseWakeLock()
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock =
            pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "MaviVPN::ServiceWakeLock").apply {
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
