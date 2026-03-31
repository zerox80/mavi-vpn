package com.mavi.vpn

import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.content.Context
import android.util.Log
import com.mavi.vpn.data.PrefsManager
import com.mavi.vpn.native_lib.NativeLib
import com.mavi.vpn.service.NotificationHelper
import kotlinx.coroutines.flow.MutableStateFlow

class MaviVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var thread: Thread? = null
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile private var vpnSessionHandle: Long = 0
    @Volatile private var isRunning = false
    private var wakeLock: PowerManager.WakeLock? = null
    private val vpnLock = Any()
    
    private lateinit var prefs: PrefsManager
    private lateinit var notificationHelper: NotificationHelper

    companion object {
        /** Observable connection state for UI */
        val isConnected = MutableStateFlow(false)
    }

    override fun onCreate() {
        super.onCreate()
        prefs = PrefsManager(this)
        notificationHelper = NotificationHelper(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action

        if (action == "STOP") {
            stopVpn()
            return START_NOT_STICKY
        }
        
        if (action == "CONNECT" || intent == null) {
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

            if (ip.isNotEmpty() && token.isNotEmpty()) {
                startVpn(ip, port, token, pin, splitMode, splitPackages)
                return START_STICKY
            } else {
                Log.e("MaviVPN", "Cannot restart: Credentials missing.")
            }
        }
        
        return START_NOT_STICKY
    }

    private fun startVpn(ip: String, port: String, token: String, certPin: String, splitMode: String, splitPackages: String) {
        if (thread != null) {
            isRunning = false
            try { thread?.join(2000) } catch(_: Exception){}
            thread = null
        }

        synchronized(vpnLock) {
            try {
                if (connectivityManager != null && networkCallback != null) {
                    connectivityManager?.unregisterNetworkCallback(networkCallback!!)
                }
            } catch (e: Exception) {
                Log.w("MaviVPN", "Failed to unregister previous callback: ${e.message}")
            }
            networkCallback = null
        }

        try {
            connectivityManager = getSystemService(ConnectivityManager::class.java)
            networkCallback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    Log.d("MaviVPN", "Network available: $network")
                    synchronized(vpnLock) {
                        if (vpnSessionHandle != 0L) {
                            NativeLib.networkChanged(vpnSessionHandle)
                        }
                    }
                }
            }
            val req = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build()
            connectivityManager?.registerNetworkCallback(req, networkCallback!!)
        } catch (e: Exception) {
            Log.e("MaviVPN", "Failed to register network callback", e)
        }

        val notification = notificationHelper.createNotification("Mavi VPN", "Connecting to $ip...")
        
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "MaviVPN::ServiceWakeLock")
        wakeLock?.acquire(10 * 60 * 60 * 1000L)

        isRunning = true
        startForeground(1, notification)

        thread = Thread {
            Log.d("MaviVPN", "Starting VPN Thread")
            
            while (isRunning) {
                try {
                    var retryCount = 0
                    val crMode = prefs.savedCensorshipResistant
                        
                    while (isRunning) {
                        Log.d("MaviVPN", "Attempting connection to $ip:$port (Attempt ${++retryCount})")
                        
                        if (retryCount > 1) {
                            notificationHelper.updateNotification(1, "Mavi VPN", "Retrying connection to $ip (Attempt $retryCount)...")
                        }

                        val handle = NativeLib.init(this, token, "$ip:$port", certPin, crMode)
                        if (handle == 0L) {
                            Log.e("MaviVPN", "Handshake failed. Retrying in 2 seconds...")
                            repeat(4) { if (isRunning) Thread.sleep(500) }
                            continue
                        }
                        
                        retryCount = 0
                        synchronized(vpnLock) {
                            vpnSessionHandle = handle
                        }
                        break
                    }
                    
                    if (!isRunning) continue 
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
                             builder.setMtu(1280)

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
                
                if (Thread.currentThread() != thread) {
                    break
                }
                
                if (isRunning) {
                    try { Thread.sleep(500) } catch(_: Exception){}
                }
            }
            stopSelf()
        }.also { it.start() }
    }

    private fun stopVpn() {
        isRunning = false
        isConnected.value = false
        
        synchronized(vpnLock) {
             val handle = vpnSessionHandle
             if (handle != 0L) {
                  NativeLib.stop(handle)
             }
        }
        
        try {
            if (connectivityManager != null && networkCallback != null) {
                connectivityManager?.unregisterNetworkCallback(networkCallback!!)
            }
        } catch(e: Exception) {
            Log.w("MaviVPN", "Error unregistering callback: ${e.message}")
        }
        connectivityManager = null
        networkCallback = null
        
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            e.printStackTrace()
        }
        vpnInterface = null
        if (thread != null) {
            try {
                thread?.join(3000)
            } catch(_: Exception){}
            thread = null
        }
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
        
        try {
            if (wakeLock?.isHeld == true) {
                wakeLock?.release()
            }
        } catch (e: Exception) {
            Log.w("MaviVPN", "Error releasing WakeLock: ${e.message}")
        }
        wakeLock = null
        
        stopSelf()
    }

    override fun onDestroy() {
        super.onDestroy()
        try {
            if (wakeLock?.isHeld == true) {
                wakeLock?.release()
            }
        } catch (_: Exception) {}
        wakeLock = null
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
            val prefix = Integer.bitCount(mask.toInt())
            val expected = if (prefix == 0) 0L else (0xFFFFFFFFL shl (32 - prefix)) and 0xFFFFFFFFL
            if (mask != expected) return 24
            prefix
        } catch (e: Exception) {
            24 
        }
    }
}

