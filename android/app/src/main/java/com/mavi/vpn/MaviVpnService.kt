package com.mavi.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
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

class MaviVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var thread: Thread? = null
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile private var vpnSessionHandle: Long = 0
    @Volatile private var isRunning = false
    private var wakeLock: PowerManager.WakeLock? = null
    private val vpnLock = Any()

    companion object {
        init {
            System.loadLibrary("mavivpn")
        }
    }

    // Native methods implemented in Rust
    private external fun init(service: MaviVpnService, token: String, endpoint: String, certPin: String, censorshipResistant: Boolean): Long
    private external fun getConfig(handle: Long): String
    private external fun startLoop(handle: Long, fd: Int)
    private external fun stop(handle: Long)
    private external fun free(handle: Long)
    private external fun networkChanged(handle: Long)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action

        if (action == "STOP") {
            stopVpn()
            return START_NOT_STICKY
        }
        
        // If action is CONNECT or intent is null (System Restart), we try to start
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
                
                // Save to prefs for restart
                val prefs = getSharedPreferences("MaviVPN", Context.MODE_PRIVATE)
                prefs.edit()
                    .putString("saved_ip", ip)
                    .putString("saved_port", port)
                    .putString("saved_token", token)
                    .putString("saved_pin", pin)
                    .putString("saved_split_mode", splitMode)
                    .putString("saved_split_packages", splitPackages)
                    .apply()
            } else {
                Log.i("MaviVPN", "Service restarted by System. Reloading credentials...")
                val prefs = getSharedPreferences("MaviVPN", Context.MODE_PRIVATE)
                ip = prefs.getString("saved_ip", "") ?: ""
                port = prefs.getString("saved_port", "4433") ?: "4433"
                token = prefs.getString("saved_token", "") ?: ""
                pin = prefs.getString("saved_pin", "") ?: ""
                splitMode = prefs.getString("saved_split_mode", "") ?: ""
                splitPackages = prefs.getString("saved_split_packages", "") ?: ""
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
        if (thread != null) return

        // Register Network Callback
        try {
            connectivityManager = getSystemService(ConnectivityManager::class.java)
            networkCallback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    Log.d("MaviVPN", "Network available: $network")
                    if (vpnSessionHandle != 0L) {
                         networkChanged(vpnSessionHandle)
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

        // Create Notification
        val channelId = "vpn_channel"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val chan = NotificationChannel(channelId, "VPN Status", NotificationManager.IMPORTANCE_LOW)
            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(chan)
        }

        val notification = Notification.Builder(this, channelId)
            .setContentTitle("Mavi VPN")
            .setContentText("Connecting to $ip...")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .build()
        
        // Acquire WakeLock to keep VPN running during sleep
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "MaviVPN::ServiceWakeLock")
        wakeLock?.acquire() // Held until stopVpn() releases it

        isRunning = true
        startForeground(1, notification)

        thread = Thread {
            Log.d("MaviVPN", "Starting VPN Thread")
            
            while (isRunning) {
                try {
                    Log.d("MaviVPN", "Attempting connection to $ip:$port")
                    // 1. Init / Handshake
                    val handle = init(this, token, "$ip:$port", certPin, true)
                    if (handle == 0L) {
                        Log.e("MaviVPN", "Handshake failed. Retrying in 500ms...")
                        Thread.sleep(500)
                        continue
                    }
                    synchronized(vpnLock) {
                        vpnSessionHandle = handle
                    }

                    try {
                        // 2. Get Config
                        val configJson = getConfig(handle)
                        Log.d("MaviVPN", "Config Received: $configJson")
                        val root = org.json.JSONObject(configJson)
                        // Check if wrapped in Config (which it is due to Rust Enum serialization)
                        val config = if (root.has("Config")) root.getJSONObject("Config") else root
                        
                        // 3. Establish Interface
                        var localInterface: ParcelFileDescriptor? = null // Declare outside try
                        
                        try {
                             val builder = Builder()
                        
                             // Parse Config
                             val assignedIp = config.getString("assigned_ip")
                             // Dynamic netmask calculation
                             val netmask = config.optString("netmask", "255.255.255.0")
                             val prefixLength = netmaskToPrefixLength(netmask)
                        
                             builder.addAddress(assignedIp, prefixLength)
                        
                             // Routes
                             builder.addRoute("0.0.0.0", 0)
                        
                             // DNS
                             val dns = config.optString("dns_server", "8.8.8.8")
                             builder.addDnsServer(dns)
                        
                             // IPv6
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

                             // Split Tunneling (App based)
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
                             // Set inner MTU to 1280 to comply with IPv6 minimum requirements
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
                            
                                 // 4. Start Loop (Blocks until error or stop)
                                 startLoop(handle, fd)
                            
                                 Log.d("MaviVPN", "Native VPN loop exited")
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
                        Log.d("MaviVPN", "Cleaning up VPN session for retry/stop")
                        
                        // Clean native memory safely
                        synchronized(vpnLock) {
                             if (vpnSessionHandle != 0L) {
                                  free(vpnSessionHandle)
                                  vpnSessionHandle = 0
                             }
                        }
                    }
                } catch (e: Exception) {
                     Log.e("MaviVPN", "Critical error in VPN thread: ${e.message}")
                     try { Thread.sleep(500) } catch(_: Exception){}
                }
                
                // Ensure current thread is still active
                if (Thread.currentThread() != thread) {
                    Log.i("MaviVPN", "Thread superseded. Exiting loop.")
                    break
                }
                
                if (isRunning) {
                    Log.i("MaviVPN", "Connection lost or loop exited. Restarting in 500ms...")
                    try { Thread.sleep(500) } catch(_: Exception){}
                }
            }
            
            Log.i("MaviVPN", "VPN Thread Stopped. Stopping Service.")
            stopSelf()
        }.also { it.start() }
    }

    private fun stopVpn() {
        isRunning = false
        
        synchronized(vpnLock) {
             val handle = vpnSessionHandle
             if (handle != 0L) {
                  stop(handle) // Signal Rust to stop
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
                // thread?.interrupt() // Don't interrupt, let the native stop flag handle it
                thread = null 
            } catch(_: Exception){}
        }
        stopForeground(true)
        
        try {
            if (wakeLock?.isHeld == true) {
                wakeLock?.release()
                Log.d("MaviVPN", "WakeLock released")
            }
        } catch (e: Exception) {
            Log.w("MaviVPN", "Error releasing WakeLock: ${e.message}")
        }
        wakeLock = null
    }

    private fun netmaskToPrefixLength(netmask: String): Int {
        return try {
            netmask.split(".").sumOf { Integer.bitCount(it.toInt()) }
        } catch (e: Exception) {
            24 // Fallback default
        }
    }
}

