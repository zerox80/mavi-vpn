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
import android.util.Log

class MaviVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var thread: Thread? = null
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile private var vpnSessionHandle: Long = 0

    companion object {
        init {
            System.loadLibrary("mavivpn")
        }
    }

    // Native methods implemented in Rust
    private external fun init(service: MaviVpnService, token: String, endpoint: String, certPin: String): Long
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
        } else if (action == "CONNECT") {
            val ip = intent?.getStringExtra("IP") ?: ""
            val port = intent?.getStringExtra("PORT") ?: "4433"
            val token = intent?.getStringExtra("TOKEN") ?: ""
            val pin = intent?.getStringExtra("PIN") ?: ""
            startVpn(ip, port, token, pin)
            return START_STICKY
        }
        return START_NOT_STICKY
    }

    private fun startVpn(ip: String, port: String, token: String, certPin: String) {
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
        
        startForeground(1, notification)

        thread = Thread {
            Log.d("MaviVPN", "Starting VPN initialization to $ip:$port")
            
            // 1. Init / Handshake
            val handle = init(this, token, "$ip:$port", certPin)
            if (handle == 0L) {
                Log.e("MaviVPN", "Handshake failed. Stopping.")
                stopVpn()
                return@Thread
            }
            vpnSessionHandle = handle

            try {
                // 2. Get Config
                val configJson = getConfig(handle)
                Log.d("MaviVPN", "Config Received: $configJson")
                val root = org.json.JSONObject(configJson)
                // Check if wrapped in Config (which it is due to Rust Enum serialization)
                val config = if (root.has("Config")) root.getJSONObject("Config") else root
                
                // 3. Establish Interface
                val builder = Builder()
                
                // Parse Config
                val assignedIp = config.getString("assigned_ip")
                // netmask usually /24 for IPv4 in this simple setup, or we can parse string
                // config doesn't send CIDR for v4, just netmask IP.. but Builder wants prefix length.
                // Rust config sends 'netmask' as IP. 255.255.255.0 -> 24.
                // For simplicity assuming /24 as server default is 10.8.0.0/24
                val prefixLength = 24 
                
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

                builder.setSession("MaviVPN")
                builder.setMtu(config.optInt("mtu", 1280))

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    builder.setMetered(false)
                }

                vpnInterface = builder.establish()

                if (vpnInterface != null) {
                    val fd = vpnInterface!!.fd
                    Log.d("MaviVPN", "Interface established. Starting Loop.")
                    
                    // 4. Start Loop
                    startLoop(handle, fd)
                    
                    Log.d("MaviVPN", "Native VPN loop exited")
                } else {
                    Log.e("MaviVPN", "Failed to establish VPN interface")
                }

            } catch (e: Exception) {
                Log.e("MaviVPN", "Error during VPN setup: ${e.message}")
                e.printStackTrace()
            } finally {
                Log.d("MaviVPN", "Cleaning up VPN session")
                if (vpnSessionHandle != 0L) {
                     free(vpnSessionHandle)
                     vpnSessionHandle = 0
                }
                stopSelf()
            }
        }.also { it.start() }
    }

    private fun stopVpn() {
        val handle = vpnSessionHandle
        if (handle != 0L) {
             stop(handle) // Signal Rust to stop
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
    }
}
