package com.mavi.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log

class MaviVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var thread: Thread? = null

    companion object {
        init {
            System.loadLibrary("mavivpn")
        }
    }

    // Native methods implemented in Rust
    private external fun connect(fd: Int, token: String, endpoint: String): Int
    private external fun stop()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        if (action == "STOP") {
            stopVpn()
            return START_NOT_STICKY
        } else if (action == "CONNECT") {
            val ip = intent?.getStringExtra("IP") ?: ""
            val port = intent?.getStringExtra("PORT") ?: "4433"
            val token = intent?.getStringExtra("TOKEN") ?: ""
            startVpn(ip, port, token)
            return START_STICKY
        }
        return START_NOT_STICKY
    }

    private fun startVpn(ip: String, port: String, token: String) {
        if (thread != null) return

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

        // Establish VPN Interface
        val builder = Builder()
        
        // Add DNS server (Google DNS for reliability)
        builder.addDnsServer("8.8.8.8")
        builder.addDnsServer("8.8.4.4")

        builder.addAddress("10.8.0.2", 24)
        builder.addRoute("0.0.0.0", 0)
        builder.setSession("MaviVPN")
        builder.setMtu(1280)
        
        // Ensure blocking for better reachability on some networks
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }
        
        vpnInterface = builder.establish()

        if (vpnInterface != null) {
            val fd = vpnInterface!!.fd
            thread = Thread {
                Log.d("MaviVPN", "Starting native VPN loop to $ip:$port")
                connect(fd, token, "$ip:$port")
                Log.d("MaviVPN", "Native VPN loop exited")
                stopSelf()
            }.also { it.start() }
        }
    }

    private fun stopVpn() {
        stop()
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            e.printStackTrace()
        }
        vpnInterface = null
        thread?.interrupt()
        thread = null
        stopForeground(true)
    }
}
