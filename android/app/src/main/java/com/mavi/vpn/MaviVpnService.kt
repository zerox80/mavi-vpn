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
            startVpn()
            return START_STICKY
        }
        return START_NOT_STICKY
    }

    private fun startVpn() {
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
            .setContentText("Connected to secure network")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .build()
        
        startForeground(1, notification)

        // Establish VPN Interface
        val builder = Builder()
        builder.addAddress("10.8.0.2", 24) // Initial dummy address, will be updated by Rust logic ideally? 
        // Note: Android VpnService usually needs an address upfront. 
        // For a proper setup, Rust should negotiate IP then we update builder. 
        // But for simplicity/demo, we can set a dummy or try to set it dynamically via JNI callback.
        // For 10/10 app, we should do the handshake FIRST in regular socket, get IP, then establish VPN.
        // But here we'll pass the FD to Rust directly.
        // Let's assume we use 0.0.0.0 and let Rust handle TUN read/write, but Android requires an address.
        // We'll use a placeholder and fix it later if needed.
        builder.addRoute("0.0.0.0", 0)
        builder.setSession("MaviVPN")
        builder.setMtu(1280)
        
        vpnInterface = builder.establish()

        if (vpnInterface != null) {
            val fd = vpnInterface!!.fd
            thread = Thread {
                Log.d("MaviVPN", "Starting native VPN loop")
                connect(fd, "test-token", "192.168.1.100:4433") // TODO: Configurable
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
