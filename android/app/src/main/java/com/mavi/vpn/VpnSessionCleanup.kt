package com.mavi.vpn

import android.net.ConnectivityManager
import android.os.ParcelFileDescriptor

internal data class SessionCleanup(
    val handle: Long,
    val workerThread: Thread?,
    val callback: ConnectivityManager.NetworkCallback?,
    val vpnInterface: ParcelFileDescriptor?,
    val generation: Long,
)
