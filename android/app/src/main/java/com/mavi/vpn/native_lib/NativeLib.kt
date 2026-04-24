package com.mavi.vpn.native_lib

import com.mavi.vpn.MaviVpnService

object NativeLib {
    init {
        System.loadLibrary("mavivpn")
    }

    external fun init(service: MaviVpnService, token: String, endpoint: String, certPin: String, censorshipResistant: Boolean, http3Framing: Boolean, echConfig: String, vpnMtu: Int): Long
    external fun getLastInitError(): String
    external fun getConfig(handle: Long): String
    external fun startLoop(handle: Long, fd: Int)
    external fun stop(handle: Long)
    external fun free(handle: Long)
    external fun networkChanged(handle: Long)
}
