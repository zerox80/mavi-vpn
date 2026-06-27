package com.mavi.vpn.data

import org.junit.Assert.assertEquals
import org.junit.Test

class PrefsManagerTest {
    @Test
    fun sanitizeVpnMtuKeepsDisabledAndSupportedValues() {
        assertEquals(0, sanitizeVpnMtu(0))
        assertEquals(1280, sanitizeVpnMtu(1280))
        assertEquals(1360, sanitizeVpnMtu(1360))
    }

    @Test
    fun sanitizeVpnMtuFallsBackForUnsupportedValues() {
        assertEquals(0, sanitizeVpnMtu(-1))
        assertEquals(0, sanitizeVpnMtu(1))
        assertEquals(0, sanitizeVpnMtu(1279))
        assertEquals(0, sanitizeVpnMtu(1361))
        assertEquals(0, sanitizeVpnMtu(Int.MAX_VALUE))
    }
}
