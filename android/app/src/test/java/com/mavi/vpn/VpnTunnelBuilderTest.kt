package com.mavi.vpn

import org.junit.Assert.assertEquals
import org.junit.Test

class VpnTunnelBuilderTest {
    @Test
    fun clampTunnelMtuKeepsValuesInRange() {
        assertEquals(1300, clampTunnelMtu(1300))
        assertEquals(1280, clampTunnelMtu(1280))
        assertEquals(1360, clampTunnelMtu(1360))
    }

    @Test
    fun clampTunnelMtuFallsBackWhenOutOfRange() {
        assertEquals(1280, clampTunnelMtu(1000))
        assertEquals(1280, clampTunnelMtu(1279))
        assertEquals(1280, clampTunnelMtu(1361))
        assertEquals(1280, clampTunnelMtu(1500))
    }

    @Test
    fun parseSplitPackagesReturnsEmptyForBlankInput() {
        assertEquals(emptyList<String>(), parseSplitPackages(""))
        assertEquals(emptyList<String>(), parseSplitPackages("  ,  , "))
    }

    @Test
    fun parseSplitPackagesTrimsAndDropsBlanks() {
        assertEquals(
            listOf("com.a.app", "com.b.app"),
            parseSplitPackages("com.a.app, ,com.b.app,"),
        )
        assertEquals(
            listOf("com.a.app", "com.b.app"),
            parseSplitPackages("  com.a.app ,  com.b.app  "),
        )
    }
}
