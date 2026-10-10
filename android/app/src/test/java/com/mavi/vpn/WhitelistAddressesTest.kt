package com.mavi.vpn

import org.junit.Assert.assertEquals
import org.junit.Test
import java.net.InetAddress

class WhitelistAddressesTest {
    @Test
    fun namesAndAliasesNeverReachTheNumericParser() {
        val entries =
            listOf(
                "example.test",
                "localhost",
                "127.1",
                "2130706433",
                "0x7f000001",
                "192.0.2.1.",
                "192.0.2.1:443",
                "[2001:db8::1]",
                "fe80::1%wlan0",
                "192.0.2.1/32",
                " 192.0.2.1",
                "192.0.2.01",
                "192.0.2.256",
            )
        assertEquals(
            emptyList<InetAddress>(),
            whitelistAddresses(entries, true) {
                error("No lookup or parsing is allowed for $it")
            },
        )
    }

    @Test
    fun literalAddressesPreserveFamilyFilteringAndDeduplication() {
        val v4 = InetAddress.getByAddress(byteArrayOf(192.toByte(), 0, 2, 1))
        val v6 = InetAddress.getByAddress(ByteArray(16).also { it[15] = 1 })
        val entries = listOf("192.0.2.1", "::1", "192.0.2.1")
        val parser: (String) -> InetAddress = { if (it == "::1") v6 else v4 }
        assertEquals(listOf(v4, v6), whitelistAddresses(entries, true, parser))
        assertEquals(listOf(v4), whitelistAddresses(entries, false, parser))
        assertEquals(
            emptyList<InetAddress>(),
            whitelistAddresses(listOf("::::"), true) {
                throw IllegalArgumentException("invalid numeric address")
            },
        )
    }
}
