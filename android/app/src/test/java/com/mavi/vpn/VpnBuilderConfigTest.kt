package com.mavi.vpn

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class VpnBuilderConfigTest {
    @Test
    fun assignedIpv6ConfigIsNoopWhenServerDidNotAssignIpv6() {
        val builder = RecordingBuilder()

        val enabled = applyAssignedIpv6Config(JSONObject("""{"assigned_ip":"10.8.0.2"}"""), builder)

        assertFalse(enabled)
        assertTrue(builder.calls.isEmpty())
    }

    @Test
    fun assignedIpv6ConfigAddsAddressRouteAndDns() {
        val builder = RecordingBuilder()

        val enabled = applyAssignedIpv6Config(
            JSONObject(
                """
                {
                  "assigned_ipv6": "fd00::2",
                  "netmask_v6": 64,
                  "dns_server_v6": "fd00::1"
                }
                """.trimIndent(),
            ),
            builder,
        )

        assertTrue(enabled)
        assertEquals(
            listOf(
                "address fd00::2/64",
                "route ::/0",
                "dns fd00::1",
            ),
            builder.calls,
        )
    }

    @Test
    fun assignedIpv6ConfigPropagatesRouteFailure() {
        val builder = RecordingBuilder(failIpv6Route = true)

        try {
            applyAssignedIpv6Config(JSONObject("""{"assigned_ipv6":"fd00::2"}"""), builder)
            fail("Expected IPv6 route failure")
        } catch (e: IllegalStateException) {
            assertEquals("route failed", e.message)
        }

        assertEquals(
            listOf(
                "address fd00::2/64",
                "route ::/0",
            ),
            builder.calls,
        )
    }
}

private class RecordingBuilder(
    private val failIpv6Route: Boolean = false,
) : VpnBuilderAdapter {
    val calls = mutableListOf<String>()

    override fun addAddress(
        address: String,
        prefixLength: Int,
    ) {
        calls.add("address $address/$prefixLength")
    }

    override fun addRoute(
        address: String,
        prefixLength: Int,
    ) {
        calls.add("route $address/$prefixLength")
        if (failIpv6Route && address == "::" && prefixLength == 0) {
            throw IllegalStateException("route failed")
        }
    }

    override fun addDnsServer(address: String) {
        calls.add("dns $address")
    }
}
