package com.mavi.vpn

import android.net.VpnService
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class VpnStartRequestTest {
    private val saved =
        VpnStartRequest(
            ip = "vpn.example.com",
            port = "443",
            token = "saved-credential",
            pin = "saved-pin",
            splitMode = "exclude",
            splitPackages = "com.example.app",
        )

    @Test
    fun alwaysOnAndStickyRestartsRestoreSavedConfigurationWithoutReadingExtras() {
        for (action in listOf(null, VpnService.SERVICE_INTERFACE)) {
            val request =
                resolveVpnStartRequest(
                    action = action,
                    savedRequest = { saved },
                    connectRequest = { error("System start must not overwrite saved credentials") },
                )
            assertEquals(saved, request)
        }
    }

    @Test
    fun explicitConnectUsesTheNewRequest() {
        val explicit = saved.copy(ip = "new.example.com", token = "new-credential")
        val request =
            resolveVpnStartRequest(
                action = "CONNECT",
                savedRequest = { error("Explicit CONNECT must read its extras") },
                connectRequest = { explicit },
            )
        assertEquals(explicit, request)
    }

    @Test
    fun stopAndUnknownActionsLeaveConfigurationUntouched() {
        for (action in listOf("STOP", "unknown")) {
            assertNull(
                resolveVpnStartRequest(
                    action = action,
                    savedRequest = { error("Unexpected saved-config read") },
                    connectRequest = { error("Unexpected preference write") },
                ),
            )
        }
    }
}
