package com.mavi.vpn

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class KeycloakTokenManagerTest {
    @Test
    fun accessTokenIsUsableWhenExpiryIsOutsideSkewWindow() {
        val token = jwt(exp = nowSeconds() + 120)

        assertTrue(OAuthHelper.isAccessTokenUsable(token, skewSeconds = 60))
    }

    @Test
    fun accessTokenIsNotUsableInsideSkewWindow() {
        val token = jwt(exp = nowSeconds() + 30)

        assertFalse(OAuthHelper.isAccessTokenUsable(token, skewSeconds = 60))
    }

    @Test
    fun accessTokenIsNotUsableWhenExpired() {
        val token = jwt(exp = nowSeconds() - 1)

        assertFalse(OAuthHelper.isAccessTokenUsable(token, skewSeconds = 0))
    }

    @Test
    fun accessTokenIsNotUsableWhenMalformed() {
        assertFalse(OAuthHelper.isAccessTokenUsable("not-a-jwt", skewSeconds = 0))
    }

    @Test
    fun accessTokenExpiresAtReadsExpClaim() {
        val exp = nowSeconds() + 600

        assertEquals(exp, OAuthHelper.accessTokenExpiresAt(jwt(exp)))
    }

    @Test
    fun refreshResponseKeepsPreviousRefreshTokenWhenKeycloakOmitsRotation() {
        val tokens = OAuthHelper.parseTokenResponse("""{"access_token":"new-access"}""", fallbackRefreshToken = "old-refresh")

        assertNotNull(tokens)
        assertEquals("new-access", tokens?.accessToken)
        assertEquals("old-refresh", tokens?.refreshToken)
    }

    @Test
    fun tokenResponseWithoutRefreshTokenOrFallbackIsRejected() {
        val tokens = OAuthHelper.parseTokenResponse("""{"access_token":"new-access"}""")

        assertNull(tokens)
    }

    @Test
    fun tokenResponseWithoutAccessTokenIsRejected() {
        val tokens = OAuthHelper.parseTokenResponse("""{"refresh_token":"refresh"}""")

        assertNull(tokens)
    }

    @Test
    fun managerDoesNotRefreshUsableAccessToken() {
        runBlocking {
            var refreshCalls = 0
            val token = jwt(exp = nowSeconds() + 600)
            val store = FakeTokenStore(accessToken = token, refreshToken = "refresh")
            val manager =
                KeycloakTokenManager(store) { _, _, _, _ ->
                    refreshCalls++
                    RefreshResult.Error("unexpected")
                }

            val result = manager.getUsableAccessToken(skewSeconds = 60)

            assertTrue(result is TokenAcquireResult.Usable)
            assertEquals(token, (result as TokenAcquireResult.Usable).accessToken)
            assertFalse(result.refreshed)
            assertEquals(0, refreshCalls)
            assertFalse(store.sessionInvalid)
        }
    }

    @Test
    fun managerRefreshesExpiredAccessTokenAndPersistsRotatedTokens() {
        runBlocking {
            val refreshedAccess = jwt(exp = nowSeconds() + 600)
            val store = FakeTokenStore(accessToken = jwt(exp = nowSeconds() - 1), refreshToken = "old-refresh")
            val manager =
                KeycloakTokenManager(store) { refreshToken, keycloakUrl, realm, clientId ->
                    assertEquals("old-refresh", refreshToken)
                    assertEquals("https://auth.example.com", keycloakUrl)
                    assertEquals("mavi-vpn", realm)
                    assertEquals("mavi-client", clientId)
                    RefreshResult.Success(OAuthTokens(refreshedAccess, "new-refresh"))
                }

            val result = manager.getUsableAccessToken(skewSeconds = 60)

            assertTrue(result is TokenAcquireResult.Usable)
            assertEquals(refreshedAccess, store.accessToken)
            assertEquals("new-refresh", store.refreshToken)
            assertFalse(store.sessionInvalid)
        }
    }

    @Test
    fun managerLeavesTokensIntactOnTemporaryRefreshFailure() {
        runBlocking {
            val expiredAccess = jwt(exp = nowSeconds() - 1)
            val store = FakeTokenStore(accessToken = expiredAccess, refreshToken = "refresh")
            val manager =
                KeycloakTokenManager(store) { _, _, _, _ ->
                    RefreshResult.NetworkError("offline")
                }

            val result = manager.getUsableAccessToken(skewSeconds = 60)

            assertTrue(result is TokenAcquireResult.TemporaryFailure)
            assertEquals(expiredAccess, store.accessToken)
            assertEquals("refresh", store.refreshToken)
            assertFalse(store.sessionInvalid)
        }
    }

    @Test
    fun managerClearsTokensOnlyWhenRefreshIsRejected() {
        runBlocking {
            val store = FakeTokenStore(accessToken = jwt(exp = nowSeconds() - 1), refreshToken = "refresh")
            val manager =
                KeycloakTokenManager(store) { _, _, _, _ ->
                    RefreshResult.Error("invalid_grant")
                }

            val result = manager.getUsableAccessToken(skewSeconds = 60)

            assertTrue(result is TokenAcquireResult.NeedsLogin)
            assertEquals("", store.accessToken)
            assertEquals("", store.refreshToken)
            assertTrue(store.sessionInvalid)
        }
    }

    @Test
    fun managerDoesNotClearTokensWhenRefreshTokenIsMissing() {
        runBlocking {
            val expiredAccess = jwt(exp = nowSeconds() - 1)
            val store = FakeTokenStore(accessToken = expiredAccess, refreshToken = "")
            val manager =
                KeycloakTokenManager(store) { _, _, _, _ ->
                    RefreshResult.Error("unexpected")
                }

            val result = manager.getUsableAccessToken(skewSeconds = 60)

            assertTrue(result is TokenAcquireResult.NeedsLogin)
            assertEquals(expiredAccess, store.accessToken)
            assertEquals("", store.refreshToken)
            assertFalse(store.sessionInvalid)
        }
    }

    private class FakeTokenStore(
        override var accessToken: String,
        override var refreshToken: String,
        override var sessionInvalid: Boolean = false,
        override val keycloakUrl: String = "https://auth.example.com",
        override val realm: String = "mavi-vpn",
        override val clientId: String = "mavi-client",
    ) : KeycloakTokenStore

    private fun jwt(exp: Long): String {
        val header = encode("""{"alg":"RS256"}""")
        val payload = encode("""{"exp":$exp}""")
        return "$header.$payload.signature"
    }

    private fun encode(json: String): String = Base64.getUrlEncoder().withoutPadding().encodeToString(json.toByteArray(Charsets.UTF_8))

    private fun nowSeconds(): Long = System.currentTimeMillis() / 1000L
}
