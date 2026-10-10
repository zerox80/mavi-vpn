package com.mavi.vpn.data

import com.mavi.vpn.KeycloakAuthority
import com.mavi.vpn.KeycloakTokenManager
import com.mavi.vpn.KeycloakTokenSnapshot
import com.mavi.vpn.KeycloakTokenStore
import com.mavi.vpn.OAuthTokens
import com.mavi.vpn.RefreshResult
import com.mavi.vpn.TokenAcquireResult
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class KeycloakSessionPreferencesTest {
    private val memory = MemoryPreferences()
    private val sessions = KeycloakSessionPreferences(memory.prefs, memory.secrets)
    private val issuer = KeycloakAuthority.from("https://auth.example.com/auth", "realm", "client")!!
    private val tokens = OAuthTokens("access", "refresh")
    private val adapter =
        object : KeycloakTokenStore {
            override fun snapshot(): KeycloakTokenSnapshot = sessions.snapshot()

            override fun replace(
                expected: KeycloakTokenSnapshot,
                tokens: OAuthTokens?,
                invalid: Boolean,
            ): Boolean = sessions.replace(expected, tokens, invalid)
        }

    private fun configure(authority: KeycloakAuthority = issuer) {
        sessions.updateAuthority(authority.baseUrl, authority.realm, authority.clientId)
    }

    private fun login(): KeycloakTokenSnapshot {
        assertTrue(sessions.beginLogin(issuer, "state", "verifier"))
        val pending = sessions.consumeLogin("state")!!
        assertTrue(sessions.replace(pending.snapshot, tokens, false))
        return sessions.snapshot()
    }

    @Test
    fun legacyTokensAreNeverAdoptedByCurrentConfiguration() =
        runBlocking {
            configure()
            memory.secrets.setString("saved_token", "legacy-access")
            memory.secrets.setString("saved_refresh_token", "legacy-refresh")
            assertNull(sessions.snapshot().tokens)
            val manager = KeycloakTokenManager(adapter) { _, _, _, _ -> error("must require a fresh login") }
            assertTrue(manager.refreshAccessToken() is TokenAcquireResult.NeedsLogin)
        }

    @Test
    fun storedTokensSurviveRestartOnlyForTheSameAuthority() {
        configure()
        login()
        val reopened = KeycloakSessionPreferences(memory.prefs, memory.secrets)
        assertEquals(tokens, reopened.snapshot().tokens)
        sessions.updateAuthority("https://AUTH.example.com:443/auth/", "realm", "client")
        assertEquals(tokens, sessions.snapshot().tokens)
        for (other in listOf(
            issuer.copy(baseUrl = "https://other.example.com/auth"),
            issuer.copy(baseUrl = "https://auth.example.com/other"),
            issuer.copy(baseUrl = "https://auth.example.com:8443/auth"),
            issuer.copy(realm = "other"),
            issuer.copy(clientId = "other"),
        )) {
            configure()
            login()
            configure(other)
            assertNull(sessions.snapshot().tokens)
        }
    }

    @Test
    fun interruptedConfigurationWriteCannotRelabelOldTokens() {
        configure()
        login()
        // Even if old encrypted data remains after a crash or restored preferences,
        // the issuer inside the record must still match before either token is used.
        memory.prefs
            .edit()
            .putString("saved_kc_url", "https://other.example.com")
            .apply()
        assertNull(sessions.snapshot().tokens)
    }

    @Test
    fun pkceStateIsOneUseAndBoundToTheStartingConfigurationAndLogin() {
        configure()
        assertTrue(sessions.beginLogin(issuer, "first", "verifier"))
        assertNull(sessions.consumeLogin("wrong-state"))
        val first = sessions.consumeLogin("first")!!
        assertNull(sessions.consumeLogin("first"))
        configure(issuer.copy(realm = "other"))
        configure()
        assertFalse(sessions.replace(first.snapshot, tokens, false))
        assertTrue(sessions.beginLogin(issuer, "second", "verifier"))
        assertTrue(sessions.beginLogin(issuer, "third", "verifier"))
        assertNull(sessions.consumeLogin("second"))
        assertNotNull(sessions.consumeLogin("third"))
        assertTrue(sessions.beginLogin(issuer, "fourth", "verifier"))
        configure(issuer.copy(clientId = "other"))
        assertNull(sessions.consumeLogin("fourth"))
    }

    @Test
    fun lateRefreshResultsCannotOverwriteOrClearANewerLogin() =
        runBlocking {
            for (result in listOf(
                RefreshResult.Success(OAuthTokens("late-access", "late-refresh")),
                RefreshResult.Error("invalid_grant"),
                RefreshResult.NetworkError("offline"),
            )) {
                configure()
                login()
                val manager =
                    KeycloakTokenManager(adapter) { token, url, realm, client ->
                        assertEquals("refresh", token)
                        assertEquals(issuer.baseUrl, url)
                        assertEquals(issuer.realm, realm)
                        assertEquals(issuer.clientId, client)
                        configure(issuer.copy(realm = "other"))
                        configure()
                        login()
                        result
                    }
                assertTrue(manager.refreshAccessToken() is TokenAcquireResult.NeedsLogin)
                assertEquals(tokens, sessions.snapshot().tokens)
                assertFalse(memory.prefs.getBoolean("saved_keycloak_session_invalid", false))
            }
        }

    @Test
    fun refreshForUnchangedAuthorityPersistsRotationAndPreservesTemporaryFailures() =
        runBlocking {
            configure()
            login()
            val rotated = OAuthTokens("rotated-access", "rotated-refresh")
            val manager = KeycloakTokenManager(adapter) { _, _, _, _ -> RefreshResult.Success(rotated) }
            assertTrue(manager.refreshAccessToken() is TokenAcquireResult.Usable)
            assertEquals(rotated, sessions.snapshot().tokens)
            val offline = KeycloakTokenManager(adapter) { _, _, _, _ -> RefreshResult.NetworkError("offline") }
            assertTrue(offline.refreshAccessToken() is TokenAcquireResult.TemporaryFailure)
            assertEquals(rotated, sessions.snapshot().tokens)
            val rejected = KeycloakTokenManager(adapter) { _, _, _, _ -> RefreshResult.Error("invalid_grant") }
            assertTrue(rejected.refreshAccessToken() is TokenAcquireResult.NeedsLogin)
            assertNull(sessions.snapshot().tokens)
        }

    @Test
    fun logoutInvalidatesPendingResultsAndClearsLegacyCredentialsTogether() {
        configure()
        val snapshot = login()
        memory.secrets.setString("saved_token", "legacy-access")
        memory.secrets.setString("saved_refresh_token", "legacy-refresh")
        sessions.clear()
        assertFalse(sessions.replace(snapshot, tokens, false))
        assertEquals("", memory.secrets.getString("saved_token"))
        assertEquals("", memory.secrets.getString("saved_refresh_token"))
        assertNull(sessions.snapshot().tokens)
    }

    @Test
    fun authorityRejectsAmbiguousUrlsAndPreservesIpv6Loopback() {
        for (url in listOf("https://user@auth.example.com", "https://auth.example.com?other", "https://auth.example.com#other")) {
            assertNull(KeycloakAuthority.from(url, "realm", "client"))
        }
        assertEquals("http://[::1]:8080/auth", KeycloakAuthority.from("http://[::1]:8080/auth/", "realm", "client")?.baseUrl)
    }
}
