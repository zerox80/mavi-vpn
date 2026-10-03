package com.mavi.vpn

import com.mavi.vpn.data.PrefsManager
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

sealed class TokenAcquireResult {
    data class Usable(
        val accessToken: String,
        val refreshed: Boolean,
    ) : TokenAcquireResult()

    data class TemporaryFailure(
        val message: String,
    ) : TokenAcquireResult()

    data class NeedsLogin(
        val message: String,
    ) : TokenAcquireResult()
}

interface KeycloakTokenStore {
    fun snapshot(): KeycloakTokenSnapshot

    fun replace(
        expected: KeycloakTokenSnapshot,
        tokens: OAuthTokens?,
        invalid: Boolean,
    ): Boolean
}

class PrefsKeycloakTokenStore(
    private val prefs: PrefsManager,
) : KeycloakTokenStore {
    override fun snapshot(): KeycloakTokenSnapshot = prefs.keycloak.snapshot()

    override fun replace(
        expected: KeycloakTokenSnapshot,
        tokens: OAuthTokens?,
        invalid: Boolean,
    ): Boolean = prefs.keycloak.replace(expected, tokens, invalid)
}

class KeycloakTokenManager(
    private val store: KeycloakTokenStore,
    private val refresher: suspend (
        refreshToken: String,
        keycloakUrl: String,
        realm: String,
        clientId: String,
    ) -> RefreshResult = OAuthHelper::refreshToken,
) {
    private val refreshMutex = Mutex()

    suspend fun getUsableAccessToken(skewSeconds: Long = 60): TokenAcquireResult {
        return refreshMutex.withLock {
            val snapshot = store.snapshot()
            val currentAccessToken = snapshot.tokens?.accessToken.orEmpty()
            if (OAuthHelper.isAccessTokenUsable(currentAccessToken, skewSeconds)) {
                if (!store.replace(snapshot, snapshot.tokens, invalid = false)) {
                    return@withLock sessionChanged()
                }
                return@withLock TokenAcquireResult.Usable(currentAccessToken, refreshed = false)
            }

            refreshLocked(snapshot)
        }
    }

    suspend fun refreshAccessToken(): TokenAcquireResult =
        refreshMutex.withLock {
            refreshLocked(store.snapshot())
        }

    private fun sessionChanged(): TokenAcquireResult.NeedsLogin =
        TokenAcquireResult.NeedsLogin("Keycloak configuration or login changed; reconnect")

    private suspend fun refreshLocked(snapshot: KeycloakTokenSnapshot): TokenAcquireResult {
        val authority =
            snapshot.authority
                ?: return TokenAcquireResult.NeedsLogin("Keycloak configuration is incomplete")
        val currentRefreshToken = snapshot.tokens?.refreshToken.orEmpty()
        if (currentRefreshToken.isBlank()) {
            return TokenAcquireResult.NeedsLogin("No refresh token available")
        }

        // Both the secret and endpoint come from one immutable snapshot. A
        // settings edit during I/O cannot redirect a token or adopt its result.
        return when (
            val refreshed =
                refresher(
                    currentRefreshToken,
                    authority.baseUrl,
                    authority.realm,
                    authority.clientId,
                )
        ) {
            is RefreshResult.Success -> {
                if (!store.replace(snapshot, refreshed.tokens, invalid = false)) return sessionChanged()
                TokenAcquireResult.Usable(refreshed.tokens.accessToken, refreshed = true)
            }
            is RefreshResult.NetworkError -> {
                if (!store.replace(snapshot, snapshot.tokens, invalid = false)) return sessionChanged()
                TokenAcquireResult.TemporaryFailure(refreshed.error)
            }
            is RefreshResult.Error -> {
                if (!store.replace(snapshot, null, invalid = true)) return sessionChanged()
                TokenAcquireResult.NeedsLogin(refreshed.message)
            }
        }
    }
}
