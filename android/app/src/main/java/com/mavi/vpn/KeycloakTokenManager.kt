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
    var accessToken: String
    var refreshToken: String
    var sessionInvalid: Boolean
    val keycloakUrl: String
    val realm: String
    val clientId: String
}

class PrefsKeycloakTokenStore(
    private val prefs: PrefsManager,
) : KeycloakTokenStore {
    override var accessToken: String
        get() = prefs.savedToken
        set(value) {
            prefs.savedToken = value
        }

    override var refreshToken: String
        get() = prefs.savedRefreshToken
        set(value) {
            prefs.savedRefreshToken = value
        }

    override var sessionInvalid: Boolean
        get() = prefs.savedKeycloakSessionInvalid
        set(value) {
            prefs.savedKeycloakSessionInvalid = value
        }

    override val keycloakUrl: String
        get() = prefs.savedKcUrl

    override val realm: String
        get() = prefs.savedKcRealm

    override val clientId: String
        get() = prefs.savedKcClientId
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
            val currentAccessToken = store.accessToken
            if (OAuthHelper.isAccessTokenUsable(currentAccessToken, skewSeconds)) {
                store.sessionInvalid = false
                return@withLock TokenAcquireResult.Usable(currentAccessToken, refreshed = false)
            }

            refreshLocked()
        }
    }

    suspend fun refreshAccessToken(): TokenAcquireResult =
        refreshMutex.withLock {
            refreshLocked()
        }

    private suspend fun refreshLocked(): TokenAcquireResult {
        val currentRefreshToken = store.refreshToken
        if (currentRefreshToken.isBlank()) {
            return TokenAcquireResult.NeedsLogin("No refresh token available")
        }

        if (store.keycloakUrl.isBlank() || store.realm.isBlank() || store.clientId.isBlank()) {
            return TokenAcquireResult.NeedsLogin("Keycloak configuration is incomplete")
        }

        return when (
            val refreshed =
                refresher(
                currentRefreshToken,
                store.keycloakUrl,
                store.realm,
                store.clientId,
            )
        ) {
            is RefreshResult.Success -> {
                store.accessToken = refreshed.tokens.accessToken
                store.refreshToken = refreshed.tokens.refreshToken
                store.sessionInvalid = false
                TokenAcquireResult.Usable(refreshed.tokens.accessToken, refreshed = true)
            }
            is RefreshResult.NetworkError -> {
                store.sessionInvalid = false
                TokenAcquireResult.TemporaryFailure(refreshed.error)
            }
            is RefreshResult.Error -> {
                store.accessToken = ""
                store.refreshToken = ""
                store.sessionInvalid = true
                TokenAcquireResult.NeedsLogin(refreshed.message)
            }
        }
    }
}
