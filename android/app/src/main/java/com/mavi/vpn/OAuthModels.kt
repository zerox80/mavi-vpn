package com.mavi.vpn

data class OAuthTokens(
    val accessToken: String,
    val refreshToken: String,
)

sealed class RefreshResult {
    data class Success(
        val tokens: OAuthTokens,
    ) : RefreshResult()

    data class Error(
        val message: String,
    ) : RefreshResult()

    data class NetworkError(
        val error: String,
    ) : RefreshResult()
}
