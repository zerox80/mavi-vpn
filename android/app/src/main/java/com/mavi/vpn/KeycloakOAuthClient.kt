package com.mavi.vpn

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.util.concurrent.TimeUnit
import java.util.Base64 as JavaBase64

/** Keycloak token endpoint, UserInfo, response parsing, and JWT expiry helpers. */
internal object KeycloakOAuthClient {
    // Real token responses (access + refresh + optional id token, all JWTs) are a
    // few KB; this only guards against a compromised/MITMed Keycloak instance
    // streaming an unbounded body into memory. peekBody truncates rather than
    // reading past the cap, so an oversized body just fails JSON parsing below.
    private const val MAX_TOKEN_RESPONSE_BYTES = 256L * 1024

    private val httpClient: OkHttpClient by lazy {
        OkHttpClient
            .Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .writeTimeout(15, TimeUnit.SECONDS)
            .build()
    }

    fun isAccessTokenUsable(
        token: String,
        skewSeconds: Long,
    ): Boolean {
        if (token.isBlank()) {
            return false
        }

        val exp = accessTokenExpiresAt(token) ?: return false
        val now = System.currentTimeMillis() / 1000L
        return now + skewSeconds < exp
    }

    fun accessTokenExpiresAt(token: String): Long? {
        if (token.isBlank()) {
            return null
        }

        return try {
            val payload = parseJwtPayload(token) ?: return null
            val exp = payload.optLong("exp", -1L)
            exp.takeIf { it > 0L }
        } catch (_: Exception) {
            null
        }
    }

    fun parseTokenResponse(
        body: String,
        fallbackRefreshToken: String? = null,
    ): OAuthTokens? {
        return try {
            val json = JSONObject(body)
            val accessToken = json.optString("access_token", "")
            if (accessToken.isBlank()) {
                return null
            }

            val responseRefreshToken = json.optString("refresh_token", "")
            val refreshToken =
                if (responseRefreshToken.isNotBlank()) {
                    responseRefreshToken
                } else {
                    fallbackRefreshToken.orEmpty()
                }

            if (refreshToken.isBlank()) {
                return null
            }

            OAuthTokens(accessToken, refreshToken)
        } catch (_: Exception) {
            null
        }
    }

    suspend fun isAccessTokenAcceptedByKeycloak(
        token: String,
        kcUrl: String,
        realm: String,
    ): Boolean? =
        withContext(Dispatchers.IO) {
            if (token.isBlank() || kcUrl.isBlank() || realm.isBlank()) {
                return@withContext null
            }

            val keycloakBaseUrl =
                OAuthConfiguration.validatedKeycloakBaseUrl(kcUrl) ?: return@withContext null
            val userInfoUrl = "$keycloakBaseUrl/realms/$realm/protocol/openid-connect/userinfo"
            val request =
                Request
                    .Builder()
                    .url(userInfoUrl)
                    .header("Authorization", "Bearer $token")
                    .get()
                    .build()

            try {
                httpClient.newCall(request).execute().use { response ->
                    when {
                        response.isSuccessful -> true
                        response.code == 401 || response.code == 403 -> false
                        else -> {
                            Log.w("OAuthHelper", "UserInfo token validation returned HTTP ${response.code}")
                            null
                        }
                    }
                }
            } catch (e: Exception) {
                Log.w("OAuthHelper", "UserInfo token validation failed: ${e.message}")
                null
            }
        }

    fun exchangeAuthorizationCode(
        keycloakBaseUrl: String,
        realm: String,
        clientId: String,
        code: String,
        redirectUri: String,
        verifier: String,
    ): OAuthTokens? {
        val tokenUrl = "$keycloakBaseUrl/realms/$realm/protocol/openid-connect/token"
        val formBody =
            FormBody
                .Builder()
                .add("grant_type", "authorization_code")
                .add("client_id", clientId)
                .add("code", code)
                .add("redirect_uri", redirectUri)
                .add("code_verifier", verifier)
                .build()
        val request = Request.Builder().url(tokenUrl).post(formBody).build()

        return try {
            httpClient.newCall(request).execute().use { response ->
                val body = response.peekBody(MAX_TOKEN_RESPONSE_BYTES).string()
                if (response.isSuccessful) {
                    val tokens = parseTokenResponse(body)
                    if (tokens == null) {
                        Log.e("OAuthHelper", "Token response missing 'access_token' or 'refresh_token' field")
                    }
                    tokens
                } else {
                    Log.e("OAuthHelper", "Token exchange failed with HTTP ${response.code}; response body redacted")
                    null
                }
            }
        } catch (e: Exception) {
            Log.e("OAuthHelper", "Token exchange exception: ${e.message}")
            null
        }
    }

    suspend fun refreshToken(
        refreshToken: String,
        kcUrl: String,
        realm: String,
        clientId: String,
    ): RefreshResult =
        withContext(Dispatchers.IO) {
            if (refreshToken.isBlank()) return@withContext RefreshResult.Error("No refresh token available")

            val keycloakBaseUrl =
                OAuthConfiguration.validatedKeycloakBaseUrl(kcUrl)
                    ?: return@withContext RefreshResult.Error("Invalid Keycloak URL")
            val tokenUrl = "$keycloakBaseUrl/realms/$realm/protocol/openid-connect/token"

            val formBody =
                FormBody
                    .Builder()
                    .add("grant_type", "refresh_token")
                    .add("client_id", clientId)
                    .add("refresh_token", refreshToken)
                    .build()

            val request = Request.Builder().url(tokenUrl).post(formBody).build()

            try {
                httpClient.newCall(request).execute().use { response ->
                    val body = response.peekBody(MAX_TOKEN_RESPONSE_BYTES).string()
                    if (response.isSuccessful) {
                        val tokens = parseTokenResponse(body, fallbackRefreshToken = refreshToken)
                        if (tokens == null) {
                            Log.e("OAuthHelper", "Refresh response missing access token")
                            return@withContext RefreshResult.NetworkError("Invalid refresh response from Keycloak")
                        }
                        return@withContext RefreshResult.Success(tokens)
                    }
                    Log.e("OAuthHelper", "Refresh token request failed with HTTP ${response.code}; response body redacted")
                    return@withContext classifyRefreshHttpFailure(response.code, body)
                }
            } catch (e: java.io.IOException) {
                Log.w("OAuthHelper", "Refresh token IO exception (Offline?): ${e.message}")
                return@withContext RefreshResult.NetworkError(e.message ?: "Offline or network timeout")
            } catch (e: Exception) {
                Log.e("OAuthHelper", "Refresh token unknown exception: ${e.message}")
                return@withContext RefreshResult.Error(e.message ?: "Unknown exception during refresh")
            }
        }

    fun classifyRefreshHttpFailure(
        statusCode: Int,
        body: String,
    ): RefreshResult {
        val oauthError = runCatching { JSONObject(body).optString("error") }.getOrNull()
        val terminal =
            statusCode in 400..499 &&
                statusCode !in setOf(408, 425, 429) &&
                oauthError == "invalid_grant"
        return if (terminal) {
            RefreshResult.Error("Refresh token rejected by server (HTTP $statusCode, invalid_grant)")
        } else {
            RefreshResult.NetworkError("Temporary or ambiguous refresh failure (HTTP $statusCode)")
        }
    }

    private fun parseJwtPayload(token: String): JSONObject? {
        val parts = token.split(".")
        if (parts.size < 2) {
            return null
        }

        val payload = parts[1].padEnd((parts[1].length + 3) / 4 * 4, '=')
        val decoded = JavaBase64.getUrlDecoder().decode(payload)
        return JSONObject(String(decoded, Charsets.UTF_8))
    }
}
