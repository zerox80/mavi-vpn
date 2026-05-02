package com.mavi.vpn

import android.content.Context
import android.net.Uri
import android.util.Base64
import android.util.Log
import androidx.browser.customtabs.CustomTabsIntent
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64 as JavaBase64
import java.util.concurrent.TimeUnit

data class OAuthTokens(val accessToken: String, val refreshToken: String)

sealed class RefreshResult {
    data class Success(val tokens: OAuthTokens) : RefreshResult()
    data class Error(val message: String) : RefreshResult()
    data class NetworkError(val error: String) : RefreshResult()
}

object OAuthHelper {
    // @Volatile ensures cross-thread visibility; synchronized(OAuthHelper) ensures atomicity
    // of combined read+clear operations to prevent CSRF state corruption under parallel flows.
    @Volatile private var codeVerifier: String? = null
    @Volatile private var oauthState: String? = null

    private val httpClient: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .writeTimeout(15, TimeUnit.SECONDS)
            .build()
    }

    private fun generateRandomBase64(): String {
        val sr = SecureRandom()
        val bytes = ByteArray(32)
        sr.nextBytes(bytes)
        return Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }

    fun generatePKCE(): String {
        val verifier = generateRandomBase64()
        codeVerifier = verifier

        val bytes = verifier.toByteArray(Charsets.US_ASCII)
        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest(bytes)
        return Base64.encodeToString(digest, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }

    fun startAuth(context: Context, kcUrl: String, realm: String, clientId: String) {
        val challenge: String
        val state: String
        // Generate PKCE challenge and state atomically so a concurrent startAuth() call
        // cannot overwrite codeVerifier between generatePKCE() and the oauthState assignment.
        synchronized(OAuthHelper) {
            challenge = generatePKCE()
            state = generateRandomBase64()
            oauthState = state
        }
        val redirectUri = "mavivpn://oauth"

        val url = Uri.parse(kcUrl).buildUpon()
            .appendPath("realms")
            .appendPath(realm)
            .appendPath("protocol")
            .appendPath("openid-connect")
            .appendPath("auth")
            .appendQueryParameter("response_type", "code")
            .appendQueryParameter("client_id", clientId)
            .appendQueryParameter("redirect_uri", redirectUri)
            .appendQueryParameter("scope", "openid profile email")
            .appendQueryParameter("code_challenge", challenge)
            .appendQueryParameter("code_challenge_method", "S256")
            .appendQueryParameter("state", state)
            .appendQueryParameter("prompt", "login") // FORCES Keycloak to ignore cookies and show login!
            .build()

        val customTabsIntent = CustomTabsIntent.Builder().build()
        customTabsIntent.launchUrl(context, url)
    }

    fun isAccessTokenUsable(token: String, skewSeconds: Long = 60): Boolean {
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

    fun parseTokenResponse(body: String, fallbackRefreshToken: String? = null): OAuthTokens? {
        return try {
            val json = JSONObject(body)
            val accessToken = json.optString("access_token", "")
            if (accessToken.isBlank()) {
                return null
            }

            val responseRefreshToken = json.optString("refresh_token", "")
            val refreshToken = if (responseRefreshToken.isNotBlank()) {
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
        realm: String
    ): Boolean? = withContext(Dispatchers.IO) {
        if (token.isBlank() || kcUrl.isBlank() || realm.isBlank()) {
            return@withContext null
        }

        val userInfoUrl = "${kcUrl.trimEnd('/')}/realms/$realm/protocol/openid-connect/userinfo"
        val request = Request.Builder()
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

    suspend fun exchangeCodeForToken(code: String, returnedState: String?, kcUrl: String, realm: String, clientId: String): OAuthTokens? = withContext(Dispatchers.IO) {
        // Read and clear state atomically to prevent a second concurrent call from
        // consuming the same verifier (replay) or seeing a partially-overwritten state.
        val expectedState: String?
        val verifier: String?
        synchronized(OAuthHelper) {
            expectedState = oauthState
            verifier = codeVerifier
            oauthState = null
            codeVerifier = null
        }

        if (expectedState == null || returnedState != expectedState) {
            Log.e("OAuthHelper", "OAuth state mismatch — possible CSRF. Aborting token exchange.")
            return@withContext null
        }

        verifier ?: return@withContext null

        val redirectUri = "mavivpn://oauth"
        val tokenUrl = "$kcUrl/realms/$realm/protocol/openid-connect/token"

        val formBody = FormBody.Builder()
            .add("grant_type", "authorization_code")
            .add("client_id", clientId)
            .add("code", code)
            .add("redirect_uri", redirectUri)
            .add("code_verifier", verifier)
            .build()

        val request = Request.Builder()
            .url(tokenUrl)
            .post(formBody)
            .build()

        try {
            val response = httpClient.newCall(request).execute()
            val body = response.body.string()
            if (response.isSuccessful) {
                val tokens = parseTokenResponse(body)
                if (tokens == null) {
                    Log.e("OAuthHelper", "Token response missing 'access_token' or 'refresh_token' field")
                    return@withContext null
                }
                return@withContext tokens
            }
            Log.e("OAuthHelper", "Token exchange failed with HTTP ${response.code}: $body")
            null
        } catch (e: Exception) {
            Log.e("OAuthHelper", "Token exchange exception: ${e.message}")
            null
        }
    }

    suspend fun refreshToken(refreshToken: String, kcUrl: String, realm: String, clientId: String): RefreshResult = withContext(Dispatchers.IO) {
        if (refreshToken.isBlank()) return@withContext RefreshResult.Error("No refresh token available")

        val tokenUrl = "$kcUrl/realms/$realm/protocol/openid-connect/token"

        val formBody = FormBody.Builder()
            .add("grant_type", "refresh_token")
            .add("client_id", clientId)
            .add("refresh_token", refreshToken)
            .build()

        val request = Request.Builder()
            .url(tokenUrl)
            .post(formBody)
            .build()

        try {
            val response = httpClient.newCall(request).execute()
            val body = response.body.string()
            if (response.isSuccessful) {
                val tokens = parseTokenResponse(body, fallbackRefreshToken = refreshToken)
                if (tokens == null) {
                    Log.e("OAuthHelper", "Refresh response missing access token")
                    return@withContext RefreshResult.Error("Invalid JSON from Keycloak")
                }
                return@withContext RefreshResult.Success(tokens)
            }
            if (response.code >= 500) {
                 return@withContext RefreshResult.NetworkError("Server Error (HTTP ${response.code})")
            }
            Log.e("OAuthHelper", "Refresh token request failed with HTTP ${response.code}: $body")
            return@withContext RefreshResult.Error("Refresh rejected by server (HTTP ${response.code})")
        } catch (e: java.io.IOException) {
            Log.w("OAuthHelper", "Refresh token IO exception (Offline?): ${e.message}")
            return@withContext RefreshResult.NetworkError(e.message ?: "Offline or network timeout")
        } catch (e: Exception) {
            Log.e("OAuthHelper", "Refresh token unknown exception: ${e.message}")
            return@withContext RefreshResult.Error(e.message ?: "Unknown exception during refresh")
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
