package com.mavi.vpn

import android.content.Context
import android.net.Uri
import android.util.Base64
import android.util.Log
import androidx.browser.customtabs.CustomTabsIntent
import com.mavi.vpn.data.PrefsManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.net.URI
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.TimeUnit
import java.util.Base64 as JavaBase64

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

object OAuthHelper {
    // @Volatile ensures cross-thread visibility; synchronized(OAuthHelper) ensures atomicity
    // of combined read+clear operations to prevent CSRF state corruption under parallel flows.
    @Volatile
    private var codeVerifier: String? = null

    @Volatile
    private var oauthState: String? = null

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

    fun oauthRedirectUri(): String = BuildConfig.OAUTH_REDIRECT_URI

    fun validateAuthConfiguration(kcUrl: String): String? = validateKeycloakUrl(kcUrl) ?: validateOAuthRedirectUri()

    fun normalizeKeycloakBaseUrl(kcUrl: String): String = kcUrl.trim().trimEnd('/')

    fun validateKeycloakUrl(kcUrl: String): String? {
        val normalized = normalizeKeycloakBaseUrl(kcUrl)
        if (normalized.startsWith("https://")) {
            return null
        }
        if (normalized.startsWith("http://")) {
            val authority =
                normalized
                    .removePrefix("http://")
                    .split('/', '?', '#')
                    .firstOrNull()
                    .orEmpty()
            if (authority.contains('@')) {
                return "Keycloak URL must not contain userinfo; plain HTTP is only allowed for localhost"
            }
            val host =
                if (authority.startsWith("[")) {
                    authority.removePrefix("[").substringBefore(']')
                } else {
                    authority.substringBeforeLast(':', authority)
                }
            if (host == "localhost" || host == "127.0.0.1" || host == "::1") {
                return null
            }
            return "Keycloak URL must use https://; plain HTTP is only allowed for localhost"
        }
        return "Keycloak URL must start with https://"
    }

    fun validateOAuthRedirectUri(
        redirectUri: String = oauthRedirectUri(),
        allowCustomScheme: Boolean = BuildConfig.DEBUG,
    ): String? {
        val normalized = redirectUri.trim()
        val uri =
            try {
                URI(normalized)
            } catch (_: Exception) {
                return "OAuth redirect URI is invalid"
            }

        val scheme = uri.scheme?.lowercase()
        val hasHost = !uri.host.isNullOrBlank()
        val hasPath = !uri.rawPath.isNullOrBlank()
        val hasNoExtras = uri.rawQuery == null && uri.rawFragment == null

        if (scheme == "https" && hasHost && hasPath && hasNoExtras) {
            return null
        }

        if (
            allowCustomScheme &&
            isReverseDnsCustomScheme(scheme) &&
            hasHost &&
            hasPath &&
            hasNoExtras
        ) {
            return null
        }

        return if (allowCustomScheme) {
            "OAuth redirect URI must be https:// with host/path, " +
                "or a reverse-DNS custom scheme for debug builds"
        } else {
            "OAuth redirect URI must be a verified https:// App Link with host/path"
        }
    }

    private fun isReverseDnsCustomScheme(scheme: String?): Boolean =
        scheme != null &&
            scheme != "http" &&
            scheme != "https" &&
            "." in scheme

    private fun validatedKeycloakBaseUrl(kcUrl: String): String? {
        val error = validateKeycloakUrl(kcUrl)
        if (error != null) {
            Log.e("OAuthHelper", error)
            return null
        }
        return normalizeKeycloakBaseUrl(kcUrl)
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

    fun startAuth(
        context: Context,
        kcUrl: String,
        realm: String,
        clientId: String,
    ): Boolean {
        val keycloakBaseUrl = validatedKeycloakBaseUrl(kcUrl) ?: return false
        val redirectUri = oauthRedirectUri()
        val redirectError = validateOAuthRedirectUri(redirectUri)
        if (redirectError != null) {
            Log.e("OAuthHelper", redirectError)
            return false
        }

        val challenge: String
        val state: String
        val verifier: String
        // Generate PKCE challenge and state atomically so a concurrent startAuth() call
        // cannot overwrite codeVerifier between generatePKCE() and the oauthState assignment.
        synchronized(OAuthHelper) {
            challenge = generatePKCE()
            state = generateRandomBase64()
            verifier = codeVerifier.orEmpty()
            oauthState = state
        }
        PrefsManager(context.applicationContext).also { prefs ->
            prefs.savedOauthCodeVerifier = verifier
            prefs.savedOauthState = state
        }

        val url =
            Uri
                .parse(keycloakBaseUrl)
                .buildUpon()
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
                // Allow Keycloak to reuse an existing SSO cookie so the user does not
                // have to type credentials on every connect. A missing/invalid session
                // is handled by the caller, which falls back to interactive login.
                .build()

        return try {
            val customTabsIntent = CustomTabsIntent.Builder().build()
            customTabsIntent.launchUrl(context, url)
            true
        } catch (e: Exception) {
            Log.e("OAuthHelper", "Could not launch Keycloak login: ${e.message}")
            false
        }
    }

    fun isOAuthRedirect(data: Uri): Boolean {
        val expected = Uri.parse(oauthRedirectUri())
        return data.scheme == expected.scheme &&
            data.host == expected.host &&
            data.path == expected.path
    }

    fun isAccessTokenUsable(
        token: String,
        skewSeconds: Long = 60,
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

            val keycloakBaseUrl = validatedKeycloakBaseUrl(kcUrl) ?: return@withContext null
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

    suspend fun exchangeCodeForToken(
        context: Context,
        code: String,
        returnedState: String?,
        kcUrl: String,
        realm: String,
        clientId: String,
    ): OAuthTokens? =
        withContext(Dispatchers.IO) {
            // Read and clear state atomically to prevent a second concurrent call from
            // consuming the same verifier (replay) or seeing a partially-overwritten state.
            val expectedState: String?
            val verifier: String?
            synchronized(OAuthHelper) {
                val prefs = PrefsManager(context.applicationContext)
                val persistedState = prefs.savedOauthState
                val persistedVerifier = prefs.savedOauthCodeVerifier
                expectedState = if (persistedState.isNotBlank()) persistedState else oauthState
                verifier = if (persistedVerifier.isNotBlank()) persistedVerifier else codeVerifier
                prefs.savedOauthState = ""
                prefs.savedOauthCodeVerifier = ""
                oauthState = null
                codeVerifier = null
            }

            val stateMatches =
                expectedState != null &&
                    returnedState != null &&
                    MessageDigest.isEqual(
                        returnedState.toByteArray(Charsets.UTF_8),
                        expectedState.toByteArray(Charsets.UTF_8),
                    )
            if (!stateMatches) {
                Log.e("OAuthHelper", "OAuth state mismatch; possible CSRF. Aborting token exchange.")
                return@withContext null
            }

            verifier ?: return@withContext null

            val redirectUri = oauthRedirectUri()
            val redirectError = validateOAuthRedirectUri(redirectUri)
            if (redirectError != null) {
                Log.e("OAuthHelper", redirectError)
                return@withContext null
            }
            val keycloakBaseUrl = validatedKeycloakBaseUrl(kcUrl) ?: return@withContext null
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

            val request =
                Request
                    .Builder()
                    .url(tokenUrl)
                    .post(formBody)
                    .build()

            try {
                httpClient.newCall(request).execute().use { response ->
                    val body = response.peekBody(MAX_TOKEN_RESPONSE_BYTES).string()
                    if (response.isSuccessful) {
                        val tokens = parseTokenResponse(body)
                        if (tokens == null) {
                            Log.e("OAuthHelper", "Token response missing 'access_token' or 'refresh_token' field")
                            return@withContext null
                        }
                        return@withContext tokens
                    }
                    Log.e("OAuthHelper", "Token exchange failed with HTTP ${response.code}; response body redacted")
                    null
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
                validatedKeycloakBaseUrl(kcUrl)
                    ?: return@withContext RefreshResult.Error("Invalid Keycloak URL")
            val tokenUrl = "$keycloakBaseUrl/realms/$realm/protocol/openid-connect/token"

            val formBody =
                FormBody
                    .Builder()
                    .add("grant_type", "refresh_token")
                    .add("client_id", clientId)
                    .add("refresh_token", refreshToken)
                    .build()

            val request =
                Request
                    .Builder()
                    .url(tokenUrl)
                    .post(formBody)
                    .build()

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

    internal fun classifyRefreshHttpFailure(
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
