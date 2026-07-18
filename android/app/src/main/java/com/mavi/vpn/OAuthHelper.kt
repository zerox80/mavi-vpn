package com.mavi.vpn

import android.content.Context
import android.net.Uri
import android.util.Base64
import android.util.Log
import androidx.browser.customtabs.CustomTabsIntent
import com.mavi.vpn.data.PrefsManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Public OAuth facade and owner of the short-lived PKCE/browser-flow state.
 * URL policy lives in [OAuthConfiguration], while token parsing and Keycloak
 * HTTP calls live in [KeycloakOAuthClient].
 */
object OAuthHelper {
    // @Volatile ensures cross-thread visibility; synchronized(OAuthHelper) ensures atomicity
    // of combined read+clear operations to prevent CSRF state corruption under parallel flows.
    @Volatile
    private var codeVerifier: String? = null

    @Volatile
    private var oauthState: String? = null

    fun oauthRedirectUri(): String = BuildConfig.OAUTH_REDIRECT_URI

    fun validateAuthConfiguration(kcUrl: String): String? =
        validateKeycloakUrl(kcUrl) ?: validateOAuthRedirectUri()

    fun normalizeKeycloakBaseUrl(kcUrl: String): String = OAuthConfiguration.normalizeKeycloakBaseUrl(kcUrl)

    fun validateKeycloakUrl(kcUrl: String): String? = OAuthConfiguration.validateKeycloakUrl(kcUrl)

    fun validateOAuthRedirectUri(
        redirectUri: String = oauthRedirectUri(),
        allowCustomScheme: Boolean = BuildConfig.DEBUG,
    ): String? = OAuthConfiguration.validateOAuthRedirectUri(redirectUri, allowCustomScheme)

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
        val keycloakBaseUrl = OAuthConfiguration.validatedKeycloakBaseUrl(kcUrl) ?: return false
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
    ): Boolean = KeycloakOAuthClient.isAccessTokenUsable(token, skewSeconds)

    fun accessTokenExpiresAt(token: String): Long? = KeycloakOAuthClient.accessTokenExpiresAt(token)

    fun parseTokenResponse(
        body: String,
        fallbackRefreshToken: String? = null,
    ): OAuthTokens? = KeycloakOAuthClient.parseTokenResponse(body, fallbackRefreshToken)

    suspend fun isAccessTokenAcceptedByKeycloak(
        token: String,
        kcUrl: String,
        realm: String,
    ): Boolean? = KeycloakOAuthClient.isAccessTokenAcceptedByKeycloak(token, kcUrl, realm)

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
            val keycloakBaseUrl =
                OAuthConfiguration.validatedKeycloakBaseUrl(kcUrl) ?: return@withContext null

            KeycloakOAuthClient.exchangeAuthorizationCode(
                keycloakBaseUrl = keycloakBaseUrl,
                realm = realm,
                clientId = clientId,
                code = code,
                redirectUri = redirectUri,
                verifier = verifier,
            )
        }

    suspend fun refreshToken(
        refreshToken: String,
        kcUrl: String,
        realm: String,
        clientId: String,
    ): RefreshResult = KeycloakOAuthClient.refreshToken(refreshToken, kcUrl, realm, clientId)

    internal fun classifyRefreshHttpFailure(
        statusCode: Int,
        body: String,
    ): RefreshResult = KeycloakOAuthClient.classifyRefreshHttpFailure(statusCode, body)
}
