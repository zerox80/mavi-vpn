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
    fun oauthRedirectUri(): String = BuildConfig.OAUTH_REDIRECT_URI

    fun validateAuthConfiguration(kcUrl: String): String? = validateKeycloakUrl(kcUrl) ?: validateOAuthRedirectUri()

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

    private fun generatePKCE(verifier: String): String {
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

        val authority = KeycloakAuthority.from(keycloakBaseUrl, realm, clientId) ?: return false
        val verifier = generateRandomBase64()
        val challenge = generatePKCE(verifier)
        val state = generateRandomBase64()
        val prefs = PrefsManager(context.applicationContext)
        if (!prefs.keycloak.beginLogin(authority, state, verifier)) return false

        val url =
            Uri
                .parse(authority.baseUrl)
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
    ): OAuthTokens? =
        withContext(Dispatchers.IO) {
            val prefs = PrefsManager(context.applicationContext)
            val pending = prefs.keycloak.consumeLogin(returnedState) ?: return@withContext null
            val authority = pending.snapshot.authority ?: return@withContext null

            val redirectUri = oauthRedirectUri()
            val redirectError = validateOAuthRedirectUri(redirectUri)
            if (redirectError != null) {
                Log.e("OAuthHelper", redirectError)
                return@withContext null
            }
            val tokens =
                KeycloakOAuthClient.exchangeAuthorizationCode(
                    keycloakBaseUrl = authority.baseUrl,
                    realm = authority.realm,
                    clientId = authority.clientId,
                    code = code,
                    redirectUri = redirectUri,
                    verifier = pending.verifier,
                ) ?: return@withContext null
            if (prefs.keycloak.replace(pending.snapshot, tokens, invalid = false)) tokens else null
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
