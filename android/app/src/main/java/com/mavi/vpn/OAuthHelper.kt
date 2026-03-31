package com.mavi.vpn

import android.content.Context
import android.net.Uri
import android.util.Base64
import androidx.browser.customtabs.CustomTabsIntent
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

object OAuthHelper {
    private var codeVerifier: String? = null
    private var oauthState: String? = null

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
        val challenge = generatePKCE()
        val state = generateRandomBase64()
        oauthState = state
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

    suspend fun exchangeCodeForToken(code: String, returnedState: String?, kcUrl: String, realm: String, clientId: String): String? = withContext(Dispatchers.IO) {
        val expectedState = oauthState
        if (expectedState == null || returnedState != expectedState) {
            android.util.Log.e("OAuthHelper", "OAuth state mismatch — possible CSRF. Aborting token exchange.")
            return@withContext null
        }
        oauthState = null

        val verifier = codeVerifier ?: return@withContext null
        val redirectUri = "mavivpn://oauth"
        
        val tokenUrl = "$kcUrl/realms/$realm/protocol/openid-connect/token"
        
        val client = OkHttpClient()
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
            val response = client.newCall(request).execute()
            val body = response.body?.string() ?: return@withContext null
            if (response.isSuccessful) {
                val json = JSONObject(body)
                return@withContext json.getString("access_token")
            }
            null
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }
}
