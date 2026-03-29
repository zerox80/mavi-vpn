package com.mavi.vpn

import android.content.Context
import android.net.Uri
import android.util.Base64
import android.util.Log
import androidx.browser.customtabs.CustomTabsIntent
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit
import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

object OAuthHelper {
    @Volatile private var codeVerifier: String? = null
    private val httpClient: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .writeTimeout(15, TimeUnit.SECONDS)
            .build()
    }
    
    fun generatePKCE(): String {
        val sr = SecureRandom()
        val code = ByteArray(32)
        sr.nextBytes(code)
        val verifier = Base64.encodeToString(code, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
        synchronized(OAuthHelper) { codeVerifier = verifier }
        
        val bytes = verifier.toByteArray(Charsets.US_ASCII)
        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest(bytes)
        return Base64.encodeToString(digest, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
    }

    fun startAuth(context: Context, kcUrl: String, realm: String, clientId: String) {
        val challenge = generatePKCE()
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
            .build()
            
        val customTabsIntent = CustomTabsIntent.Builder().build()
        customTabsIntent.launchUrl(context, url)
    }

    suspend fun exchangeCodeForToken(code: String, kcUrl: String, realm: String, clientId: String): String? = withContext(Dispatchers.IO) {
        val verifier = synchronized(OAuthHelper) {
            val v = codeVerifier
            codeVerifier = null
            v
        } ?: return@withContext null
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
            httpClient.newCall(request).execute().use { response ->
                val body = response.body?.string() ?: return@withContext null
                if (response.isSuccessful) JSONObject(body).getString("access_token") else null
            }
        } catch (e: Exception) {
            Log.e("OAuthHelper", "Token exchange failed", e)
            null
        }
    }
}
