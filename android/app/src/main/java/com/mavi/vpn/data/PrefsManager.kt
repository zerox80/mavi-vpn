package com.mavi.vpn.data

import android.content.Context
import android.content.SharedPreferences

private const val DEFAULT_VPN_MTU = 0
private const val MIN_VPN_MTU = 1280
private const val MAX_VPN_MTU = 1360

internal fun sanitizeVpnMtu(value: Int): Int = if (value == DEFAULT_VPN_MTU || value in MIN_VPN_MTU..MAX_VPN_MTU) value else DEFAULT_VPN_MTU

class PrefsManager(
    context: Context,
) {
    private val prefs: SharedPreferences = context.getSharedPreferences("MaviVPN", Context.MODE_PRIVATE)
    private val secrets = SecureStringPreferences(prefs)
    internal val keycloak = KeycloakSessionPreferences(prefs, secrets)

    var savedIp: String
        get() = prefs.getString("saved_ip", "") ?: ""
        set(value) = prefs.edit().putString("saved_ip", value).apply()

    var savedPort: String
        get() = prefs.getString("saved_port", "10443") ?: "10443"
        set(value) = prefs.edit().putString("saved_port", value).apply()

    // Read-only legacy values, used only for preshared-key migration.
    val savedToken: String
        get() = secrets.getString("saved_token")

    val savedRefreshToken: String
        get() = secrets.getString("saved_refresh_token")

    var savedKeycloakSessionInvalid: Boolean
        get() = prefs.getBoolean("saved_keycloak_session_invalid", false)
        set(value) = prefs.edit().putBoolean("saved_keycloak_session_invalid", value).apply()

    var savedPin: String
        get() = prefs.getString("saved_pin", "") ?: ""
        set(value) = prefs.edit().putString("saved_pin", value).apply()

    var savedSplitMode: String
        get() = prefs.getString("saved_split_mode", "exclude") ?: "exclude"
        set(value) = prefs.edit().putString("saved_split_mode", value).apply()

    var savedSplitPackages: String
        get() = prefs.getString("saved_split_packages", "") ?: ""
        set(value) = prefs.edit().putString("saved_split_packages", value).apply()

    var savedCensorshipResistant: Boolean
        get() = prefs.getBoolean("saved_censorship_resistant", false)
        set(value) = prefs.edit().putBoolean("saved_censorship_resistant", value).apply()

    var savedHttp3Framing: Boolean
        get() = prefs.getBoolean("saved_http3_framing", false)
        set(value) = prefs.edit().putBoolean("saved_http3_framing", value).apply()

    var savedHttp2Framing: Boolean
        get() = prefs.getBoolean("saved_http2_framing", false)
        set(value) = prefs.edit().putBoolean("saved_http2_framing", value).apply()

    var savedEchConfig: String
        get() = prefs.getString("saved_ech_config", "") ?: ""
        set(value) = prefs.edit().putString("saved_ech_config", value).apply()

    var savedUseKeycloak: Boolean
        get() = prefs.getBoolean("saved_use_keycloak", false)
        set(value) = prefs.edit().putBoolean("saved_use_keycloak", value).apply()

    val savedKcUrl: String
        get() = prefs.getString("saved_kc_url", "") ?: ""

    val savedKcRealm: String
        get() = prefs.getString("saved_kc_realm", "mavi-vpn") ?: "mavi-vpn"

    val savedKcClientId: String
        get() = prefs.getString("saved_kc_client_id", "mavi-client") ?: "mavi-client"

    var savedPresharedKey: String
        get() = secrets.getString("saved_preshared_key")
        set(value) = secrets.setString("saved_preshared_key", value)

    var savedVpnMtu: Int
        get() = sanitizeVpnMtu(prefs.getInt("saved_vpn_mtu", DEFAULT_VPN_MTU))
        set(value) = prefs.edit().putInt("saved_vpn_mtu", sanitizeVpnMtu(value)).apply()

    var tempSplitMode: String
        get() = prefs.getString("temp_split_mode", "exclude") ?: "exclude"
        set(value) = prefs.edit().putString("temp_split_mode", value).apply()

    var tempSplitPackages: String
        get() = prefs.getString("temp_split_packages", "") ?: ""
        set(value) = prefs.edit().putString("temp_split_packages", value).apply()
}
