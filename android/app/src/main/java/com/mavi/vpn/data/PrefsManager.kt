package com.mavi.vpn.data

import android.content.Context
import android.content.SharedPreferences

class PrefsManager(context: Context) {
    private val prefs: SharedPreferences = context.getSharedPreferences("MaviVPN", Context.MODE_PRIVATE)

    var savedIp: String
        get() = prefs.getString("saved_ip", "") ?: ""
        set(value) = prefs.edit().putString("saved_ip", value).apply()

    var savedPort: String
        get() = prefs.getString("saved_port", "4433") ?: "4433"
        set(value) = prefs.edit().putString("saved_port", value).apply()

    var savedToken: String
        get() = prefs.getString("saved_token", "") ?: ""
        set(value) = prefs.edit().putString("saved_token", value).apply()

    var savedRefreshToken: String
        get() = prefs.getString("saved_refresh_token", "") ?: ""
        set(value) = prefs.edit().putString("saved_refresh_token", value).apply()

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

    var savedEchConfig: String
        get() = prefs.getString("saved_ech_config", "") ?: ""
        set(value) = prefs.edit().putString("saved_ech_config", value).apply()

    var savedUseKeycloak: Boolean
        get() = prefs.getBoolean("saved_use_keycloak", false)
        set(value) = prefs.edit().putBoolean("saved_use_keycloak", value).apply()

    var savedKcUrl: String
        get() = prefs.getString("saved_kc_url", "") ?: ""
        set(value) = prefs.edit().putString("saved_kc_url", value).apply()

    var savedKcRealm: String
        get() = prefs.getString("saved_kc_realm", "mavi-vpn") ?: "mavi-vpn"
        set(value) = prefs.edit().putString("saved_kc_realm", value).apply()

    var savedKcClientId: String
        get() = prefs.getString("saved_kc_client_id", "mavi-client") ?: "mavi-client"
        set(value) = prefs.edit().putString("saved_kc_client_id", value).apply()

    var savedPresharedKey: String
        get() = prefs.getString("saved_preshared_key", "") ?: ""
        set(value) = prefs.edit().putString("saved_preshared_key", value).apply()

    var tempSplitMode: String
        get() = prefs.getString("temp_split_mode", "exclude") ?: "exclude"
        set(value) = prefs.edit().putString("temp_split_mode", value).apply()

    var tempSplitPackages: String
        get() = prefs.getString("temp_split_packages", "") ?: ""
        set(value) = prefs.edit().putString("temp_split_packages", value).apply()
}
