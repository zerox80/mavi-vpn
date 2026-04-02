package com.mavi.vpn.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.mavi.vpn.MaviVpnService
import com.mavi.vpn.OAuthHelper
import com.mavi.vpn.data.PrefsManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class VpnViewModel(application: Application) : AndroidViewModel(application) {
    private val prefs = PrefsManager(application)

    // UI State
    var serverIp = MutableStateFlow(prefs.savedIp)
    var serverPort = MutableStateFlow(prefs.savedPort)
    var authToken = MutableStateFlow(prefs.savedToken)
    var certPin = MutableStateFlow(prefs.savedPin)

    // Keycloak state
    var useKeycloak = MutableStateFlow(prefs.savedUseKeycloak)
    var kcUrl = MutableStateFlow(prefs.savedKcUrl)
    var kcRealm = MutableStateFlow(prefs.savedKcRealm)
    var kcClientId = MutableStateFlow(prefs.savedKcClientId)

    // Settings state
    var splitMode = MutableStateFlow(prefs.savedSplitMode)
    var splitPackages = MutableStateFlow(prefs.savedSplitPackages)
    var censorshipResistant = MutableStateFlow(prefs.savedCensorshipResistant)

    private val _errorMessage = MutableStateFlow("")
    val errorMessage: StateFlow<String> = _errorMessage.asStateFlow()

    val isConnected = MaviVpnService.isConnected

    init {
        // We only clear out token entirely if the token is completely
        // unusable and refresh fails, but for the viewModel startup,
        // we can just leave it. If it fails to refresh during connection,
        // MaviVpnService handles the clearing.
    }

    fun updateErrorMessage(message: String) {
        _errorMessage.value = message
    }

    fun clearAuthToken() {
        authToken.value = ""
        prefs.savedToken = ""
        prefs.savedRefreshToken = ""
    }

    fun saveServerDetails() {
        prefs.savedIp = serverIp.value
        prefs.savedPort = serverPort.value
        prefs.savedToken = authToken.value
        prefs.savedPin = certPin.value
    }

    fun saveKeycloakDetails() {
        prefs.savedKcUrl = kcUrl.value
        prefs.savedKcRealm = kcRealm.value
        prefs.savedKcClientId = kcClientId.value
        prefs.savedUseKeycloak = useKeycloak.value
    }

    fun saveSettings(mode: String, packages: String, crMode: Boolean) {
        splitMode.value = mode
        splitPackages.value = packages
        censorshipResistant.value = crMode
        
        prefs.savedSplitMode = mode
        prefs.savedSplitPackages = packages
        prefs.savedCensorshipResistant = crMode
    }
}
