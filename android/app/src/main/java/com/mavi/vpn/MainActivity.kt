package com.mavi.vpn

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.lifecycleScope
import com.mavi.vpn.ui.screens.SettingsScreen
import com.mavi.vpn.ui.screens.VpnScreen
import com.mavi.vpn.ui.theme.MaviVpnTheme
import com.mavi.vpn.viewmodel.VpnViewModel
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    private val viewModel: VpnViewModel by viewModels()

    // Set when the user taps Connect with Keycloak enabled: we launch a fresh
    // interactive login first and only start the tunnel once the redirect brings
    // back new tokens. Forces re-authentication on every manual connect instead
    // of silently reusing the stored token.
    private var pendingConnect = false

    private val vpnPrepareLauncher =
        registerForActivityResult(
            ActivityResultContracts.StartActivityForResult(),
        ) { result ->
            if (result.resultCode == Activity.RESULT_OK) {
                val token =
                    if (viewModel.useKeycloak.value) {
                        viewModel.authToken.value
                    } else {
                        viewModel.presharedKey.value
                    }
                startVpnService(
                    viewModel.serverIp.value,
                    viewModel.serverPort.value,
                    token,
                    viewModel.certPin.value,
                    viewModel.splitMode.value,
                    viewModel.splitPackages.value,
                )
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        handleIntent(intent)

        setContent {
            MaviVpnTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background,
                ) {
                    var currentScreen by remember { mutableStateOf("home") }

                    if (currentScreen == "home") {
                        VpnScreen(
                            viewModel = viewModel,
                            onConnect = { ip, port, token, pin ->
                                if (viewModel.useKeycloak.value) {
                                    val authConfigError =
                                        OAuthHelper.validateAuthConfiguration(viewModel.kcUrl.value)
                                    if (authConfigError != null) {
                                        viewModel.updateErrorMessage(authConfigError)
                                    } else {
                                        viewModel.updateErrorMessage("")
                                        viewModel.saveServerDetails()
                                        viewModel.saveKeycloakDetails()
                                        if (
                                            viewModel.hasSavedKeycloakRefreshToken() &&
                                            !viewModel.isSavedKeycloakSessionInvalid()
                                        ) {
                                            // Reuse the stored access token. The service will
                                            // silently refresh it while the tunnel is active.
                                            prepareAndStartVpn(
                                                ip,
                                                port,
                                                viewModel.authToken.value,
                                                pin,
                                                viewModel.splitMode.value,
                                                viewModel.splitPackages.value,
                                            )
                                        } else {
                                            // No usable stored session -> interactive login.
                                            pendingConnect = true
                                            val started =
                                                OAuthHelper.startAuth(
                                                    this@MainActivity,
                                                    viewModel.kcUrl.value,
                                                    viewModel.kcRealm.value,
                                                    viewModel.kcClientId.value,
                                                )
                                            if (!started) {
                                                pendingConnect = false
                                                viewModel.updateErrorMessage(
                                                    "Could not start Keycloak login.",
                                                )
                                            }
                                        }
                                    }
                                } else {
                                    prepareAndStartVpn(
                                        ip,
                                        port,
                                        token,
                                        pin,
                                        viewModel.splitMode.value,
                                        viewModel.splitPackages.value,
                                    )
                                }
                            },
                            onDisconnect = { stopVpn() },
                            onOpenSettings = { currentScreen = "settings" },
                        )
                    } else {
                        SettingsScreen(
                            viewModel = viewModel,
                            onBack = { mode, pkgs, crMode, h3Mode, vpnMtu ->
                                viewModel.saveSettings(mode, pkgs, crMode, h3Mode, vpnMtu)
                                currentScreen = "home"
                            },
                        )
                    }
                }
            }
        }
    }

    private fun prepareAndStartVpn(
        ip: String,
        port: String,
        token: String,
        pin: String,
        splitMode: String,
        splitPackages: String,
    ) {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            // Store details in VM if needed, or rely on them being there
            vpnPrepareLauncher.launch(intent)
        } else {
            startVpnService(ip, port, token, pin, splitMode, splitPackages)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent) {
        val data: Uri? = intent.data
        if (data != null && OAuthHelper.isOAuthRedirect(data)) {
            intent.setData(null)

            val oauthError = data.getQueryParameter("error")
            if (oauthError != null) {
                pendingConnect = false
                val description = data.getQueryParameter("error_description") ?: oauthError
                viewModel.updateErrorMessage("Keycloak login failed: $description")
                return
            }

            val code = data.getQueryParameter("code")
            if (code.isNullOrBlank()) {
                pendingConnect = false
                viewModel.updateErrorMessage(
                    "Keycloak login did not return an authorization code.",
                )
                return
            }

            val returnedState = data.getQueryParameter("state")
            lifecycleScope.launch {
                val tokens =
                    OAuthHelper.exchangeCodeForToken(
                        this@MainActivity,
                        code,
                        returnedState,
                        viewModel.kcUrl.value,
                        viewModel.kcRealm.value,
                        viewModel.kcClientId.value,
                    )
                if (tokens == null) {
                    pendingConnect = false
                    viewModel.updateErrorMessage("Keycloak login failed. Please try again.")
                    return@launch
                }

                viewModel.updateErrorMessage("")
                viewModel.saveOAuthTokens(tokens)
                if (pendingConnect) {
                    // The user tapped Connect: now that a fresh login
                    // succeeded, bring the tunnel up with the new token.
                    pendingConnect = false
                    prepareAndStartVpn(
                        viewModel.serverIp.value,
                        viewModel.serverPort.value,
                        tokens.accessToken,
                        viewModel.certPin.value,
                        viewModel.splitMode.value,
                        viewModel.splitPackages.value,
                    )
                } else {
                    recreate()
                }
            }
        }
    }

    private fun startVpnService(
        ip: String,
        port: String,
        token: String,
        pin: String,
        splitMode: String,
        splitPackages: String,
    ) {
        val intent =
            Intent(this, MaviVpnService::class.java).apply {
                action = "CONNECT"
                putExtra("IP", ip)
                putExtra("PORT", port)
                putExtra("TOKEN", token)
                putExtra("PIN", pin)
                putExtra("SPLIT_MODE", splitMode)
                putExtra("SPLIT_PACKAGES", splitPackages)
            }
        startService(intent)
    }

    private fun stopVpn() {
        val intent = Intent(this, MaviVpnService::class.java)
        intent.action = "STOP"
        startService(intent)
    }

    fun requestBatteryOptimizationIgnore() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val intent = Intent()
            val packageName = packageName
            val pm = getSystemService(POWER_SERVICE) as PowerManager
            if (!pm.isIgnoringBatteryOptimizations(packageName)) {
                intent.action = Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS
                intent.data = Uri.parse("package:$packageName")
                startActivity(intent)
            }
        }
    }
}
