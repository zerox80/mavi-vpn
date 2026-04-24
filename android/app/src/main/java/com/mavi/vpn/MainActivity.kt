package com.mavi.vpn

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.ui.Modifier
import androidx.lifecycle.lifecycleScope
import com.mavi.vpn.ui.screens.VpnScreen
import com.mavi.vpn.ui.screens.SettingsScreen
import com.mavi.vpn.ui.theme.MaviVpnTheme
import com.mavi.vpn.viewmodel.VpnViewModel
import kotlinx.coroutines.launch
import androidx.compose.runtime.*

class MainActivity : ComponentActivity() {

    private val viewModel: VpnViewModel by viewModels()

    private val vpnPrepareLauncher = registerForActivityResult(androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
             startVpnService(
                 viewModel.serverIp.value,
                 viewModel.serverPort.value,
                 viewModel.authToken.value,
                 viewModel.certPin.value,
                 viewModel.splitMode.value,
                 viewModel.splitPackages.value
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
                    color = MaterialTheme.colorScheme.background
                ) {
                    var currentScreen by remember { mutableStateOf("home") }

                    if (currentScreen == "home") {
                        VpnScreen(
                            viewModel = viewModel,
                            onConnect = { ip, port, token, pin -> 
                                prepareAndStartVpn(ip, port, token, pin, viewModel.splitMode.value, viewModel.splitPackages.value) 
                            },
                            onDisconnect = { stopVpn() },
                            onOpenSettings = { currentScreen = "settings" }
                        )
                    } else {
                        SettingsScreen(
                            viewModel = viewModel,
                            onBack = { mode, pkgs, crMode, h3Mode, vpnMtu -> 
                                viewModel.saveSettings(mode, pkgs, crMode, h3Mode, vpnMtu)
                                currentScreen = "home"
                            }
                        )
                    }
                }
            }
        }
    }

    private fun prepareAndStartVpn(ip: String, port: String, token: String, pin: String, splitMode: String, splitPackages: String) {
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
        if (data != null && data.scheme == "mavivpn" && data.host == "oauth") {
            val code = data.getQueryParameter("code")
            if (code != null) {
                intent.setData(null)
                
                val returnedState = data.getQueryParameter("state")
                lifecycleScope.launch {
                    val tokens = OAuthHelper.exchangeCodeForToken(
                        code,
                        returnedState,
                        viewModel.kcUrl.value,
                        viewModel.kcRealm.value,
                        viewModel.kcClientId.value
                    )
                    if (tokens != null) {
                        viewModel.authToken.value = tokens.accessToken
                        val prefs = com.mavi.vpn.data.PrefsManager(this@MainActivity)
                        prefs.savedRefreshToken = tokens.refreshToken
                        viewModel.saveServerDetails()
                        recreate()
                    }
                }
            }
        }
    }

    private fun startVpnService(ip: String, port: String, token: String, pin: String, splitMode: String, splitPackages: String) {
        val intent = Intent(this, MaviVpnService::class.java).apply {
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
