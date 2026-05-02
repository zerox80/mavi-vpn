package com.mavi.vpn.ui.screens

import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mavi.vpn.OAuthHelper
import com.mavi.vpn.ui.components.MaviCore
import com.mavi.vpn.ui.components.MaviCoreState
import com.mavi.vpn.ui.components.MaviTextField
import com.mavi.vpn.ui.theme.MaviTheme
import com.mavi.vpn.viewmodel.VpnViewModel
import kotlinx.coroutines.delay

@Composable
fun ConfigView(
    viewModel: VpnViewModel,
    context: Context,
    isConnected: Boolean,
) {
    val T = MaviTheme.colors
    val serverIp by viewModel.serverIp.collectAsState()
    val serverPort by viewModel.serverPort.collectAsState()
    val authToken by viewModel.authToken.collectAsState()
    val certPin by viewModel.certPin.collectAsState()
    val echConfig by viewModel.echConfig.collectAsState()
    
    val useKeycloak by viewModel.useKeycloak.collectAsState()
    val kcUrl by viewModel.kcUrl.collectAsState()
    val kcRealm by viewModel.kcRealm.collectAsState()
    val kcClientId by viewModel.kcClientId.collectAsState()
    
    val errorMessage by viewModel.errorMessage.collectAsState()
    val hasKeycloakRefreshToken = viewModel.hasSavedKeycloakRefreshToken()
    val keycloakSessionInvalid = viewModel.isSavedKeycloakSessionInvalid()
    val hasKeycloakToken = useKeycloak && authToken.isNotEmpty()
    val hasKeycloakSession = hasKeycloakToken || hasKeycloakRefreshToken
    val keycloakTokenUsableLocally = hasKeycloakToken && OAuthHelper.isAccessTokenUsable(authToken, skewSeconds = 0)

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(top = 58.dp, bottom = 16.dp, start = 16.dp, end = 16.dp)
    ) {
        Column(modifier = Modifier.padding(horizontal = 8.dp, vertical = 14.dp)) {
            Text(
                text = "/ CONFIGURATION",
                fontFamily = MaterialTheme.typography.labelSmall.fontFamily,
                fontSize = 10.sp,
                color = T.mute,
                letterSpacing = 1.5.sp
            )
            Text(
                text = "Tunnel Endpoint",
                fontFamily = MaterialTheme.typography.displayLarge.fontFamily,
                fontSize = 34.sp,
                color = T.ink,
                letterSpacing = (-0.8).sp,
                modifier = Modifier.padding(top = 2.dp)
            )
        }

        Spacer(modifier = Modifier.height(12.dp))

        Card(
            colors = CardDefaults.cardColors(containerColor = T.surface),
            shape = RoundedCornerShape(14.dp),
            border = androidx.compose.foundation.BorderStroke(1.dp, T.line),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                MaviTextField(
                    value = serverIp,
                    onValueChange = { viewModel.serverIp.value = it },
                    label = "Server IP / Endpoint",
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(12.dp))
                MaviTextField(
                    value = serverPort,
                    onValueChange = { viewModel.serverPort.value = it },
                    label = "Port",
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(12.dp))
                MaviTextField(
                    value = certPin,
                    onValueChange = { viewModel.certPin.value = it },
                    label = "Certificate PIN (SHA256 Hex)",
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(modifier = Modifier.height(12.dp))
                MaviTextField(
                    value = echConfig,
                    onValueChange = { viewModel.echConfig.value = it },
                    label = "ECH Config List (Hex) - Optional",
                    placeholder = "Enter to bypass SNI inspection",
                    modifier = Modifier.fillMaxWidth()
                )
            }
        }

        Spacer(modifier = Modifier.height(24.dp))

        Column(modifier = Modifier.padding(horizontal = 8.dp)) {
            Text(
                text = "/ AUTHENTICATION",
                fontFamily = MaterialTheme.typography.labelSmall.fontFamily,
                fontSize = 10.sp,
                color = T.mute,
                letterSpacing = 1.5.sp
            )
        }

        Spacer(modifier = Modifier.height(12.dp))

        Card(
            colors = CardDefaults.cardColors(containerColor = T.surface),
            shape = RoundedCornerShape(14.dp),
            border = androidx.compose.foundation.BorderStroke(1.dp, T.line),
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Switch(
                        checked = useKeycloak,
                        onCheckedChange = { checked ->
                            if (checked && !useKeycloak) {
                                viewModel.saveServerDetails()
                            }
                            viewModel.useKeycloak.value = checked
                            viewModel.updateErrorMessage("")
                        },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = Color.White,
                            checkedTrackColor = T.accent,
                            uncheckedThumbColor = T.mute,
                            uncheckedTrackColor = T.bg
                        )
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Text("Keycloak Authentication", color = T.ink, fontSize = 15.sp)
                }

                Spacer(modifier = Modifier.height(12.dp))

                if (useKeycloak) {
                    MaviTextField(
                        value = kcUrl,
                        onValueChange = { viewModel.kcUrl.value = it },
                        label = "Keycloak Server URL",
                        placeholder = "https://auth.example.com",
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    MaviTextField(
                        value = kcRealm,
                        onValueChange = { viewModel.kcRealm.value = it },
                        label = "Realm",
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    MaviTextField(
                        value = kcClientId,
                        onValueChange = { viewModel.kcClientId.value = it },
                        label = "Client ID",
                        modifier = Modifier.fillMaxWidth()
                    )

                    Spacer(modifier = Modifier.height(16.dp))

                    Button(
                        onClick = {
                            if (kcUrl.isEmpty()) {
                                viewModel.updateErrorMessage("Please enter a Keycloak Server URL.")
                            } else {
                                viewModel.saveKeycloakDetails()
                                viewModel.updateErrorMessage("")
                                OAuthHelper.startAuth(context, kcUrl, kcRealm, kcClientId)
                            }
                        },
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = T.accent),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Icon(Icons.Default.Lock, contentDescription = null, modifier = Modifier.size(18.dp), tint = Color.White)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Login with Keycloak", color = Color.White)
                    }

                    if (hasKeycloakSession || keycloakSessionInvalid) {
                        val statusText = when {
                            keycloakSessionInvalid -> "Session expired - login required"
                            keycloakTokenUsableLocally -> "Authenticated locally"
                            hasKeycloakRefreshToken -> "Access token will refresh"
                            else -> "Login required"
                        }
                        val statusColor = when {
                            keycloakSessionInvalid -> T.warn
                            keycloakTokenUsableLocally -> T.ok
                            hasKeycloakRefreshToken -> T.ok
                            else -> T.warn
                        }

                        Text(
                            text = statusText,
                            color = statusColor,
                            fontSize = 12.sp,
                            modifier = Modifier.padding(top = 8.dp)
                        )
                    }
                } else {
                    MaviTextField(
                        value = authToken,
                        onValueChange = { viewModel.authToken.value = it },
                        label = "Preshared Key",
                        placeholder = "Pre-shared token",
                        modifier = Modifier.fillMaxWidth(),
                        visualTransformation = PasswordVisualTransformation()
                    )
                }
            }
        }

        if (errorMessage.isNotEmpty()) {
            Spacer(modifier = Modifier.height(16.dp))
            Text(text = errorMessage, color = T.warn, fontSize = 13.sp, modifier = Modifier.padding(horizontal = 8.dp))
        }
    }
}
