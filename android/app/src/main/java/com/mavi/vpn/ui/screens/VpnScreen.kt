package com.mavi.vpn.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mavi.vpn.ui.components.MaviTextField
import com.mavi.vpn.viewmodel.VpnViewModel
import com.mavi.vpn.OAuthHelper
import kotlinx.coroutines.delay

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VpnScreen(
    viewModel: VpnViewModel,
    onConnect: (String, String, String, String) -> Unit,
    onDisconnect: () -> Unit,
    onOpenSettings: () -> Unit
) {
    val context = LocalContext.current
    val isConnected by viewModel.isConnected.collectAsState()
    
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
    val hasKeycloakToken = useKeycloak && authToken.isNotEmpty()
    val keycloakTokenUsableLocally = hasKeycloakToken && OAuthHelper.isAccessTokenUsable(authToken, skewSeconds = 0)

    LaunchedEffect(useKeycloak, authToken, isConnected) {
        if (!useKeycloak || authToken.isEmpty()) {
            return@LaunchedEffect
        }

        while (true) {
            // Re-sync the latest token from prefs in case the background service refreshed it
            val prefs = com.mavi.vpn.data.PrefsManager(viewModel.getApplication())
            val freshToken = prefs.savedToken
            if (freshToken.isNotEmpty() && freshToken != authToken) {
                viewModel.authToken.value = freshToken
            }
            
            // Check the most up-to-date token
            if (freshToken.isNotEmpty() && !OAuthHelper.isAccessTokenUsable(freshToken, skewSeconds = 0)) {
                // Background service failed to refresh it in time or we are totally expired.
                if (isConnected) {
                    onDisconnect()
                }
                viewModel.clearAuthToken()
                viewModel.updateErrorMessage("Keycloak access token expired. Please login again.")
                break
            }

            // Local token check only; the active HTTP check was removed to prevent UI-driven disconnects
            delay(5_000)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        // Scrollable content area
        Column(
            modifier = Modifier
                .weight(1f)
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(48.dp))

            Icon(
                imageVector = if (isConnected) Icons.Default.Lock else Icons.Default.Settings,
                contentDescription = null,
                modifier = Modifier
                    .size(80.dp)
                    .clickable { onOpenSettings() },
                tint = if (isConnected) Color(0xFF00FF7F) else Color(0xFF007AFF)
            )

            Spacer(modifier = Modifier.height(24.dp))

            Text(
                text = "MAVI VPN",
                fontSize = 32.sp,
                fontWeight = FontWeight.Bold,
                color = Color.White
            )

            Text(
                text = if (isConnected) "SECURED CONNECTION" else "READY TO CONNECT",
                fontSize = 14.sp,
                color = if (isConnected) Color(0xFF00FF7F) else Color.Gray
            )

            Spacer(modifier = Modifier.height(32.dp))

            if (!isConnected) {
                // --- Server fields ---
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

                Spacer(modifier = Modifier.height(16.dp))
                Divider(color = Color(0xFF2C2C2C))

                // --- Auth mode toggle ---
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Checkbox(
                        checked = useKeycloak,
                        onCheckedChange = { checked ->
                            if (checked && !useKeycloak) {
                                // Switching to KC
                                viewModel.saveServerDetails()
                            }
                            viewModel.useKeycloak.value = checked
                            viewModel.updateErrorMessage("")
                        },
                        colors = CheckboxDefaults.colors(
                            checkedColor = Color(0xFF673AB7),
                            uncheckedColor = Color.Gray,
                            checkmarkColor = Color.White
                        )
                    )
                    Text("Keycloak Authentication", color = Color.White, fontSize = 14.sp)
                }

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

                    Spacer(modifier = Modifier.height(12.dp))

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
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF673AB7)),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Icon(Icons.Default.Lock, contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Login with Keycloak")
                    }

                    if (hasKeycloakToken) {
                        val statusText = when {
                            keycloakTokenUsableLocally -> "Authenticated locally"
                            else -> "Token expired locally"
                        }
                        val statusColor = when {
                            keycloakTokenUsableLocally -> Color(0xFF00FF7F)
                            else -> Color(0xFFFF3B30)
                        }

                        Text(
                            text = statusText,
                            color = statusColor,
                            fontSize = 12.sp,
                            modifier = Modifier.padding(top = 4.dp)
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

                if (errorMessage.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(text = errorMessage, color = Color(0xFFFF3B30), fontSize = 12.sp)
                }

                Spacer(modifier = Modifier.height(16.dp))

                OutlinedButton(
                    onClick = onOpenSettings,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = Color.White)
                ) {
                    Text("Split Tunneling Settings")
                }
            } else {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(Color(0xFF1E1E1E), RoundedCornerShape(12.dp))
                        .padding(24.dp)
                ) {
                    Column {
                        Text("Connected to:", color = Color.Gray, fontSize = 12.sp)
                        Text(serverIp, color = Color.White, fontSize = 18.sp, fontWeight = FontWeight.Medium)
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        Button(
            onClick = {
                if (isConnected) {
                    onDisconnect()
                } else {
                    viewModel.updateErrorMessage("")
                    if (serverIp.isEmpty()) {
                        viewModel.updateErrorMessage("Please enter a server endpoint.")
                    } else if (useKeycloak) {
                        if (kcUrl.isEmpty()) {
                            viewModel.updateErrorMessage("Please enter Keycloak server details.")
                        } else if (authToken.isEmpty()) {
                            viewModel.updateErrorMessage("Please login with Keycloak first.")
                        } else if (!OAuthHelper.isAccessTokenUsable(authToken)) {
                            viewModel.clearAuthToken()
                            viewModel.updateErrorMessage("Keycloak login expired. Please login again.")
                        } else {
                            viewModel.saveKeycloakDetails()
                            onConnect(serverIp, serverPort, authToken, certPin)
                        }
                    } else {
                        if (authToken.isEmpty()) {
                            viewModel.updateErrorMessage("Please enter a Preshared Key.")
                        } else {
                            viewModel.saveServerDetails()
                            onConnect(serverIp, serverPort, authToken, certPin)
                        }
                    }
                }
            },
            modifier = Modifier.fillMaxWidth().height(56.dp),
            shape = RoundedCornerShape(12.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = if (isConnected) Color(0xFFFF3B30) else Color(0xFF007AFF)
            )
        ) {
            Text(
                text = if (isConnected) "DISCONNECT" else "CONNECT",
                fontSize = 18.sp,
                fontWeight = FontWeight.Bold,
                color = Color.White
            )
        }
        
        Spacer(modifier = Modifier.height(24.dp))
    }
}
