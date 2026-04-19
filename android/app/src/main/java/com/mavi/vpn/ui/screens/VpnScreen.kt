package com.mavi.vpn.ui.screens

import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mavi.vpn.ui.components.MaviTextField
import com.mavi.vpn.viewmodel.VpnViewModel
import com.mavi.vpn.OAuthHelper
import com.mavi.vpn.ui.components.MaviCore
import com.mavi.vpn.ui.components.MaviCoreState
import com.mavi.vpn.ui.theme.MaviTheme
import kotlinx.coroutines.delay

@Composable
fun VpnScreen(
    viewModel: VpnViewModel,
    onConnect: (String, String, String, String) -> Unit,
    onDisconnect: () -> Unit,
    onOpenSettings: () -> Unit
) {
    val context = LocalContext.current
    val isConnected by viewModel.isConnected.collectAsState()
    
    val authToken by viewModel.authToken.collectAsState()
    val useKeycloak by viewModel.useKeycloak.collectAsState()

    // Keycloak token refresh loop logic
    LaunchedEffect(useKeycloak, authToken, isConnected) {
        if (!useKeycloak || authToken.isEmpty()) return@LaunchedEffect

        while (true) {
            val prefs = com.mavi.vpn.data.PrefsManager(viewModel.getApplication())
            val freshToken = prefs.savedToken
            if (freshToken.isNotEmpty() && freshToken != authToken) {
                viewModel.authToken.value = freshToken
            }
            if (freshToken.isNotEmpty() && !OAuthHelper.isAccessTokenUsable(freshToken, skewSeconds = 0)) {
                if (isConnected) onDisconnect()
                viewModel.clearAuthToken()
                viewModel.updateErrorMessage("Keycloak access token expired. Please login again.")
                break
            }
            delay(5_000)
        }
    }

    var currentTab by remember { mutableStateOf("home") }
    val T = MaviTheme.colors

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(T.bg)
    ) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(bottom = 88.dp)
        ) {
            when (currentTab) {
                "home" -> HomeView(
                    viewModel = viewModel,
                    isConnected = isConnected,
                    onConnect = onConnect,
                    onDisconnect = onDisconnect,
                    onOpenSettings = onOpenSettings,
                    onGoToConfig = { currentTab = "config" }
                )
                "config" -> ConfigView(
                    viewModel = viewModel,
                    context = context,
                    isConnected = isConnected
                )
                "stats", "you" -> Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text("Coming Soon", color = T.mute)
                }
            }
        }

        // Bottom Tab Bar
        Row(
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .fillMaxWidth()
                .height(88.dp)
                .background(T.surface)
                .border(width = 1.dp, color = T.line)
                .padding(top = 12.dp, start = 20.dp, end = 20.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.Top
        ) {
            val tabs = listOf(
                Triple("home", "Tunnel", "◉"),
                Triple("config", "Config", "◎"),
                Triple("stats", "Stats", "≡"),
                Triple("you", "You", "◇")
            )
            
            tabs.forEach { (id, label, glyph) ->
                val isSelected = currentTab == id
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    modifier = Modifier
                        .weight(1f)
                        .clickable(
                            interactionSource = remember { androidx.compose.foundation.interaction.MutableInteractionSource() },
                            indication = null
                        ) {
                            currentTab = id
                        }
                ) {
                    Text(
                        text = glyph,
                        fontSize = 18.sp,
                        color = if (isSelected) T.accent else T.mute,
                        fontFamily = MaterialTheme.typography.labelSmall.fontFamily
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = label.uppercase(),
                        fontSize = 10.sp,
                        letterSpacing = 1.sp,
                        color = if (isSelected) T.accent else T.mute,
                        fontFamily = MaterialTheme.typography.labelSmall.fontFamily
                    )
                }
            }
        }
    }
}

@Composable
fun HomeView(
    viewModel: VpnViewModel,
    isConnected: Boolean,
    onConnect: (String, String, String, String) -> Unit,
    onDisconnect: () -> Unit,
    onOpenSettings: () -> Unit,
    onGoToConfig: () -> Unit
) {
    val T = MaviTheme.colors
    val serverIp by viewModel.serverIp.collectAsState()
    val serverPort by viewModel.serverPort.collectAsState()
    val authToken by viewModel.authToken.collectAsState()
    val certPin by viewModel.certPin.collectAsState()
    val useKeycloak by viewModel.useKeycloak.collectAsState()
    val kcUrl by viewModel.kcUrl.collectAsState()

    val state = if (isConnected) MaviCoreState.ON else MaviCoreState.OFF
    val labelColor = if (isConnected) T.ok else T.mute
    val isDark = androidx.compose.foundation.isSystemInDarkTheme()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(top = 58.dp, bottom = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        // Wordmark
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.Bottom
        ) {
            Text(
                text = "mavi",
                fontFamily = MaterialTheme.typography.displayLarge.fontFamily,
                fontSize = 28.sp,
                fontWeight = FontWeight.Medium,
                letterSpacing = (-0.8).sp,
                color = T.ink
            )
            Text(
                text = "PRIVATE · TUNNEL",
                fontFamily = MaterialTheme.typography.labelSmall.fontFamily,
                fontSize = 10.sp,
                letterSpacing = 1.5.sp,
                color = T.mute
            )
        }

        Spacer(modifier = Modifier.weight(1f))

        // Core Area
        Box(contentAlignment = Alignment.Center) {
            MaviCore(state = state, accent = T.accent, isDark = isDark, sizeDp = 240)
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Status Text
        Text(
            text = "// ${if (isConnected) "ENCRYPTED" else "NOT CONNECTED"}",
            fontFamily = MaterialTheme.typography.labelSmall.fontFamily,
            fontSize = 10.sp,
            letterSpacing = 2.sp,
            color = labelColor
        )
        Spacer(modifier = Modifier.height(6.dp))
        Text(
            text = if (serverIp.isNotEmpty()) serverIp else "Unknown",
            fontFamily = MaterialTheme.typography.displayLarge.fontFamily,
            fontSize = 36.sp,
            color = T.ink,
            lineHeight = 36.sp,
            letterSpacing = (-0.8).sp
        )
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = "Port $serverPort · ${if (isConnected) "tunnel active" else "ready"}",
            fontSize = 13.sp,
            color = T.ink2
        )

        Spacer(modifier = Modifier.height(24.dp))

        // Connect Button
        Button(
            onClick = {
                if (isConnected) {
                    onDisconnect()
                } else {
                    viewModel.updateErrorMessage("")
                    if (serverIp.isEmpty()) {
                        viewModel.updateErrorMessage("Please enter a server endpoint in Config.")
                        onGoToConfig()
                    } else if (useKeycloak) {
                        if (kcUrl.isEmpty() || authToken.isEmpty()) {
                            viewModel.updateErrorMessage("Please login with Keycloak first in Config.")
                            onGoToConfig()
                        } else if (!OAuthHelper.isAccessTokenUsable(authToken)) {
                            viewModel.clearAuthToken()
                            viewModel.updateErrorMessage("Keycloak login expired. Please login again.")
                            onGoToConfig()
                        } else {
                            viewModel.saveKeycloakDetails()
                            onConnect(serverIp, serverPort, authToken, certPin)
                        }
                    } else {
                        if (authToken.isEmpty()) {
                            viewModel.updateErrorMessage("Please enter a Preshared Key in Config.")
                            onGoToConfig()
                        } else {
                            viewModel.saveServerDetails()
                            onConnect(serverIp, serverPort, authToken, certPin)
                        }
                    }
                }
            },
            colors = ButtonDefaults.buttonColors(
                containerColor = if (isConnected) Color.Transparent else T.accent,
                contentColor = if (isConnected) T.ink else Color.White
            ),
            shape = CircleShape,
            modifier = Modifier
                .height(56.dp)
                .width(220.dp)
                .border(
                    width = if (isConnected) 1.5.dp else 0.dp,
                    color = if (isConnected) T.ink else Color.Transparent,
                    shape = CircleShape
                )
        ) {
            Text(
                text = if (isConnected) "Disconnect" else "Connect",
                fontSize = 15.sp,
                fontWeight = FontWeight.SemiBold,
                letterSpacing = 0.3.sp
            )
        }

        Spacer(modifier = Modifier.weight(1f))

        // Bottom Card
        Box(
            modifier = Modifier
                .padding(horizontal = 16.dp)
                .fillMaxWidth()
                .clip(RoundedCornerShape(18.dp))
                .background(T.surface)
                .border(1.dp, T.line, RoundedCornerShape(18.dp))
                .clickable { onOpenSettings() }
                .padding(16.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Settings, contentDescription = null, tint = T.ink, modifier = Modifier.size(26.dp))
                    Spacer(modifier = Modifier.width(14.dp))
                    Column {
                        Text("ADVANCED", fontFamily = MaterialTheme.typography.labelSmall.fontFamily, fontSize = 9.sp, letterSpacing = 1.5.sp, color = T.mute)
                        Text("Split Tunneling", fontSize = 15.sp, fontWeight = FontWeight.SemiBold, color = T.ink)
                    }
                }
                Text("›", fontSize = 24.sp, color = T.mute, fontFamily = MaterialTheme.typography.labelSmall.fontFamily)
            }
        }
    }
}

@Composable
fun ConfigView(
    viewModel: VpnViewModel,
    context: Context,
    isConnected: Boolean
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
    val hasKeycloakToken = useKeycloak && authToken.isNotEmpty()
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

                    if (hasKeycloakToken) {
                        val statusText = when {
                            keycloakTokenUsableLocally -> "Authenticated locally"
                            else -> "Token expired locally"
                        }
                        val statusColor = when {
                            keycloakTokenUsableLocally -> T.ok
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
