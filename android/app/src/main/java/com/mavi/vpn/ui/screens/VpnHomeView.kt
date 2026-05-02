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
fun HomeView(
    viewModel: VpnViewModel,
    isConnected: Boolean,
    onConnect: (String, String, String, String) -> Unit,
    onDisconnect: () -> Unit,
    onOpenSettings: () -> Unit,
    onGoToConfig: () -> Unit,
) {
    val T = MaviTheme.colors
    val serverIp by viewModel.serverIp.collectAsState()
    val serverPort by viewModel.serverPort.collectAsState()
    val authToken by viewModel.authToken.collectAsState()
    val certPin by viewModel.certPin.collectAsState()
    val useKeycloak by viewModel.useKeycloak.collectAsState()
    val kcUrl by viewModel.kcUrl.collectAsState()
    val hasKeycloakRefreshToken = viewModel.hasSavedKeycloakRefreshToken()

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
                        val hasKeycloakSession = authToken.isNotEmpty() || hasKeycloakRefreshToken
                        if (kcUrl.isEmpty() || !hasKeycloakSession) {
                            viewModel.updateErrorMessage("Please login with Keycloak first in Config.")
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
