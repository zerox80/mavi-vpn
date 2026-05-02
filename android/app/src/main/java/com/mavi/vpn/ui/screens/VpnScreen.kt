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
fun VpnScreen(
    viewModel: VpnViewModel,
    onConnect: (String, String, String, String) -> Unit,
    onDisconnect: () -> Unit,
    onOpenSettings: () -> Unit,
) {
    val context = LocalContext.current
    val isConnected by viewModel.isConnected.collectAsState()
    
    val useKeycloak by viewModel.useKeycloak.collectAsState()

    // Mirror token changes persisted by MaviVpnService without owning refresh/logout decisions.
    LaunchedEffect(useKeycloak) {
        if (!useKeycloak) return@LaunchedEffect

        val prefs = com.mavi.vpn.data.PrefsManager(viewModel.getApplication())
        while (true) {
            val freshToken = prefs.savedToken
            if (freshToken != viewModel.authToken.value) {
                viewModel.authToken.value = freshToken
            }

            if (prefs.savedKeycloakSessionInvalid) {
                viewModel.updateErrorMessage("Keycloak access token expired. Please login again.")
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
                "home" ->
                    HomeView(
                        viewModel = viewModel,
                        isConnected = isConnected,
                        onConnect = onConnect,
                        onDisconnect = onDisconnect,
                        onOpenSettings = onOpenSettings,
                        onGoToConfig = { currentTab = "config" },
                    )
                "config" -> ConfigView(
                    viewModel = viewModel,
                    context = context,
                    isConnected = isConnected
                )
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
                Pair("home", "Tunnel" to "◉"),
                Pair("config", "Config" to "◎")
            )
            
            tabs.forEach { (id, info) ->
                val (label, glyph) = info
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
