package com.mavi.vpn.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

val PrimaryBlue = Color(0xFF007AFF)
val BackgroundDark = Color(0xFF121212)
val SurfaceDark = Color(0xFF1E1E1E)
val SuccessGreen = Color(0xFF00FF7F)
val ErrorRed = Color(0xFFFF3B30)
val KeycloakPurple = Color(0xFF673AB7)
val DividerGray = Color(0xFF2C2C2C)

@Composable
fun MaviVpnTheme(content: @Composable () -> Unit) {
    val colorScheme = darkColorScheme(
        primary = PrimaryBlue,
        background = BackgroundDark,
        surface = SurfaceDark,
        error = ErrorRed,
        secondary = KeycloakPurple
    )

    MaterialTheme(
        colorScheme = colorScheme,
        content = content
    )
}
