package com.mavi.vpn.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

@Immutable
data class MaviColors(
    val bg: Color,
    val surface: Color,
    val elevated: Color,
    val ink: Color,
    val ink2: Color,
    val mute: Color,
    val line: Color,
    val accent: Color,
    val accentSoft: Color,
    val ok: Color,
    val warn: Color
)

val LightColors = MaviColors(
    bg = Color(0xFFF4F2EC),
    surface = Color(0xFFFBFAF6),
    elevated = Color(0xFFFFFFFF),
    ink = Color(0xFF141310),
    ink2 = Color(0xFF3A372F),
    mute = Color(0xFF6B6759),
    line = Color(0xFFE4DFD2),
    accent = Color(0xFF2B44FF),
    accentSoft = Color(0xFFE6E9FF),
    ok = Color(0xFF146B3A),
    warn = Color(0xFFC25100)
)

val DarkColors = MaviColors(
    bg = Color(0xFF0B0B0A),
    surface = Color(0xFF141412),
    elevated = Color(0xFF1C1C19),
    ink = Color(0xFFF5F2E8),
    ink2 = Color(0xFFBFBBAB),
    mute = Color(0xFF7A7769),
    line = Color(0xFF26241F),
    accent = Color(0xFF7A8CFF),
    accentSoft = Color(0xFF1D2150),
    ok = Color(0xFF5ECB8A),
    warn = Color(0xFFF19855)
)

val LocalMaviColors = staticCompositionLocalOf { LightColors }

val MaviTypography = Typography(
    displayLarge = TextStyle(
        fontFamily = FontFamily.Serif, // Mapping to Fraunces
        fontWeight = FontWeight.Normal,
        fontSize = 36.sp,
        letterSpacing = (-0.8).sp
    ),
    bodyLarge = TextStyle(
        fontFamily = FontFamily.SansSerif, // Mapping to Geist/UI
        fontWeight = FontWeight.Normal,
        fontSize = 15.sp
    ),
    labelSmall = TextStyle(
        fontFamily = FontFamily.Monospace, // Mapping to JetBrains Mono
        fontWeight = FontWeight.Normal,
        fontSize = 10.sp,
        letterSpacing = 1.5.sp
    )
)

@Composable
fun MaviVpnTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val colors = if (darkTheme) DarkColors else LightColors

    // Also map to Material3 color scheme for standard components
    val materialColorScheme = if (darkTheme) {
        darkColorScheme(
            background = colors.bg,
            surface = colors.surface,
            primary = colors.accent,
            onPrimary = Color.White,
            onBackground = colors.ink,
            onSurface = colors.ink,
            error = colors.warn
        )
    } else {
        lightColorScheme(
            background = colors.bg,
            surface = colors.surface,
            primary = colors.accent,
            onPrimary = Color.White,
            onBackground = colors.ink,
            onSurface = colors.ink,
            error = colors.warn
        )
    }

    CompositionLocalProvider(LocalMaviColors provides colors) {
        MaterialTheme(
            colorScheme = materialColorScheme,
            typography = MaviTypography,
            content = content
        )
    }
}

object MaviTheme {
    val colors: MaviColors
        @Composable
        get() = LocalMaviColors.current
}
