package com.mavi.vpn.ui.components

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.withFrameMillis
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.unit.dp
import kotlin.math.cos
import kotlin.math.sin

enum class MaviCoreState { OFF, CONNECTING, ON }

@Composable
fun MaviCore(
    state: MaviCoreState,
    accent: Color,
    isDark: Boolean,
    modifier: Modifier = Modifier,
    sizeDp: Int = 240
) {
    // We drive time via withFrameMillis to simulate requestAnimationFrame tracking actual time
    var timeSeconds by remember { mutableFloatStateOf(0f) }
    LaunchedEffect(Unit) {
        val startTime = withFrameMillis { it }
        while (true) {
            withFrameMillis { frameTime ->
                timeSeconds = (frameTime - startTime) / 1000f
            }
        }
    }

    val breathe = 0.5f + 0.5f * sin(timeSeconds * 0.9f)
    val pulse = 0.5f + 0.5f * sin(timeSeconds * 2.4f)
    val rotSpeed = if (state == MaviCoreState.CONNECTING) 60f else 18f
    val rot = (timeSeconds * rotSpeed) % 360f

    val rings = listOf(0.42f, 0.56f, 0.72f, 0.88f)
    val isOff = state == MaviCoreState.OFF

    val ringColor = if (isOff) {
        if (isDark) Color(0xFFFFFFFF).copy(alpha = 0.07f) else Color(0xFF000000).copy(alpha = 0.08f)
    } else {
        accent
    }

    Canvas(modifier = modifier.size(sizeDp.dp)) {
        val sizePx = size.width
        val R = sizePx / 2f
        val cx = R
        val cy = R
        val centerOffset = Offset(cx, cy)

        // ambient halo
        val haloRadius = R * (0.9f + 0.04f * breathe)
        val haloAlpha = if (isOff) 0f else 0.25f
        if (haloAlpha > 0f) {
            drawCircle(
                brush = Brush.radialGradient(
                    colors = listOf(accent.copy(alpha = haloAlpha), accent.copy(alpha = 0f)),
                    center = centerOffset,
                    radius = haloRadius
                ),
                radius = haloRadius,
                center = centerOffset
            )
        }

        // concentric rings
        rings.forEachIndexed { i, f ->
            val strokeWidth = if (i == 1) 1.5f.dp.toPx() else 1f.dp.toPx()
            val opacity = if (isOff) 0.6f else 0.18f + 0.12f * (1f - i / rings.size.toFloat()) + 0.08f * pulse
            
            drawCircle(
                color = ringColor.copy(alpha = opacity),
                radius = R * f,
                center = centerOffset,
                style = Stroke(width = strokeWidth)
            )
        }

        // radial ticks
        if (!isOff) {
            for (i in 0 until 48) {
                val a = (i * 360f / 48f) * Math.PI / 180f
                val r1 = R * 0.91f
                val r2 = R * (0.94f + 0.02f * sin(timeSeconds * 2f + i))
                val opacity = 0.15f + 0.35f * ((sin(timeSeconds * 1.5f + i * 0.4f) + 1f) / 2f)
                
                val start = Offset(
                    x = cx + (cos(a) * r1).toFloat(),
                    y = cy + (sin(a) * r1).toFloat()
                )
                val end = Offset(
                    x = cx + (cos(a) * r2).toFloat(),
                    y = cy + (sin(a) * r2).toFloat()
                )
                
                drawLine(
                    color = accent.copy(alpha = opacity),
                    start = start,
                    end = end,
                    strokeWidth = 1f.dp.toPx()
                )
            }
        }

        // core blob
        val coreR = R * 0.28f + if (isOff) 0f else 6f.dp.toPx() * breathe
        val coreAlpha1 = if (isOff) 0.05f else 0.9f
        val coreAlpha2 = if (isOff) 0.02f else 0.35f
        
        // core glow
        drawCircle(
            brush = Brush.radialGradient(
                colors = listOf(
                    accent.copy(alpha = coreAlpha1),
                    accent.copy(alpha = coreAlpha2),
                    accent.copy(alpha = 0f)
                ),
                center = centerOffset,
                radius = coreR + 20f.dp.toPx()
            ),
            radius = coreR + 20f.dp.toPx(),
            center = centerOffset
        )
        
        // core solid
        val solidColor = if (isOff) {
            if (isDark) Color(0xFF2A2824) else Color(0xFFE8E3D3)
        } else {
            accent
        }
        drawCircle(
            color = solidColor,
            radius = coreR,
            center = centerOffset
        )
        
        // inner highlight
        if (!isOff) {
            val highlightCenter = Offset(cx - coreR * 0.3f, cy - coreR * 0.3f)
            drawCircle(
                color = Color.White.copy(alpha = 0.18f + 0.1f * breathe),
                radius = coreR * 0.5f,
                center = highlightCenter
            )
        }

        // orbit dots
        if (!isOff) {
            val orbitR = R * 0.56f
            for (i in 0 until 5) {
                val a = (rot + i * 72f) * Math.PI / 180f
                val dotX = cx + (cos(a) * orbitR).toFloat()
                val dotY = cy + (sin(a) * orbitR).toFloat()
                val dotR = if (i == 0) 4f.dp.toPx() else 2f.dp.toPx()
                val opacity = if (i == 0) 1f else 0.4f + 0.3f * sin(timeSeconds * 2f + i).toFloat()
                
                drawCircle(
                    color = accent.copy(alpha = opacity),
                    radius = dotR,
                    center = Offset(dotX, dotY)
                )
            }
        }
    }
}
