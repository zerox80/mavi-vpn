package com.mavi.vpn.ui.components

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.BitmapDrawable
import android.graphics.drawable.Drawable
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.ImageBitmap
import kotlin.math.min
import kotlin.math.roundToInt

@Composable
fun MaviTextField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    placeholder: String = "",
    singleLine: Boolean = true,
    visualTransformation: androidx.compose.ui.text.input.VisualTransformation = androidx.compose.ui.text.input.VisualTransformation.None
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label, color = Color.Gray) },
        placeholder = { if (placeholder.isNotEmpty()) Text(placeholder, color = Color.Gray) },
        modifier = modifier,
        singleLine = singleLine,
        visualTransformation = visualTransformation,
        colors = OutlinedTextFieldDefaults.colors(
            focusedBorderColor = Color(0xFF007AFF),
            unfocusedBorderColor = Color.DarkGray,
            focusedTextColor = Color.White,
            unfocusedTextColor = Color.White
        )
    )
}

fun drawableToBitmap(drawable: Drawable, maxSizePx: Int = 48): Bitmap? {
    return try {
        val boundedMaxSize = maxSizePx.coerceAtLeast(1)
        val sourceWidth = if (drawable.intrinsicWidth > 0) drawable.intrinsicWidth else boundedMaxSize
        val sourceHeight = if (drawable.intrinsicHeight > 0) drawable.intrinsicHeight else boundedMaxSize
        val scale = min(
            boundedMaxSize.toFloat() / sourceWidth.toFloat(),
            boundedMaxSize.toFloat() / sourceHeight.toFloat()
        ).coerceAtMost(1f)
        val width = (sourceWidth * scale).roundToInt().coerceAtLeast(1)
        val height = (sourceHeight * scale).roundToInt().coerceAtLeast(1)

        if (drawable is BitmapDrawable) {
            val bitmap = drawable.bitmap
            if (bitmap.width <= boundedMaxSize && bitmap.height <= boundedMaxSize) {
                return bitmap
            }
            return Bitmap.createScaledBitmap(bitmap, width, height, true)
        }
        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bitmap)
        drawable.setBounds(0, 0, canvas.width, canvas.height)
        drawable.draw(canvas)
        bitmap
    } catch (e: Exception) {
        null
    }
}

fun Bitmap.toImageBitmap(): ImageBitmap {
    return this.asImageBitmap()
}
