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

fun drawableToBitmap(drawable: Drawable): Bitmap? {
    return try {
        if (drawable is BitmapDrawable) {
            return drawable.bitmap
        }
        val width = if (drawable.intrinsicWidth > 0) drawable.intrinsicWidth else 48
        val height = if (drawable.intrinsicHeight > 0) drawable.intrinsicHeight else 48
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
