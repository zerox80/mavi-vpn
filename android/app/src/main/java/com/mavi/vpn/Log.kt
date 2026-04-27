package com.mavi.vpn

import android.content.Context
import com.mavi.vpn.data.PrefsManager
import com.mavi.vpn.native_lib.NativeLib

object Log {
    @Volatile
    private var enabled: Boolean = false

    fun configure(context: Context) {
        setEnabled(PrefsManager(context.applicationContext).savedEnableLogging)
    }

    fun setEnabled(value: Boolean) {
        enabled = value
        runCatching {
            NativeLib.setLoggingEnabled(value)
        }
    }

    fun isEnabled(): Boolean = enabled

    fun d(tag: String, message: String): Int =
        if (enabled) android.util.Log.d(tag, message) else 0

    fun d(tag: String, message: String, throwable: Throwable): Int =
        if (enabled) android.util.Log.d(tag, message, throwable) else 0

    fun i(tag: String, message: String): Int =
        if (enabled) android.util.Log.i(tag, message) else 0

    fun i(tag: String, message: String, throwable: Throwable): Int =
        if (enabled) android.util.Log.i(tag, message, throwable) else 0

    fun w(tag: String, message: String): Int =
        if (enabled) android.util.Log.w(tag, message) else 0

    fun w(tag: String, message: String, throwable: Throwable): Int =
        if (enabled) android.util.Log.w(tag, message, throwable) else 0

    fun e(tag: String, message: String): Int =
        if (enabled) android.util.Log.e(tag, message) else 0

    fun e(tag: String, message: String, throwable: Throwable): Int =
        if (enabled) android.util.Log.e(tag, message, throwable) else 0
}
