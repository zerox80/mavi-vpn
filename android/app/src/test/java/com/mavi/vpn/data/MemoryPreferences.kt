package com.mavi.vpn.data

import android.content.SharedPreferences
import java.lang.reflect.Proxy
import java.util.Base64

/** Minimal in-memory implementation of the Android preferences contract. */
internal class MemoryPreferences {
    private val values = mutableMapOf<String, Any>()
    val prefs: SharedPreferences =
        Proxy.newProxyInstance(
            SharedPreferences::class.java.classLoader,
            arrayOf(SharedPreferences::class.java),
        ) { _, method, args ->
            when (method.name) {
                "getString", "getBoolean" -> values[args[0]] ?: args[1]
                "edit" -> editor()
                else -> error("Unexpected preference call: ${method.name}")
            }
        } as SharedPreferences

    private fun editor(): SharedPreferences.Editor {
        val changes = mutableMapOf<String, Any?>()
        return Proxy.newProxyInstance(
            SharedPreferences.Editor::class.java.classLoader,
            arrayOf(SharedPreferences.Editor::class.java),
        ) { proxy, method, args ->
            when (method.name) {
                "putString", "putBoolean" -> {
                    changes[args[0] as String] = args[1]
                    proxy
                }
                "remove" -> {
                    changes[args[0] as String] = null
                    proxy
                }
                "apply", "commit" -> {
                    changes.forEach { (key, value) ->
                        if (value == null) values.remove(key) else values[key] = value
                    }
                    if (method.name == "commit") true else null
                }
                else -> error("Unexpected editor call: ${method.name}")
            }
        } as SharedPreferences.Editor
    }

    val secrets =
        SecureStringPreferences(
            prefs,
            object : SecretCipher {
                override fun encrypt(plaintext: String): String = Base64.getEncoder().encodeToString(plaintext.toByteArray(Charsets.UTF_8))

                override fun decrypt(ciphertext: String): String = String(Base64.getDecoder().decode(ciphertext), Charsets.UTF_8)
            },
        )
}
