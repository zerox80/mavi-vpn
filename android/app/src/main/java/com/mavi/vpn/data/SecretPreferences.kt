package com.mavi.vpn.data

import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal interface SecretCipher {
    fun encrypt(plaintext: String): String

    fun decrypt(ciphertext: String): String
}

internal data class DecodedSecretPreference(
    val value: String,
    val shouldMigrate: Boolean,
)

internal object SecretPreferenceValue {
    private const val PREFIX = "enc:v1:"

    fun encode(
        cipher: SecretCipher,
        plaintext: String,
    ): String = PREFIX + cipher.encrypt(plaintext)

    fun decode(
        cipher: SecretCipher,
        stored: String,
        defaultValue: String = "",
    ): DecodedSecretPreference {
        if (stored.isBlank()) {
            return DecodedSecretPreference(defaultValue, shouldMigrate = false)
        }

        if (!stored.startsWith(PREFIX)) {
            return DecodedSecretPreference(stored, shouldMigrate = true)
        }

        return try {
            DecodedSecretPreference(
                cipher.decrypt(stored.removePrefix(PREFIX)),
                shouldMigrate = false,
            )
        } catch (_: Exception) {
            DecodedSecretPreference(defaultValue, shouldMigrate = false)
        }
    }
}

internal class SecureStringPreferences(
    private val prefs: SharedPreferences,
    private val cipher: SecretCipher = AndroidKeystoreSecretCipher,
) {
    fun getString(
        key: String,
        defaultValue: String = "",
    ): String {
        val stored = prefs.getString(key, null) ?: return defaultValue
        val decoded = SecretPreferenceValue.decode(cipher, stored, defaultValue)
        if (decoded.shouldMigrate && decoded.value.isNotBlank()) {
            setString(key, decoded.value)
        }
        return decoded.value
    }

    fun setString(
        key: String,
        value: String,
    ) {
        val editor = prefs.edit()
        if (value.isBlank()) {
            editor.remove(key)
        } else {
            editor.putString(key, SecretPreferenceValue.encode(cipher, value))
        }
        editor.apply()
    }
}

internal object AndroidKeystoreSecretCipher : SecretCipher {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "mavi_vpn_shared_preferences_v1"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_TAG_BITS = 128

    override fun encrypt(plaintext: String): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey())
        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        return "${encode(cipher.iv)}:${encode(ciphertext)}"
    }

    override fun decrypt(ciphertext: String): String {
        val parts = ciphertext.split(":", limit = 2)
        require(parts.size == 2) { "Invalid encrypted preference value" }
        val iv = decode(parts[0])
        val encrypted = decode(parts[1])
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
        return String(cipher.doFinal(encrypted), Charsets.UTF_8)
    }

    @Synchronized
    private fun secretKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }

        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        keyGenerator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return keyGenerator.generateKey()
    }

    private fun encode(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)

    private fun decode(value: String): ByteArray = Base64.decode(value, Base64.NO_WRAP)
}
