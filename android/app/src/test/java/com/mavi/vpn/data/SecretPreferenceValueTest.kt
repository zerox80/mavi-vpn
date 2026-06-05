package com.mavi.vpn.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class SecretPreferenceValueTest {
    private val cipher = Base64TestCipher()

    @Test
    fun encodedSecretUsesVersionedPrefixWithoutPlaintext() {
        val encoded = SecretPreferenceValue.encode(cipher, "refresh-token")

        assertTrue(encoded.startsWith("enc:v1:"))
        assertFalse(encoded.contains("refresh-token"))
        assertEquals(
            "refresh-token",
            SecretPreferenceValue.decode(cipher, encoded).value,
        )
    }

    @Test
    fun legacyPlaintextSecretRequestsMigration() {
        val decoded = SecretPreferenceValue.decode(cipher, "legacy-token")

        assertEquals("legacy-token", decoded.value)
        assertTrue(decoded.shouldMigrate)
    }

    @Test
    fun encryptedSecretDoesNotRequestMigration() {
        val encoded = SecretPreferenceValue.encode(cipher, "access-token")
        val decoded = SecretPreferenceValue.decode(cipher, encoded)

        assertEquals("access-token", decoded.value)
        assertFalse(decoded.shouldMigrate)
    }

    @Test
    fun malformedEncryptedSecretFailsClosed() {
        val decoded = SecretPreferenceValue.decode(cipher, "enc:v1:not-base64")

        assertEquals("", decoded.value)
        assertFalse(decoded.shouldMigrate)
    }

    private class Base64TestCipher : SecretCipher {
        override fun encrypt(plaintext: String): String =
            Base64.getEncoder().encodeToString(plaintext.toByteArray(Charsets.UTF_8))

        override fun decrypt(ciphertext: String): String =
            String(Base64.getDecoder().decode(ciphertext), Charsets.UTF_8)
    }
}
