package com.ratelmesh.android.data

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.json.JSONObject

data class ClientSettings(
    val coordinatorUrl: String,
    val authKey: String,
    val hostname: String,
)

/** Stores one AES-GCM authenticated payload under a non-exportable Android Keystore key. */
class SecureSettings(context: Context) {
    private val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    @Synchronized
    fun load(): ClientSettings {
        val ciphertext = preferences.getString(KEY_CIPHERTEXT, null) ?: return emptySettings()
        val iv = preferences.getString(KEY_IV, null) ?: return emptySettings()
        return runCatching {
            val cipher = Cipher.getInstance(TRANSFORMATION).apply {
                init(
                    Cipher.DECRYPT_MODE,
                    encryptionKey(),
                    GCMParameterSpec(TAG_BITS, Base64.decode(iv, Base64.NO_WRAP)),
                )
            }
            val plaintext = cipher.doFinal(Base64.decode(ciphertext, Base64.NO_WRAP))
            val json = JSONObject(plaintext.toString(Charsets.UTF_8))
            ClientSettings(
                coordinatorUrl = json.optString("coordinatorUrl"),
                authKey = json.optString("authKey"),
                hostname = json.optString("hostname"),
            )
        }.getOrElse {
            // A changed lock screen can invalidate Keystore keys. Never use a
            // partially decrypted or unauthenticated configuration.
            preferences.edit().clear().commit()
            emptySettings()
        }
    }

    @Synchronized
    fun save(value: ClientSettings) {
        val plaintext = JSONObject()
            .put("coordinatorUrl", value.coordinatorUrl)
            .put("authKey", value.authKey)
            .put("hostname", value.hostname)
            .toString()
            .toByteArray(Charsets.UTF_8)
        val cipher = Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.ENCRYPT_MODE, encryptionKey())
        }
        val ciphertext = cipher.doFinal(plaintext)
        // commit() is deliberate: the foreground service may read immediately.
        check(
            preferences.edit()
                .putString(KEY_IV, Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
                .putString(KEY_CIPHERTEXT, Base64.encodeToString(ciphertext, Base64.NO_WRAP))
                .commit(),
        ) { "Could not save encrypted client settings" }
    }

    private fun encryptionKey(): SecretKey {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER).run {
            init(
                KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .setRandomizedEncryptionRequired(true)
                    .build(),
            )
            generateKey()
        }
    }

    private fun emptySettings() = ClientSettings("", "", "")

    private companion object {
        const val PREFERENCES = "mesh-client-settings"
        const val KEY_IV = "iv"
        const val KEY_CIPHERTEXT = "ciphertext"
        const val KEY_ALIAS = "ratelmesh.mesh.settings.v1"
        const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val TAG_BITS = 128
    }
}
