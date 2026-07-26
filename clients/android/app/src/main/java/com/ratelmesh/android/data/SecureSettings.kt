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

internal fun requiresIdentityReset(previous: ClientSettings, next: ClientSettings): Boolean =
    next.authKey.isNotBlank() &&
        (next.authKey != previous.authKey || next.coordinatorUrl != previous.coordinatorUrl)

internal object IdentityResetCoordinator {
    private val lock = Any()

    fun <T> serialized(action: () -> T): T = synchronized(lock, action)
}

/** Stores one AES-GCM authenticated payload under a non-exportable Android Keystore key. */
class SecureSettings(context: Context) {
    private val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    fun load(): ClientSettings = IdentityResetCoordinator.serialized { loadLocked() }

    private fun loadLocked(): ClientSettings {
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

    fun save(value: ClientSettings) {
        IdentityResetCoordinator.serialized {
            val previous = loadLocked()
            val identityChanged = requiresIdentityReset(previous, value)
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
            val editor = preferences.edit()
                .putString(KEY_IV, Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
                .putString(KEY_CIPHERTEXT, Base64.encodeToString(ciphertext, Base64.NO_WRAP))
            if (identityChanged) {
                editor.putBoolean(KEY_IDENTITY_RESET_PENDING, true)
            }
            check(editor.commit()) { "Could not save encrypted client settings" }
        }
    }

    fun resetIdentityIfPending(reset: () -> Unit): Boolean =
        IdentityResetCoordinator.serialized {
            if (!preferences.getBoolean(KEY_IDENTITY_RESET_PENDING, false)) {
                return@serialized false
            }
            // Keep the marker and settings transaction under the same
            // process-wide lock. A concurrent save cannot be acknowledged by
            // an older reset after its state directory was deleted.
            reset()
            check(
                preferences.edit().remove(KEY_IDENTITY_RESET_PENDING).commit(),
            ) { "Could not persist completed identity reset" }
            true
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
        const val KEY_IDENTITY_RESET_PENDING = "identity-reset-pending-v1"
        const val KEY_ALIAS = "ratelmesh.mesh.settings.v1"
        const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val TAG_BITS = 128
    }
}
