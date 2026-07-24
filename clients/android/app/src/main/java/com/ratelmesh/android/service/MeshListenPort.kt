package com.ratelmesh.android.service

import android.content.Context
import java.security.SecureRandom

/**
 * Keeps this installation on its own stable UDP source port.
 *
 * Some consumer NATs incorrectly evict an existing mapping when two devices on
 * the same Wi-Fi both send WireGuard from 51820 to the same EXIT. A persisted
 * per-install port prevents the second device from stealing the first device's
 * mapping while remaining stable enough for STUN and WireGuard hole punching.
 */
internal object MeshListenPort {
    private const val PREFERENCES = "ratelmesh_network_runtime"
    private const val KEY = "wireguard_listen_port"
    // This range is disjoint from the shared Go core's 30000-60999 range, so
    // an Android device cannot collide with a Mac, iPhone, Linux or Windows
    // client even on a router with the broken same-source-port behavior.
    internal const val MIN = 10_000
    internal const val MAX = 29_999
    private const val RANGE = MAX - MIN + 1

    @Synchronized
    fun getOrCreate(context: Context): Int {
        val preferences = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
        val saved = preferences.getInt(KEY, 0)
        if (isValid(saved)) return saved

        val generated = fromEntropy(SecureRandom().nextInt(RANGE))
        check(preferences.edit().putInt(KEY, generated).commit()) {
            "could not persist WireGuard listen port"
        }
        return generated
    }

    internal fun isValid(port: Int): Boolean = port in MIN..MAX

    internal fun fromEntropy(entropy: Int): Int {
        require(entropy in 0 until RANGE)
        return MIN + entropy
    }
}
