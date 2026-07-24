package com.ratelmesh.android.data

import android.content.Context

/** Versioned affirmative consent required before any device-wide VPN starts. */
object VpnDisclosureConsent {
    private const val PREFERENCES = "vpn-disclosure"
    private const val KEY_ACCEPTED_VERSION = "accepted-version"
    const val CURRENT_VERSION = 1

    fun isAccepted(context: Context): Boolean =
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .getInt(KEY_ACCEPTED_VERSION, 0) >= CURRENT_VERSION

    fun accept(context: Context) {
        check(
            context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
                .edit()
                .putInt(KEY_ACCEPTED_VERSION, CURRENT_VERSION)
                .commit(),
        ) { "Could not persist VPN disclosure consent" }
    }
}
