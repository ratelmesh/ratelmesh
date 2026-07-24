package com.ratelmesh.android

import java.net.URI

internal const val OFFICIAL_COORDINATOR_URL = "https://control.ratelmesh.com"

internal fun normalizedCoordinator(value: String): String =
    value.trim().trimEnd('/').ifBlank { OFFICIAL_COORDINATOR_URL }

internal fun validCoordinator(value: String): Boolean = runCatching {
    val uri = URI(normalizedCoordinator(value))
    uri.scheme == "https" && !uri.host.isNullOrBlank() && uri.userInfo == null && uri.fragment == null
}.getOrDefault(false)

internal fun validEnrollmentCode(value: String, coordinator: String): Boolean {
    val code = value.trim()
    if (normalizedCoordinator(coordinator) != OFFICIAL_COORDINATOR_URL) return code.isNotBlank()
    return code.matches(Regex("ratelmesh-[23456789abcdefghjkmnpqrstuvwxyz]{4}(?:-[23456789abcdefghjkmnpqrstuvwxyz]{4}){2}"))
}

internal fun validDeviceName(value: String): Boolean =
    value.trim().matches(Regex("[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"))
