package com.ratelmesh.android

import java.net.Inet6Address
import java.net.InetAddress

internal object RemoteAccessTarget {
    fun url(scheme: String, address: String, port: Int): String? {
        if (scheme !in setOf("ssh", "rdp", "vnc") || port !in 1..65535) return null
        val host = when {
            validIpv4(address) -> address
            validIpv6(address) -> "[$address]"
            else -> return null
        }
        return "$scheme://$host:$port"
    }

    private fun validIpv4(address: String): Boolean {
        val parts = address.split('.')
        return parts.size == 4 && parts.all {
            it.isNotEmpty() && it.length <= 3 && it.all(Char::isDigit) &&
                (it.toIntOrNull() ?: -1) in 0..255
        }
    }

    private fun validIpv6(address: String): Boolean {
        if (address.isEmpty() || '%' in address ||
            !address.matches(Regex("[0-9A-Fa-f:.]+"))
        ) {
            return false
        }
        return runCatching { InetAddress.getByName(address) is Inet6Address }.getOrDefault(false)
    }
}
