package com.ratelmesh.android.service

import org.json.JSONArray
import org.json.JSONObject

/** Converts the gomobile JSON contract into wg-quick syntax consumed by WireGuard. */
internal object TunnelConfigParser {
    fun isActive(json: String): Boolean = JSONObject(json).optBoolean("active")

    fun isReady(json: String): Boolean {
        val root = JSONObject(json)
        return root.optBoolean("active") &&
            root.string("privateKey", "private_key").isNotBlank() &&
            root.strings("addresses", "address").isNotEmpty()
    }

    /**
     * WireGuard's Android GoBackend destroys the active VpnService tunnel before
     * establishing a replacement for every new Config object. Endpoint-only
     * netmap refreshes must therefore be deferred while the current path is
     * healthy; authenticated WireGuard roaming already updates that live path.
     * Route, identity and key changes still require an immediate replacement.
     */
    fun requiresTunnelReplacement(previousJson: String, nextJson: String): Boolean =
        replacementFingerprint(previousJson) != replacementFingerprint(nextJson)

    fun shouldApplyRefresh(
        previousJson: String?,
        nextJson: String,
        selectedExit: String,
        exitTrafficVerified: Boolean,
    ): Boolean {
        if (previousJson == null || requiresTunnelReplacement(previousJson, nextJson)) return true
        // In DIRECT, replacing the Mesh-only VPN does not interrupt ordinary
        // internet traffic and keeps peer/relay recovery responsive. Defer only
        // while a verified full-tunnel EXIT is carrying the user's traffic.
        return selectedExit.isBlank() || !exitTrafficVerified
    }

    fun toWgQuick(json: String, excludedApplication: String = ""): String {
        val root = JSONObject(json)
        require(root.optBoolean("active")) { "Tunnel config is inactive" }
        val privateKey = root.string("privateKey", "private_key")
        require(privateKey.isNotBlank()) { "Tunnel config has no private key" }

        val addresses = root.strings("addresses", "address")
        require(addresses.isNotEmpty()) { "Tunnel config has no interface address" }

        return buildString {
            appendLine("[Interface]")
            appendLine("PrivateKey = $privateKey")
            appendLine("Address = ${addresses.joinToString(", ")}")
            if (excludedApplication.isNotBlank()) {
                // RatelMeshMobile owns coordinator and relay sockets in a sibling
                // process under this package UID. Excluding our package keeps
                // those transport sockets on the underlying network when an
                // exit peer installs 0.0.0.0/0; otherwise the relay is routed
                // back into itself and a relay-only client loses all traffic.
                appendLine("ExcludedApplications = $excludedApplication")
            }
            root.int("listenPort", "listen_port")
                .takeIf { it > 0 }
                ?.let { appendLine("ListenPort = $it") }
            root.strings("dns", "dnsServers", "dns_servers")
                .takeIf { it.isNotEmpty() }
                ?.let { appendLine("DNS = ${it.joinToString(", ")}") }
            appendLine()

            val directRoutes = root.strings("directRoutes", "direct_routes")
            val blockRoutes = root.strings("blockRoutes", "block_routes")
            val ipv6ExitCapture = blockRoutes.toSet() == setOf("::/1", "8000::/1")
            require(blockRoutes.isEmpty() || ipv6ExitCapture) {
                "Android's WireGuard backend cannot safely enforce blockRoutes"
            }
            val peers = root.optJSONArray("peers") ?: JSONArray()
            for (index in 0 until peers.length()) {
                val peer = peers.getJSONObject(index)
                val publicKey = peer.string("publicKey", "public_key")
                require(publicKey.isNotBlank()) { "Peer $index has no public key" }
                val allowedIps = peer.strings("allowedIPs", "allowedIps", "allowed_ips", "routes").toMutableList()
                require(allowedIps.isNotEmpty()) { "Peer $index has no allowed IPs" }
                // Android's WireGuard backend cannot install standalone reject
                // routes. When the shared daemon protects a v4-only exit with
                // the two IPv6 /1 blackholes, capture ::/0 into that same exit
                // peer instead. The VPN interface then owns all IPv6 traffic;
                // an exit without IPv6 forwarding drops it inside the tunnel
                // rather than leaking it through the physical network.
                if (ipv6ExitCapture && allowedIps.contains("0.0.0.0/0") && !allowedIps.contains("::/0")) {
                    allowedIps.add("::/0")
                }
                val effectiveAllowedIps = CidrRoutes.subtract(allowedIps, directRoutes)
                if (effectiveAllowedIps.isEmpty()) continue

                appendLine("[Peer]")
                appendLine("PublicKey = $publicKey")
                peer.string("presharedKey", "preshared_key")
                    .takeIf { it.isNotBlank() }
                    ?.let { appendLine("PresharedKey = $it") }
                peer.string("endpoint")
                    .takeIf { it.isNotBlank() }
                    ?.let { appendLine("Endpoint = $it") }
                appendLine("AllowedIPs = ${effectiveAllowedIps.joinToString(", ")}")
                peer.int("persistentKeepalive", "persistentKeepaliveSeconds", "persistent_keepalive")
                    .takeIf { it > 0 }
                    ?.let { appendLine("PersistentKeepalive = $it") }
                appendLine()
            }
        }
    }

    private fun JSONObject.string(vararg names: String): String {
        for (name in names) {
            if (has(name) && !isNull(name)) return optString(name)
        }
        return ""
    }

    private fun JSONObject.int(vararg names: String): Int {
        for (name in names) {
            if (has(name) && !isNull(name)) return optInt(name)
        }
        return 0
    }

    private fun JSONObject.strings(vararg names: String): List<String> {
        for (name in names) {
            if (!has(name) || isNull(name)) continue
            val value = opt(name)
            return when (value) {
                is JSONArray -> buildList {
                    for (index in 0 until value.length()) {
                        value.optString(index).takeIf { it.isNotBlank() }?.let(::add)
                    }
                }
                is String -> value.split(',').map(String::trim).filter(String::isNotBlank)
                else -> emptyList()
            }
        }
        return emptyList()
    }

    private fun replacementFingerprint(json: String): String {
        val root = JSONObject(json)
        val fingerprint = JSONObject()
            .put("active", root.optBoolean("active"))
            .put("privateKey", root.string("privateKey", "private_key"))
            .put("listenPort", root.int("listenPort", "listen_port"))
            .put("addresses", JSONArray(root.strings("addresses", "address")))
            .put("dns", JSONArray(root.strings("dns", "dnsServers", "dns_servers")))
            .put("directRoutes", JSONArray(root.strings("directRoutes", "direct_routes")))
            .put("blockRoutes", JSONArray(root.strings("blockRoutes", "block_routes")))
            .put("killSwitch", root.optBoolean("killSwitch", false))
        val peers = root.optJSONArray("peers") ?: JSONArray()
        val stablePeers = JSONArray()
        for (index in 0 until peers.length()) {
            val peer = peers.getJSONObject(index)
            stablePeers.put(
                JSONObject()
                    .put("publicKey", peer.string("publicKey", "public_key"))
                    .put("presharedKey", peer.string("presharedKey", "preshared_key"))
                    .put(
                        "allowedIPs",
                        JSONArray(peer.strings("allowedIPs", "allowedIps", "allowed_ips", "routes")),
                    ),
            )
        }
        return fingerprint.put("peers", stablePeers).toString()
    }
}
