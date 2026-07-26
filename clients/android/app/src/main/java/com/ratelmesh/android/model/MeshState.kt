package com.ratelmesh.android.model

import org.json.JSONObject

enum class ConnectionPhase { DISCONNECTED, CONNECTING, CONNECTED, DISCONNECTING, ERROR }

data class Peer(
    val name: String,
    val meshIp: String,
    val role: String,
    val online: Boolean,
    val pathType: String,
    val platform: String,
    val remoteAccessAllowed: Boolean,
    val remoteServices: List<RemoteService>,
) {
    val authorizedRemoteServices: List<RemoteService>
        get() = if (!remoteAccessAllowed || meshIp.isBlank()) {
            emptyList()
        } else {
            remoteServices.filter {
                it.kind in setOf("ssh", "rdp", "vnc") &&
                    it.port in 1..65535 &&
                    it.targetMeshIp == meshIp
            }
        }
}

data class RemoteService(val kind: String, val port: Int, val targetMeshIp: String)

data class ExitClient(
    val name: String,
    val meshIp: String,
    val state: String,
    val online: Boolean,
)

data class MeshState(
    val phase: ConnectionPhase = ConnectionPhase.DISCONNECTED,
    val publicKey: String = "",
    val meshIp: String = "",
    val activeExit: String = "",
    val selectedExit: String = "",
    val exitTrafficVerified: Boolean = false,
    val exitClients: List<ExitClient> = emptyList(),
    val peers: List<Peer> = emptyList(),
    val error: String? = null,
    // backendState mirrors the daemon's own state string ("Running"/"Starting"/…)
    // and enrollmentRequired mirrors its enrollmentRequired flag. Both were emitted
    // by the daemon but dropped on the floor here, which is why a device that is
    // enrolled-but-unable-to-register showed an eternal "Connecting…" with no
    // reason. Surfacing them lets the UI say what is actually wrong.
    val backendState: String = "",
    val enrollmentRequired: Boolean = false,
)

internal fun parseStatus(json: String, current: MeshState): MeshState {
    val root = JSONObject(json)
    val self = root.optJSONObject("self")
    val peersJson = root.optJSONArray("peers")
    val peers = buildList {
        if (peersJson != null) {
            for (index in 0 until peersJson.length()) {
                val peer = peersJson.optJSONObject(index) ?: continue
                val peerMeshIp = peer.optString("meshIP")
                val servicesJson = peer.optJSONArray("remoteServices")
                val services = buildList {
                    if (servicesJson != null) {
                        for (serviceIndex in 0 until servicesJson.length()) {
                            val service = servicesJson.optJSONObject(serviceIndex) ?: continue
                            val kind = service.optString("kind")
                            val port = service.optInt("port")
                            val targetMeshIp = service.optString("targetMeshIp")
                            if (kind in setOf("ssh", "rdp", "vnc") &&
                                port in 1..65535 &&
                                targetMeshIp == peerMeshIp &&
                                peerMeshIp.isNotBlank()
                            ) {
                                add(RemoteService(kind = kind, port = port, targetMeshIp = targetMeshIp))
                            }
                        }
                    }
                }
                add(
                    Peer(
                        name = peer.optString("name"),
                        meshIp = peerMeshIp,
                        role = peer.optString("role"),
                        online = peer.optBoolean("online"),
                        pathType = peer.optString("pathType", "-"),
                        platform = peer.optString("platform"),
                        remoteAccessAllowed = peer.optBoolean("remoteAccessAllowed"),
                        remoteServices = services,
                    ),
                )
            }
        }
    }
    val exitClientsJson = root.optJSONArray("exitClients")
    val exitClients = buildList {
        if (exitClientsJson != null) {
            for (index in 0 until exitClientsJson.length()) {
                val client = exitClientsJson.optJSONObject(index) ?: continue
                add(
                    ExitClient(
                        name = client.optString("name"),
                        meshIp = client.optString("meshIP"),
                        state = client.optString("state", "connecting"),
                        online = client.optBoolean("online"),
                    ),
                )
            }
        }
    }
    return current.copy(
        meshIp = self?.optString("meshIP").orEmpty(),
        activeExit = root.optString("activeExit"),
        selectedExit = root.optString("selectedExit"),
        exitTrafficVerified = root.optBoolean("exitTrafficVerified"),
        exitClients = exitClients,
        peers = peers,
        backendState = root.optString("state"),
        enrollmentRequired = root.optBoolean("enrollmentRequired"),
    )
}
