import Foundation

struct MobileTunnelConfiguration: Codable, Equatable, Sendable {
    let version: UInt64
    let active: Bool
    let privateKey: String
    let listenPort: Int
    let addresses: [String]
    let dnsServers: [String]
    let peers: [MobilePeerConfiguration]
    let directRoutes: [String]
    let blockRoutes: [String]
    var killSwitch: Bool? = nil

    func effectivePeers() throws -> [MobileEffectivePeer] {
        let exclusions = try (directRoutes + blockRoutes).map(IPPrefix.init)
        return try peers.compactMap { peer in
            let allowed = try peer.allowedIPs.flatMap { try IPPrefix($0).subtracting(exclusions) }.map(\.description)
            return allowed.isEmpty ? nil : MobileEffectivePeer(peer: peer, allowedIPs: allowed)
        }
    }

    func normalizedBlockRoutes() throws -> [String] {
        try blockRoutes.map { try IPPrefix($0).description }
    }

    func wgQuickConfiguration() throws -> String {
        guard active else { throw MobileConfigurationError.inactive }
        guard !privateKey.isEmpty, !addresses.isEmpty else { throw MobileConfigurationError.missingInterface }
        var scalarFields = [privateKey]
        scalarFields.append(contentsOf: addresses)
        scalarFields.append(contentsOf: dnsServers)
        scalarFields.append(contentsOf: directRoutes)
        scalarFields.append(contentsOf: blockRoutes)
        for peer in peers {
            scalarFields.append(peer.publicKey)
            scalarFields.append(peer.presharedKey ?? "")
            scalarFields.append(peer.endpoint)
            scalarFields.append(contentsOf: peer.allowedIPs)
        }
        guard scalarFields.allSatisfy(isSingleLine) else {
            throw MobileConfigurationError.invalidField("configuration contains a line break")
        }
        let blocked = try normalizedBlockRoutes()
        var lines = ["[Interface]", "PrivateKey = \(privateKey)", "Address = \(addresses.joined(separator: ", "))"]
        if listenPort > 0 { lines.append("ListenPort = \(listenPort)") }
        if !dnsServers.isEmpty { lines.append("DNS = \(dnsServers.joined(separator: ", "))") }

        for effective in try effectivePeers() {
            let peer = effective.peer
            lines.append(contentsOf: ["", "[Peer]", "PublicKey = \(peer.publicKey)"])
            if let presharedKey = peer.presharedKey, !presharedKey.isEmpty { lines.append("PresharedKey = \(presharedKey)") }
            if !peer.endpoint.isEmpty { lines.append("Endpoint = \(peer.endpoint)") }
            lines.append("AllowedIPs = \(effective.allowedIPs.joined(separator: ", "))")
            if peer.persistentKeepalive > 0 { lines.append("PersistentKeepalive = \(peer.persistentKeepalive)") }
        }

        // An endpoint-less peer owns blocked prefixes, causing WireGuard to drop
        // those packets instead of letting them escape through the system route.
        if !blocked.isEmpty {
            lines.append(contentsOf: [
                "", "[Peer]",
                "PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=",
                "AllowedIPs = \(blocked.joined(separator: ", "))"
            ])
        }
        return lines.joined(separator: "\n") + "\n"
    }
}

private func isSingleLine(_ value: String) -> Bool {
    !value.contains("\n") && !value.contains("\r") && !value.contains("\0")
}

struct MobileEffectivePeer: Equatable, Sendable {
    let peer: MobilePeerConfiguration
    let allowedIPs: [String]
}

struct MobilePeerConfiguration: Codable, Equatable, Sendable {
    let publicKey: String
    var presharedKey: String? = nil
    let endpoint: String
    let allowedIPs: [String]
    let persistentKeepalive: Int
}

struct MobileStatus: Codable, Equatable, Sendable {
    let state: String
    let enrollmentRequired: Bool?
    let coordURL: String?
    let netmapVersion: UInt64?
    let peers: [MobilePeerStatus]
    let activeExit: String
    let selectedExit: String?
    let exitTrafficVerified: Bool?
    let exitClients: [ExitClientStatus]?
    let killSwitch: Bool?
    let dns: String?

    var exits: [MobilePeerStatus] {
        peers.filter { $0.role == "exit" }.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }
}

struct ExitClientStatus: Codable, Equatable, Identifiable, Sendable {
    let name: String
    let meshIP: String
    let state: String
    let online: Bool
    var id: String { meshIP.isEmpty ? name : meshIP }
}

struct MobileRemoteService: Codable, Equatable, Identifiable, Sendable {
    let kind: String
    let port: UInt16
    let targetMeshIp: String
    var id: String { "\(kind)|\(port)|\(targetMeshIp)" }
}

struct MobilePeerStatus: Codable, Equatable, Identifiable, Sendable {
    let name: String
    let meshIP: String
    let role: String
    let online: Bool
    let pathType: String?
    let platform: String?
    let remoteAccessAllowed: Bool?
    let remoteServices: [MobileRemoteService]?
    var id: String { meshIP.isEmpty ? name : meshIP }

    var authorizedRemoteServices: [MobileRemoteService] {
        guard remoteAccessAllowed == true, !meshIP.isEmpty else { return [] }
        return (remoteServices ?? []).filter {
            ["ssh", "rdp", "vnc"].contains($0.kind) &&
                $0.port > 0 &&
                $0.targetMeshIp == meshIP
        }
    }
}

enum MobileConfigurationError: Error {
    case inactive
    case missingInterface
    case invalidCIDR(String)
    case invalidField(String)
}
