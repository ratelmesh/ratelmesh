import Foundation
import WireGuardKit

extension MobileTunnelConfiguration {
    func wireGuardConfiguration() throws -> TunnelConfiguration {
        guard active else { throw MobileConfigurationError.inactive }
        guard let privateKey = PrivateKey(base64Key: privateKey) else {
            throw MobileConfigurationError.invalidField("privateKey")
        }
        var interface = InterfaceConfiguration(privateKey: privateKey)
        interface.addresses = try addresses.map {
            guard let value = IPAddressRange(from: $0) else { throw MobileConfigurationError.invalidField("addresses: \($0)") }
            return value
        }
        if listenPort > 0 {
            guard let value = UInt16(exactly: listenPort) else { throw MobileConfigurationError.invalidField("listenPort") }
            interface.listenPort = value
        }
        interface.dns = try dnsServers.map {
            guard let value = DNSServer(from: $0) else { throw MobileConfigurationError.invalidField("dnsServers: \($0)") }
            return value
        }

        var configurations = try effectivePeers().map { effective -> PeerConfiguration in
            guard let key = PublicKey(base64Key: effective.peer.publicKey) else {
                throw MobileConfigurationError.invalidField("peer.publicKey")
            }
            var peer = PeerConfiguration(publicKey: key)
            if let encodedPSK = effective.peer.presharedKey, !encodedPSK.isEmpty {
                guard let psk = PreSharedKey(base64Key: encodedPSK) else {
                    throw MobileConfigurationError.invalidField("peer.presharedKey")
                }
                peer.preSharedKey = psk
            }
            peer.allowedIPs = try effective.allowedIPs.map {
                guard let value = IPAddressRange(from: $0) else { throw MobileConfigurationError.invalidField("peer.allowedIPs: \($0)") }
                return value
            }
            if !effective.peer.endpoint.isEmpty {
                guard let endpoint = Endpoint(from: effective.peer.endpoint) else {
                    throw MobileConfigurationError.invalidField("peer.endpoint: \(effective.peer.endpoint)")
                }
                peer.endpoint = endpoint
            }
            if effective.peer.persistentKeepalive > 0 {
                guard let value = UInt16(exactly: effective.peer.persistentKeepalive) else {
                    throw MobileConfigurationError.invalidField("peer.persistentKeepalive")
                }
                peer.persistentKeepAlive = value
            }
            return peer
        }

        let blocked = try normalizedBlockRoutes()
        if !blocked.isEmpty {
            guard let key = PublicKey(base64Key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=") else {
                throw MobileConfigurationError.invalidField("block peer key")
            }
            var peer = PeerConfiguration(publicKey: key)
            peer.allowedIPs = try blocked.map {
                guard let value = IPAddressRange(from: $0) else { throw MobileConfigurationError.invalidField("blockRoutes: \($0)") }
                return value
            }
            configurations.append(peer)
        }
        return TunnelConfiguration(name: "RatelMesh", interface: interface, peers: configurations)
    }
}
