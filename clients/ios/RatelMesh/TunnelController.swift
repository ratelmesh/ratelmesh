import Foundation
@preconcurrency import NetworkExtension

@MainActor
final class TunnelController {
    private(set) var manager: NETunnelProviderManager?
    var status: NEVPNStatus { manager?.connection.status ?? .invalid }

    func prepare() async throws {
        manager = try await loadManager()
    }

    func installIfNeeded() async throws {
        let manager = self.manager ?? NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = AppConstants.providerBundleIdentifier
        proto.serverAddress = "RatelMesh"
        proto.providerConfiguration = ["schemaVersion": 1]
        manager.protocolConfiguration = proto
        manager.localizedDescription = AppConstants.localizedDescription
        manager.isEnabled = true
        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
        self.manager = manager
    }

    func start() throws {
        guard let manager, manager.isEnabled else { throw TunnelError.notInstalled }
        try manager.connection.startVPNTunnel()
    }

    func stop() {
        manager?.connection.stopVPNTunnel()
    }

    func setExit(_ name: String) async throws {
        let action = name.isEmpty ? "clearExit" : "useExit"
        var object: [String: String] = ["action": action]
        if !name.isEmpty { object["name"] = name }
        let reply = try await send(object)
        if let response = try JSONSerialization.jsonObject(with: reply) as? [String: Any],
           response["ok"] as? Bool == false {
            throw TunnelError.provider(response["error"] as? String ?? "出口切换失败。")
        }
    }

    func statusData() async throws -> Data? {
        guard status == .connected || status == .reasserting else { return nil }
        return try await send(["action": "status"])
    }

	func setSystemLocation(latitude: Double, longitude: Double) async throws {
		_ = try await send([
			"action": "setSystemLocation",
			"latitude": String(latitude),
			"longitude": String(longitude),
		])
	}

    private func send(_ object: [String: String]) async throws -> Data {
        guard let session = manager?.connection as? NETunnelProviderSession else { throw TunnelError.notInstalled }
        let data = try JSONSerialization.data(withJSONObject: object)
        return try await withCheckedThrowingContinuation { continuation in
            do {
                try session.sendProviderMessage(data) { response in
                    continuation.resume(returning: response ?? Data())
                }
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }

    private func loadManager() async throws -> NETunnelProviderManager? {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        return managers.first {
            ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                == AppConstants.providerBundleIdentifier
        }
    }
}

enum TunnelError: LocalizedError {
    case notInstalled
    case provider(String)

    var errorDescription: String? {
        switch self {
        case .notInstalled: "VPN 配置尚未安装。"
        case .provider(let message): message
        }
    }
}
