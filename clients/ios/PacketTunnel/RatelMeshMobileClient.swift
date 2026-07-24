import Foundation
import RatelMeshMobile

/// The only file coupled to gomobile's generated Objective-C names.
final class RatelMeshMobileClient: @unchecked Sendable {
    private let app: MobileApp

    init(configuration: ClientConfiguration, stateDirectory: URL) throws {
        var error: NSError?
        guard let app = MobileNewApp(
            configuration.coordinatorURL,
            configuration.authKey,
            stateDirectory.path,
            configuration.hostname,
            &error
        ) else {
            throw error ?? RatelMeshMobileError.creationFailed
        }
        self.app = app
    }

    func start() { app.start() }
    func stop() { app.stop() }
    var tunnelConfigurationJSON: String { app.tunnelConfigJSON() }
    var tunnelConfigurationVersion: UInt64 { UInt64(max(0, app.tunnelConfigVersion())) }
    var statusJSON: String { app.statusJSON() }

    func updatePeerStats(_ stats: [WireGuardPeerStat]) {
        guard let data = try? JSONEncoder().encode(stats), let json = String(data: data, encoding: .utf8) else { return }
        _ = try? app.updatePeerStatsJSON(json)
    }

    func useExit(_ name: String) throws {
        if name.isEmpty { try app.clearExit() }
        else { try app.useExit(name) }
    }

	func setSystemLocation(latitude: Double, longitude: Double) throws {
		try app.setSystemLocation(latitude, longitude: longitude)
	}
}

enum RatelMeshMobileError: LocalizedError {
    case creationFailed
    case exitSelectionFailed

    var errorDescription: String? {
        switch self {
        case .creationFailed: "无法启动 RatelMesh 控制核心。"
        case .exitSelectionFailed: "无法切换出口节点。"
        }
    }
}
