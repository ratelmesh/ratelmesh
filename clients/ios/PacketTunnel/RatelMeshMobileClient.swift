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
            throw RatelMeshMobileError.creationFailed
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
        do {
            if name.isEmpty { try app.clearExit() }
            else { try app.useExit(name) }
        } catch {
            throw RatelMeshMobileError.exitSelectionFailed
        }
    }

    var doctorDisclosureVersion: String { app.doctorDisclosureVersion() }

    func runNetworkDoctor(_ disclosureVersion: String, confirmed: Bool) throws -> String {
        var error: NSError?
        let result = app.runNetworkDoctor(
            disclosureVersion,
            confirmed: confirmed,
            error: &error
        )
        guard error == nil else {
            throw RatelMeshMobileError.doctorUnavailable
        }
        return result
    }

    func applyNetworkDoctorRepair(
        _ planID: String,
        action: String,
        disclosureVersion: String,
        confirmed: Bool
    ) throws -> String {
        var error: NSError?
        let result = app.applyNetworkDoctorRepair(
            planID,
            action: action,
            disclosureVersion: disclosureVersion,
            confirmed: confirmed,
            error: &error
        )
        guard error == nil else {
            throw RatelMeshMobileError.doctorUnavailable
        }
        return result
    }

    func setSystemLocation(latitude: Double, longitude: Double) throws {
        try app.setSystemLocation(latitude, longitude: longitude)
    }
}

enum RatelMeshMobileError: Error, TunnelErrorCodeProviding {
    case creationFailed
    case exitSelectionFailed
    case doctorUnavailable

    var tunnelErrorCode: TunnelErrorCode {
        switch self {
        case .creationFailed: .controlCoreStartFailed
        case .exitSelectionFailed: .exitSelectionFailed
        case .doctorUnavailable: .unknownProviderError
        }
    }
}
