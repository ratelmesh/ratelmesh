import Foundation
import RatelMeshMobile

/// Dynamic-framework boundary around the gomobile control core.
///
/// WireGuardKit also links a Go archive. Keeping this wrapper in a dynamic
/// framework prevents the two Go runtimes and their cgo trampolines from being
/// coalesced into the Packet Tunnel executable on physical devices.
public final class RatelMeshMobileClient: @unchecked Sendable {
    private let app: MobileApp

    public init(
        coordinatorURL: String,
        authKey: String,
        stateDirectory: URL,
        hostname: String
    ) throws {
        var error: NSError?
        guard let app = MobileNewApp(
            coordinatorURL,
            authKey,
            stateDirectory.path,
            hostname,
            &error
        ) else {
            throw RatelMeshControlError.creationFailed
        }
        self.app = app
    }

    public func start() { app.start() }
    public func stop() { app.stop() }
    public var tunnelConfigurationJSON: String { app.tunnelConfigJSON() }
    public var tunnelConfigurationVersion: UInt64 {
        UInt64(max(0, app.tunnelConfigVersion()))
    }
    public var statusJSON: String { app.statusJSON() }

    public func updatePeerStatsJSON(_ json: String) throws {
        try app.updatePeerStatsJSON(json)
    }

    public func useExit(_ name: String) throws {
        if name.isEmpty { try app.clearExit() }
        else { try app.useExit(name) }
    }

    public var doctorDisclosureVersion: String { app.doctorDisclosureVersion() }

    public func runNetworkDoctor(_ disclosureVersion: String, confirmed: Bool) throws -> String {
        var error: NSError?
        let result = app.runNetworkDoctor(
            disclosureVersion,
            confirmed: confirmed,
            error: &error
        )
        guard error == nil else { throw RatelMeshControlError.doctorUnavailable }
        return result
    }

    public func applyNetworkDoctorRepair(
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
        guard error == nil else { throw RatelMeshControlError.doctorUnavailable }
        return result
    }

    public func setSystemLocation(latitude: Double, longitude: Double) throws {
        try app.setSystemLocation(latitude, longitude: longitude)
    }
}

private enum RatelMeshControlError: Error {
    case creationFailed
    case doctorUnavailable
}
