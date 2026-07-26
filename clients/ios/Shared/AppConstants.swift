import Foundation

enum AppConstants {
    static let providerBundleIdentifier = "com.ratelmesh.ios.PacketTunnel"
    static let localizedDescription = "RatelMesh"
    static let configurationKey = "client-configuration-v1"
    static let installationBindingKey = "client-installation-binding-v1"
    static let installationBindingAccount = "installation-binding-v1"
    static let selectedExitKey = "selected-exit"
    static let lastStatusKey = "last-status-json"
    static let lastProviderErrorKey = "last-provider-error-v1"
    static let legacyLastProviderErrorKey = "last-provider-error"
    static let migratedProviderErrorKey = "migrated-provider-error-v1"
    static let lastSeenProviderErrorEventKey = "last-seen-provider-error-event-v1"
    static let providerErrorQueueFile = "provider-errors-v2.json"
    static let providerErrorQueueLockFile = "provider-errors-v2.lock"
    static let enrollmentResetPendingFile = "enrollment-reset-pending-v1"

    static var appGroup: String? {
        guard let value = Bundle.main.object(forInfoDictionaryKey: "RatelMeshAppGroup") as? String,
              !value.isEmpty, !value.contains("$(") else { return nil }
        return value
    }

    static var keychainAccessGroup: String? {
        guard let value = Bundle.main.object(forInfoDictionaryKey: "RatelMeshKeychainAccessGroup") as? String,
              !value.isEmpty, !value.contains("$("),
              value.rangeOfCharacter(from: .whitespacesAndNewlines) == nil else { return nil }
        return value
    }

    static func makeSharedDefaults(
        suiteName: String? = nil,
        factory: (String) -> UserDefaults? = { UserDefaults(suiteName: $0) }
    ) -> UserDefaults? {
        guard let suiteName = suiteName ?? appGroup else { return nil }
        return factory(suiteName)
    }

    static var sharedDefaults: UserDefaults? {
        makeSharedDefaults()
    }

    static var sharedContainerURL: URL? {
        guard let appGroup else { return nil }
        return FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup)
    }

    static func enrollmentResetIsPending(in container: URL) -> Bool {
        FileManager.default.fileExists(
            atPath: container.appendingPathComponent(enrollmentResetPendingFile).path
        )
    }
}

enum AppGroupAccessError: Error, TunnelErrorCodeProviding {
    case unavailable

    var tunnelErrorCode: TunnelErrorCode { .appGroupUnavailable }
}
