import Foundation

enum AppConstants {
    static let providerBundleIdentifier = "com.ratelmesh.ios.PacketTunnel"
    static let localizedDescription = "RatelMesh"
    static let configurationKey = "client-configuration-v1"
    static let selectedExitKey = "selected-exit"
    static let lastStatusKey = "last-status-json"
    static let lastProviderErrorKey = "last-provider-error"

    static var appGroup: String {
        Bundle.main.object(forInfoDictionaryKey: "RatelMeshAppGroup") as? String
            ?? "group.com.ratelmesh.shared"
    }

    static var keychainAccessGroup: String? {
        guard let value = Bundle.main.object(forInfoDictionaryKey: "RatelMeshKeychainAccessGroup") as? String,
              !value.isEmpty, !value.contains("$(") else { return nil }
        return value
    }

    static var sharedDefaults: UserDefaults {
        UserDefaults(suiteName: appGroup) ?? .standard
    }
}

