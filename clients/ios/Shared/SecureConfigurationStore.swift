import Foundation
import Security

struct SecureConfigurationStore: Sendable {
    private let service = "com.ratelmesh.ios.configuration"
    private let accessGroup: String?

    init(accessGroup: String? = AppConstants.keychainAccessGroup) {
        self.accessGroup = accessGroup
    }

    func validateAccessGroup() throws {
        _ = try baseQuery()
    }

    /// Binds persistent Keychain credentials to this app installation.
    ///
    /// Keychain items can survive uninstall while the app's standard defaults
    /// do not. The first run after this version is installed establishes a
    /// binding without disrupting a legacy installation. Later missing or
    /// mismatched local bindings are treated as reinstall/restore and the old
    /// client credential is deleted before it can be reused.
    func prepareForCurrentInstallation(
        defaults: UserDefaults = .standard,
        allowLegacyMigration: Bool = true,
        onResetRequired: () throws -> Void = {}
    ) throws -> Bool {
        let localBinding = defaults.string(forKey: AppConstants.installationBindingKey)
        let keychainBinding = try loadData(account: AppConstants.installationBindingAccount)
            .flatMap { String(data: $0, encoding: .utf8) }
        if let localBinding, localBinding == keychainBinding {
            return false
        }

        let isLegacyMigration = allowLegacyMigration &&
            localBinding == nil && keychainBinding == nil
        if !isLegacyMigration {
            try onResetRequired()
            try delete()
        }
        let replacement = UUID().uuidString
        try saveData(
            Data(replacement.utf8),
            account: AppConstants.installationBindingAccount
        )
        defaults.set(replacement, forKey: AppConstants.installationBindingKey)
        return !isLegacyMigration
    }

    func load() throws -> ClientConfiguration? {
        guard let data = try loadData(account: AppConstants.configurationKey) else { return nil }
        do {
            return try JSONDecoder().decode(ClientConfiguration.self, from: data)
        } catch {
            throw StoreError.invalidStoredConfiguration
        }
    }

    func save(_ configuration: ClientConfiguration) throws {
        let data = try JSONEncoder().encode(configuration)
        try saveData(data, account: AppConstants.configurationKey)
    }

    func delete() throws {
        let status = SecItemDelete(try baseQuery() as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw StoreError.keychain(status) }
    }

    private func loadData(account: String) throws -> Data? {
        var query = try baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw StoreError.keychain(status)
        }
        return data
    }

    private func saveData(_ data: Data, account: String) throws {
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        let baseQuery = try baseQuery(account: account)
        let updateStatus = SecItemUpdate(baseQuery as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecSuccess { return }
        guard updateStatus == errSecItemNotFound else { throw StoreError.keychain(updateStatus) }
        var item = baseQuery
        attributes.forEach { item[$0.key] = $0.value }
        let addStatus = SecItemAdd(item as CFDictionary, nil)
        guard addStatus == errSecSuccess else { throw StoreError.keychain(addStatus) }
    }

    private func baseQuery(account: String = AppConstants.configurationKey) throws -> [String: Any] {
        guard let accessGroup,
              !accessGroup.isEmpty,
              !accessGroup.contains("$("),
              accessGroup.rangeOfCharacter(from: .whitespacesAndNewlines) == nil else {
            throw StoreError.missingKeychainAccessGroup
        }
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: false
        ]
        query[kSecAttrAccessGroup as String] = accessGroup
        return query
    }
}

enum StoreError: Error {
    case keychain(OSStatus)
    case missingKeychainAccessGroup
    case invalidStoredConfiguration
}
