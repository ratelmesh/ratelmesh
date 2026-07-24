import Foundation
import Security

struct SecureConfigurationStore: Sendable {
    private let service = "com.ratelmesh.ios.configuration"

    func load() throws -> ClientConfiguration? {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else { throw StoreError.keychain(status) }
        do {
            return try JSONDecoder().decode(ClientConfiguration.self, from: data)
        } catch {
            throw StoreError.invalidStoredConfiguration
        }
    }

    func save(_ configuration: ClientConfiguration) throws {
        let data = try JSONEncoder().encode(configuration)
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        let updateStatus = SecItemUpdate(baseQuery as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecSuccess { return }
        guard updateStatus == errSecItemNotFound else { throw StoreError.keychain(updateStatus) }
        var item = baseQuery
        attributes.forEach { item[$0.key] = $0.value }
        let addStatus = SecItemAdd(item as CFDictionary, nil)
        guard addStatus == errSecSuccess else { throw StoreError.keychain(addStatus) }
    }

    func delete() throws {
        let status = SecItemDelete(baseQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw StoreError.keychain(status) }
    }

    private var baseQuery: [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: AppConstants.configurationKey,
            kSecAttrSynchronizable as String: false
        ]
        if let group = AppConstants.keychainAccessGroup {
            query[kSecAttrAccessGroup as String] = group
        }
        return query
    }
}

enum StoreError: LocalizedError {
    case keychain(OSStatus)
    case invalidStoredConfiguration

    var errorDescription: String? {
        switch self {
        case .keychain(let status): "钥匙串操作失败（\(status)）。请检查 App 与 Extension 的 Keychain Sharing 配置。"
        case .invalidStoredConfiguration: "已保存的客户端配置无法读取，请重新配置。"
        }
    }
}

