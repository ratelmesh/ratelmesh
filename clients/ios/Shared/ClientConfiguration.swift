import Foundation

struct ClientConfiguration: Codable, Equatable, Sendable {
    var coordinatorURL: String
    var authKey: String
    var hostname: String

    init(coordinatorURL: String = "", authKey: String = "", hostname: String = "") {
        self.coordinatorURL = coordinatorURL
        self.authKey = authKey
        self.hostname = hostname
    }

    func validated() throws -> ClientConfiguration {
        let coordinator = coordinatorURL.trimmingCharacters(in: .whitespacesAndNewlines)
        let host = hostname.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: coordinator), let scheme = url.scheme?.lowercased(), url.host != nil else {
            throw ConfigurationError.invalidCoordinatorURL
        }
        let localHTTP = scheme == "http" && ["localhost", "127.0.0.1", "::1"].contains(url.host?.lowercased() ?? "")
        guard scheme == "https" || localHTTP else { throw ConfigurationError.insecureCoordinatorURL }
        guard !authKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw ConfigurationError.missingAuthKey
        }
        guard !host.isEmpty, host.count <= 63,
              host.range(of: #"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"#, options: .regularExpression) != nil else {
            throw ConfigurationError.invalidHostname
        }
        return ClientConfiguration(coordinatorURL: coordinator, authKey: authKey, hostname: host)
    }
}

enum ConfigurationError: LocalizedError {
    case invalidCoordinatorURL
    case insecureCoordinatorURL
    case missingAuthKey
    case invalidHostname

    var errorDescription: String? {
        switch self {
        case .invalidCoordinatorURL: "协调器地址无效。"
        case .insecureCoordinatorURL: "协调器必须使用 HTTPS；仅本机开发地址允许 HTTP。"
        case .missingAuthKey: "请输入授权密钥。"
        case .invalidHostname: "设备名只能包含字母、数字和连字符，最长 63 个字符。"
        }
    }
}

