import AppKit
import CryptoKit
import Foundation

enum ProductInfo {
    static var version: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "—"
    }

    static func openHelp() {
        guard let url = URL(string: "https://ratelmesh.com/help") else { return }
        NSWorkspace.shared.open(url)
    }
}

struct UpdateManifest: Codable, Equatable {
    let schema: Int
    let platform: String
    let version: String
    let minimumSystemVersion: String
    let url: String
    let sha256: String
    let size: Int64
    let publishedAt: String
    let signature: String
    var pqSignature: String? = nil

    var canonicalData: Data {
        let fields = [
            "schema=\(schema)",
            "platform=\(platform)",
            "version=\(version)",
            "minimumSystemVersion=\(minimumSystemVersion)",
            "url=\(url)",
            "sha256=\(sha256)",
            "size=\(size)",
            "publishedAt=\(publishedAt)",
            "",
        ]
        return Data(fields.joined(separator: "\n").utf8)
    }
}

enum UpdateSecurityError: Error {
    case malformedManifest
    case unsupportedPlatform
    case unsafeURL
    case invalidPublicKey
    case invalidSignature
    case invalidPQSignature
    case checksumMismatch
    case staleManifest
    case rollbackManifest
}

enum UpdateFailure: Equatable {
    case network
    case configuration
    case verification
    case unsupportedSystem
    case rollbackProtection
    case checksum
    case localFile
    case unknown

    static func classify(_ error: Error) -> UpdateFailure {
        if error is URLError { return .network }
        if error is DecodingError { return .verification }
        if error is CocoaError { return .localFile }
        guard let security = error as? UpdateSecurityError else { return .unknown }
        switch security {
        case .invalidPublicKey:
            return .configuration
        case .invalidSignature, .invalidPQSignature, .malformedManifest, .unsafeURL, .staleManifest:
            return .verification
        case .unsupportedPlatform:
            return .unsupportedSystem
        case .rollbackManifest:
            return .rollbackProtection
        case .checksumMismatch:
            return .checksum
        }
    }

    func message(chinese: Bool) -> String {
        switch self {
        case .network:
            return chinese ? "无法连接官方更新服务，请检查网络后重试。" : "The official update service could not be reached. Check your network and try again."
        case .configuration:
            return chinese ? "更新安全配置缺失，请重新安装 RatelMesh。" : "Update security configuration is missing. Reinstall RatelMesh."
        case .verification:
            return chinese ? "更新签名或清单验证失败，已停止更新。" : "The update manifest or signature could not be verified. The update was stopped."
        case .unsupportedSystem:
            return chinese ? "这个更新不支持当前 macOS 版本。" : "This update does not support the current macOS version."
        case .rollbackProtection:
            return chinese ? "更新版本低于已验证版本，已被回滚保护拦截。" : "Rollback protection rejected an older update version."
        case .checksum:
            return chinese ? "下载文件校验失败，请重新下载。" : "The downloaded file failed verification. Download it again."
        case .localFile:
            return chinese ? "无法保存或打开更新文件，请检查磁盘空间。" : "The update file could not be saved or opened. Check available disk space."
        case .unknown:
            return chinese ? "更新失败，请重试；如仍失败，请重新安装。" : "The update failed. Try again; if it continues, reinstall RatelMesh."
        }
    }
}

enum UpdateSecurity {
    private static let allowedHost = "download.ratelmesh.com"

    static func verify(
        _ manifest: UpdateManifest,
        publicKeyBase64: String,
        pqPublicKeyBase64: String = "",
        pqVerifierURL: URL? = nil
    ) throws {
        guard (manifest.schema == 1 || manifest.schema == 2),
              manifest.platform == "macos",
              parseVersion(manifest.version, exactSemver: true) != nil,
              parseVersion(manifest.minimumSystemVersion, exactSemver: false) != nil,
              manifest.sha256.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
              manifest.size > 0,
              manifest.size <= 1_000_000_000,
              let published = ISO8601DateFormatter().date(from: manifest.publishedAt),
              manifestIsFresh(published)
        else {
            throw UpdateSecurityError.malformedManifest
        }

        guard let packageURL = URL(string: manifest.url),
              packageURL.scheme == "https",
              packageURL.host?.lowercased() == allowedHost,
              packageURL.path == "/download/RatelMesh-macOS-\(manifest.version)-universal.pkg",
              packageURL.user == nil,
              packageURL.password == nil,
              packageURL.query == nil,
              packageURL.fragment == nil
        else {
            throw UpdateSecurityError.unsafeURL
        }

        guard let publicKeyData = Data(base64Encoded: publicKeyBase64), publicKeyData.count == 32,
              let signatureData = Data(base64Encoded: manifest.signature), signatureData.count == 64,
              let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData)
        else {
            throw UpdateSecurityError.invalidPublicKey
        }
        guard publicKey.isValidSignature(signatureData, for: manifest.canonicalData) else {
            throw UpdateSecurityError.invalidSignature
        }
        if manifest.schema >= 2 {
            guard let publicKeyData = Data(base64Encoded: pqPublicKeyBase64), publicKeyData.count == 1952,
                  let pqSignature = manifest.pqSignature,
                  let signatureData = Data(base64Encoded: pqSignature), signatureData.count == 3309,
                  let helper = pqVerifierURL ?? bundledPQVerifierURL()
            else { throw UpdateSecurityError.invalidPQSignature }
            let process = Process()
            process.executableURL = helper
            process.arguments = ["-public", pqPublicKeyBase64, "-signature", pqSignature]
            let input = Pipe()
            process.standardInput = input
            process.standardOutput = Pipe()
            process.standardError = Pipe()
            do {
                try process.run()
                input.fileHandleForWriting.write(manifest.canonicalData)
                try input.fileHandleForWriting.close()
                process.waitUntilExit()
            } catch {
                throw UpdateSecurityError.invalidPQSignature
            }
            guard process.terminationReason == .exit, process.terminationStatus == 0 else {
                throw UpdateSecurityError.invalidPQSignature
            }
        }
    }

    private static func bundledPQVerifierURL() -> URL? {
        let candidate = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/ratelmesh-pqverify")
        return FileManager.default.isExecutableFile(atPath: candidate.path) ? candidate : nil
    }

    static func manifestIsFresh(_ published: Date, now: Date = Date()) -> Bool {
        published <= now.addingTimeInterval(5 * 60)
            && published >= now.addingTimeInterval(-30 * 24 * 60 * 60)
    }

    static func compareVersions(_ lhs: String, _ rhs: String) -> ComparisonResult {
        guard let left = parseVersion(lhs, exactSemver: false),
              let right = parseVersion(rhs, exactSemver: false)
        else {
            return lhs.compare(rhs, options: .numeric)
        }
        let count = max(left.count, right.count)
        for index in 0..<count {
            let l = index < left.count ? left[index] : 0
            let r = index < right.count ? right[index] : 0
            if l < r { return .orderedAscending }
            if l > r { return .orderedDescending }
        }
        return .orderedSame
    }

    static func sha256(of fileURL: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: fileURL)
        defer { try? handle.close() }
        var hasher = SHA256()
        while let data = try handle.read(upToCount: 1_048_576), !data.isEmpty {
            hasher.update(data: data)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    static func responseIsAllowed(_ response: URLResponse) -> Bool {
        guard let responseURL = response.url else { return false }
        return responseURL.scheme == "https" && responseURL.host?.lowercased() == allowedHost
    }

    static func systemSupports(_ minimumVersion: String) -> Bool {
        let system = ProcessInfo.processInfo.operatingSystemVersion
        let current = "\(system.majorVersion).\(system.minorVersion).\(system.patchVersion)"
        return compareVersions(current, minimumVersion) != .orderedAscending
    }

    private static func parseVersion(_ value: String, exactSemver: Bool) -> [Int]? {
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        if exactSemver ? parts.count != 3 : !(2...3).contains(parts.count) { return nil }
        var result: [Int] = []
        for part in parts {
            guard !part.isEmpty,
                  part.allSatisfy(\.isNumber),
                  (part.count == 1 || part.first != "0"),
                  let number = Int(part), number <= 999_999
            else { return nil }
            result.append(number)
        }
        return result
    }
}

enum UpdatePhase: Equatable {
    case idle
    case checking
    case upToDate
    case available
    case downloading
    case ready
    case failed

    var busy: Bool { self == .checking || self == .downloading }
}

@MainActor
final class UpdateStore: ObservableObject {
    @Published var automaticUpdates: Bool {
        didSet {
            defaults.set(automaticUpdates, forKey: automaticKey)
            if automaticUpdates {
                Task { await checkIfDue(force: true) }
            }
        }
    }
    @Published private(set) var phase: UpdatePhase = .idle
    @Published private(set) var failure: UpdateFailure?
    @Published private(set) var manifest: UpdateManifest?
    @Published private(set) var downloadedPackage: URL?

    private let defaults: UserDefaults
    private let automaticKey = "updates.automatic"
    private let lastCheckKey = "updates.lastCheck"
    private let highestManifestVersionKey = "updates.highestManifestVersion"
    private let checkDueInterval: TimeInterval
    private let schedulerInitialDelay: Duration
    private let schedulerPollInterval: Duration
    private let feedURL: URL?
    private let publicKey: String
    private let pqPublicKey: String
    private let pqVerifierURL: URL?
    private let session: URLSession
    private let currentVersion: String
    private let cacheRootOverride: URL?
    private var automaticCheckTask: Task<Void, Never>?

    init(
        defaults: UserDefaults = .standard,
        feedURL: URL? = nil,
        publicKey: String? = nil,
        pqPublicKey: String? = nil,
        pqVerifierURL: URL? = nil,
        currentVersion: String? = nil,
        cacheRoot: URL? = nil,
        session: URLSession? = nil,
        scheduleAutomaticCheck: Bool = true,
        checkDueInterval: TimeInterval = 24 * 60 * 60,
        schedulerInitialDelay: Duration = .seconds(3),
        schedulerPollInterval: Duration = .seconds(60 * 60)
    ) {
        self.defaults = defaults
        if defaults.object(forKey: automaticKey) == nil {
            defaults.set(true, forKey: automaticKey)
        }
        automaticUpdates = defaults.bool(forKey: automaticKey)
        let bundledFeed = Bundle.main.object(forInfoDictionaryKey: "RatelMeshUpdateFeedURL") as? String
        self.feedURL = feedURL ?? bundledFeed.flatMap(URL.init(string:))
        self.publicKey = publicKey ?? (Bundle.main.object(forInfoDictionaryKey: "RatelMeshUpdatePublicKey") as? String ?? "")
        self.pqPublicKey = pqPublicKey ?? (Bundle.main.object(forInfoDictionaryKey: "RatelMeshUpdatePQPublicKey") as? String ?? "")
        self.pqVerifierURL = pqVerifierURL
        self.currentVersion = currentVersion ?? ProductInfo.version
        cacheRootOverride = cacheRoot
        self.checkDueInterval = checkDueInterval
        self.schedulerInitialDelay = schedulerInitialDelay
        self.schedulerPollInterval = schedulerPollInterval

        if let session {
            self.session = session
        } else {
            let configuration = URLSessionConfiguration.ephemeral
            configuration.timeoutIntervalForRequest = 20
            configuration.timeoutIntervalForResource = 120
            configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
            self.session = URLSession(configuration: configuration)
        }

        if scheduleAutomaticCheck {
            automaticCheckTask = Task { [weak self] in
                do {
                    try await Task.sleep(for: schedulerInitialDelay)
                    while !Task.isCancelled {
                        guard self != nil else { return }
                        await self?.checkIfDue(force: false)
                        try await Task.sleep(for: schedulerPollInterval)
                    }
                } catch is CancellationError {
                    return
                } catch {
                    NSLog("RatelMesh update scheduler failed: %@", String(describing: error))
                }
            }
        }
    }

    deinit {
        automaticCheckTask?.cancel()
    }

    func check(manual: Bool) async {
        guard !phase.busy, let feedURL else {
            if manual {
                failure = .configuration
                phase = .failed
            }
            return
        }
        failure = nil
        phase = .checking
        do {
            var request = URLRequest(url: feedURL)
            request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
            request.setValue("application/json", forHTTPHeaderField: "Accept")
            let (data, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse,
                  http.statusCode == 200,
                  UpdateSecurity.responseIsAllowed(response),
                  data.count <= 65_536
            else {
                throw URLError(.badServerResponse)
            }
            let candidate = try JSONDecoder().decode(UpdateManifest.self, from: data)
            try UpdateSecurity.verify(candidate, publicKeyBase64: publicKey, pqPublicKeyBase64: pqPublicKey, pqVerifierURL: pqVerifierURL)
            // An authenticated manifest that this operating system cannot
            // install must not advance its rollback floor. Publishers may need
            // to serve a lower, compatible build to this machine later.
            guard UpdateSecurity.systemSupports(candidate.minimumSystemVersion) else {
                throw UpdateSecurityError.unsupportedPlatform
            }
            if let floor = defaults.string(forKey: highestManifestVersionKey),
               UpdateSecurity.compareVersions(candidate.version, floor) == .orderedAscending {
                throw UpdateSecurityError.rollbackManifest
            }
            if let floor = defaults.string(forKey: highestManifestVersionKey) {
                if UpdateSecurity.compareVersions(floor, candidate.version) == .orderedAscending {
                    defaults.set(candidate.version, forKey: highestManifestVersionKey)
                }
            } else {
                defaults.set(candidate.version, forKey: highestManifestVersionKey)
            }
            defaults.set(Date(), forKey: lastCheckKey)
            let comparison = UpdateSecurity.compareVersions(currentVersion, candidate.version)
            guard comparison == .orderedAscending else {
                manifest = nil
                downloadedPackage = nil
                phase = manual ? .upToDate : .idle
                return
            }

            manifest = candidate
            downloadedPackage = nil
            phase = .available
            if automaticUpdates && !manual {
                await download(candidate, promptWhenReady: true)
            }
        } catch {
            NSLog("RatelMesh update check failed: %@", String(describing: error))
            failure = UpdateFailure.classify(error)
            phase = .failed
        }
    }

    func downloadAvailableUpdate() async {
        guard let manifest else { return }
        await download(manifest, promptWhenReady: false)
    }

    func installDownloadedUpdate() {
        guard let package = downloadedPackage, let manifest else { return }
        failure = nil
        do {
            guard try UpdateSecurity.sha256(of: package) == manifest.sha256 else {
                throw UpdateSecurityError.checksumMismatch
            }
            guard NSWorkspace.shared.open(package) else { throw URLError(.cannotOpenFile) }
        } catch {
            NSLog("RatelMesh update launch failed: %@", String(describing: error))
            failure = UpdateFailure.classify(error)
            phase = .failed
        }
    }

    func failureMessage(chinese: Bool) -> String {
        (failure ?? .unknown).message(chinese: chinese)
    }

    private func checkIfDue(force: Bool) async {
        guard automaticUpdates else { return }
        if !force, let lastCheck = defaults.object(forKey: lastCheckKey) as? Date,
           Date().timeIntervalSince(lastCheck) < checkDueInterval {
            return
        }
        await check(manual: false)
    }

    private func download(_ candidate: UpdateManifest, promptWhenReady: Bool) async {
        guard !phase.busy, let packageURL = URL(string: candidate.url) else { return }
        failure = nil
        phase = .downloading
        do {
            var request = URLRequest(url: packageURL)
            request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
            let (temporaryURL, response) = try await session.download(for: request)
            guard let http = response as? HTTPURLResponse,
                  http.statusCode == 200,
                  UpdateSecurity.responseIsAllowed(response)
            else {
                throw URLError(.badServerResponse)
            }
            let attributes = try FileManager.default.attributesOfItem(atPath: temporaryURL.path)
            guard (attributes[.size] as? NSNumber)?.int64Value == candidate.size,
                  try UpdateSecurity.sha256(of: temporaryURL) == candidate.sha256
            else {
                throw UpdateSecurityError.checksumMismatch
            }

            let cacheRoot: URL
            if let cacheRootOverride {
                cacheRoot = cacheRootOverride
            } else {
                cacheRoot = try FileManager.default.url(
                    for: .cachesDirectory,
                    in: .userDomainMask,
                    appropriateFor: nil,
                    create: true
                ).appendingPathComponent("com.ratelmesh.menubar/updates", isDirectory: true)
            }
            try FileManager.default.createDirectory(at: cacheRoot, withIntermediateDirectories: true)
            let destination = cacheRoot.appendingPathComponent("RatelMesh-macOS-\(candidate.version)-universal.pkg")
            if FileManager.default.fileExists(atPath: destination.path) {
                try FileManager.default.removeItem(at: destination)
            }
            try FileManager.default.moveItem(at: temporaryURL, to: destination)
            downloadedPackage = destination
            phase = .ready
            if promptWhenReady { presentInstallPrompt(version: candidate.version) }
        } catch {
            NSLog("RatelMesh update download failed: %@", String(describing: error))
            failure = UpdateFailure.classify(error)
            phase = .failed
        }
    }

    private func presentInstallPrompt(version: String) {
        let chinese = Locale.preferredLanguages.first?.lowercased().hasPrefix("zh") == true
        let alert = NSAlert()
        alert.alertStyle = .informational
        alert.messageText = chinese ? "更新已准备好" : "Update ready"
        alert.informativeText = chinese
            ? "RatelMesh v\(version) 已下载并通过签名校验。现在打开系统安装器吗？"
            : "RatelMesh v\(version) was downloaded and verified. Open the system installer now?"
        alert.addButton(withTitle: chinese ? "现在安装" : "Install now")
        alert.addButton(withTitle: chinese ? "稍后" : "Later")
        if alert.runModal() == .alertFirstButtonReturn {
            installDownloadedUpdate()
        }
    }
}
