import Foundation

@main
private struct UpdateStoreIntegrationTests {
    static func main() async throws {
        switch CommandLine.arguments.dropFirst().first {
        case "verify-manifest":
            guard CommandLine.arguments.count == 6 else {
                throw IntegrationFailure.arguments
            }
            let manifest = try verifiedManifest(
                at: URL(fileURLWithPath: CommandLine.arguments[2]),
                publicKey: CommandLine.arguments[3],
                pqPublicKey: CommandLine.arguments[4],
                pqVerifierURL: URL(fileURLWithPath: CommandLine.arguments[5])
            )
            print(manifest.version)
        case "run":
            try await run()
        default:
            throw IntegrationFailure.arguments
        }
    }

    @MainActor
    private static func run() async throws {
        guard CommandLine.arguments.count == 8,
              let feedURL = URL(string: "https://download.ratelmesh.com/download/macos/latest.json")
        else { throw IntegrationFailure.arguments }

        let manifestURL = URL(fileURLWithPath: CommandLine.arguments[2])
        let publicKey = CommandLine.arguments[3]
        let pqPublicKey = CommandLine.arguments[4]
        let pqVerifierURL = URL(fileURLWithPath: CommandLine.arguments[5])
        let expectedVersion = CommandLine.arguments[6]
        let cacheRoot = URL(fileURLWithPath: CommandLine.arguments[7], isDirectory: true)
        let expectedManifest = try verifiedManifest(
            at: manifestURL,
            publicKey: publicKey,
            pqPublicKey: pqPublicKey,
            pqVerifierURL: pqVerifierURL
        )
        guard expectedManifest.version == expectedVersion else {
            throw IntegrationFailure.manifestChanged
        }

        let suite = "com.ratelmesh.daemon.update-integration.\(UUID().uuidString)"
        guard let defaults = UserDefaults(suiteName: suite) else { throw IntegrationFailure.defaults }
        defaults.set(false, forKey: "updates.automatic")
        defer {
            defaults.removePersistentDomain(forName: suite)
            try? FileManager.default.removeItem(at: cacheRoot)
        }

        let updater = UpdateStore(
            defaults: defaults,
            feedURL: feedURL,
            publicKey: publicKey,
            pqPublicKey: pqPublicKey,
            pqVerifierURL: pqVerifierURL,
            currentVersion: "0.0.0",
            cacheRoot: cacheRoot,
            scheduleAutomaticCheck: false
        )
        await updater.check(manual: true)
        guard updater.phase == .available,
              updater.manifest == expectedManifest
        else { throw IntegrationFailure.updateNotFound }

        await updater.downloadAvailableUpdate()
        guard updater.phase == .ready,
              let packageURL = updater.downloadedPackage,
              FileManager.default.fileExists(atPath: packageURL.path),
              let manifest = updater.manifest,
              try UpdateSecurity.sha256(of: packageURL) == manifest.sha256
        else { throw IntegrationFailure.download }

        let current = UpdateStore(
            defaults: defaults,
            feedURL: feedURL,
            publicKey: publicKey,
            pqPublicKey: pqPublicKey,
            pqVerifierURL: pqVerifierURL,
            currentVersion: expectedVersion,
            cacheRoot: cacheRoot,
            scheduleAutomaticCheck: false
        )
        await current.check(manual: true)
        guard current.phase == .upToDate else { throw IntegrationFailure.currentVersion }

        print("live macOS updater integration tests passed")
    }

    private static func verifiedManifest(
        at manifestURL: URL,
        publicKey: String,
        pqPublicKey: String,
        pqVerifierURL: URL
    ) throws -> UpdateManifest {
        guard FileManager.default.isExecutableFile(atPath: pqVerifierURL.path) else {
            throw IntegrationFailure.pqVerifier
        }
        let attributes = try FileManager.default.attributesOfItem(atPath: manifestURL.path)
        guard let size = attributes[.size] as? NSNumber, size.intValue <= 65_536 else {
            throw IntegrationFailure.manifestSize
        }
        let data = try Data(contentsOf: manifestURL, options: .mappedIfSafe)
        guard !data.isEmpty, data.count <= 65_536 else {
            throw IntegrationFailure.manifestSize
        }
        let manifest = try JSONDecoder().decode(UpdateManifest.self, from: data)
        try UpdateSecurity.verify(
            manifest,
            publicKeyBase64: publicKey,
            pqPublicKeyBase64: pqPublicKey,
            pqVerifierURL: pqVerifierURL
        )
        return manifest
    }
}

private enum IntegrationFailure: Error {
    case arguments
    case defaults
    case updateNotFound
    case download
    case currentVersion
    case manifestChanged
    case manifestSize
    case pqVerifier
}
