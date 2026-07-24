import Foundation

@main
private struct UpdateStoreIntegrationTests {
    static func main() async throws {
        guard CommandLine.arguments.count == 3,
              let feedURL = URL(string: "https://download.ratelmesh.com/download/macos/latest.json")
        else { throw IntegrationFailure.arguments }

        let publicKey = CommandLine.arguments[1]
        let cacheRoot = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
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
            currentVersion: "0.1.24",
            cacheRoot: cacheRoot,
            scheduleAutomaticCheck: false
        )
        await updater.check(manual: true)
        guard updater.phase == .available,
              updater.manifest?.version == "0.2.0"
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
            currentVersion: "0.2.0",
            cacheRoot: cacheRoot,
            scheduleAutomaticCheck: false
        )
        await current.check(manual: true)
        guard current.phase == .upToDate else { throw IntegrationFailure.currentVersion }

        print("live macOS updater integration tests passed")
    }
}

private enum IntegrationFailure: Error {
    case arguments
    case defaults
    case updateNotFound
    case download
    case currentVersion
}
