import Foundation
import os

private final class UpdateFeedProtocol: URLProtocol {
    private struct State: Sendable {
        var responseData = Data()
        var requestCount = 0
    }

    private static let state = OSAllocatedUnfairLock(initialState: State())

    static func configure(with data: Data) {
        state.withLock {
            $0.responseData = data
            $0.requestCount = 0
        }
    }

    static func count() -> Int {
        state.withLock { $0.requestCount }
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let data = Self.state.withLock {
            $0.requestCount += 1
            return $0.responseData
        }

        let response = HTTPURLResponse(
            url: URL(string: "https://download.ratelmesh.com/download/macos/latest.json")!,
            statusCode: 200,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

private final class RollbackFeedProtocol: URLProtocol {
    private struct State: Sendable {
        var manifest = Data()
        var package = Data()
        var packageStatus = 200
    }

    private static let state = OSAllocatedUnfairLock(initialState: State())

    static func configure(manifest: Data, package: Data, packageStatus: Int) {
        state.withLock {
            $0.manifest = manifest
            $0.package = package
            $0.packageStatus = packageStatus
        }
    }

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let configured = Self.state.withLock { $0 }
        let isManifest = request.url?.path == "/download/macos/latest.json"
        let status = isManifest ? 200 : configured.packageStatus
        let data = isManifest ? configured.manifest : configured.package
        guard let url = request.url,
              let response = HTTPURLResponse(
                  url: url,
                  statusCode: status,
                  httpVersion: "HTTP/1.1",
                  headerFields: ["Content-Length": "\(data.count)"]
              )
        else {
            client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
            return
        }
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

@main
private struct UpdateSchedulerTests {
    @MainActor
    static func main() async throws {
        guard CommandLine.arguments.count == 8 else { throw SchedulerFailure.arguments }
        let manifestData = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
        UpdateFeedProtocol.configure(with: manifestData)

        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [UpdateFeedProtocol.self]
        let session = URLSession(configuration: configuration)
        try await withThrowingTaskGroup(of: Data.self) { group in
            for requestID in 0..<16 {
                group.addTask {
                    let url = URL(string: "https://download.ratelmesh.com/download/macos/latest.json?request=\(requestID)")!
                    return try await session.data(from: url).0
                }
            }
            for try await data in group where data != manifestData {
                throw SchedulerFailure.concurrentState
            }
        }
        guard UpdateFeedProtocol.count() == 16 else { throw SchedulerFailure.concurrentState }
        UpdateFeedProtocol.configure(with: manifestData)

        let suite = "com.ratelmesh.daemon.update-scheduler.\(UUID().uuidString)"
        guard let defaults = UserDefaults(suiteName: suite) else { throw SchedulerFailure.defaults }
        defaults.set(false, forKey: "updates.automatic")
        defer { defaults.removePersistentDomain(forName: suite) }

        let updater = UpdateStore(
            defaults: defaults,
            feedURL: URL(string: "https://download.ratelmesh.com/download/macos/latest.json")!,
            publicKey: CommandLine.arguments[2],
            pqPublicKey: CommandLine.arguments[3],
            pqVerifierURL: URL(fileURLWithPath: CommandLine.arguments[4]),
            currentVersion: "0.1.27",
            session: session,
            scheduleAutomaticCheck: true,
            checkDueInterval: 0,
            schedulerInitialDelay: .milliseconds(5),
            schedulerPollInterval: .milliseconds(10)
        )

        try await Task.sleep(for: .milliseconds(40))
        guard UpdateFeedProtocol.count() == 0 else { throw SchedulerFailure.disabledCheck }

        updater.automaticUpdates = true
        for _ in 0..<100 where UpdateFeedProtocol.count() < 2 {
            try await Task.sleep(for: .milliseconds(10))
        }
        guard UpdateFeedProtocol.count() >= 2 else { throw SchedulerFailure.noRepeatCheck }

        updater.automaticUpdates = false
        try await Task.sleep(for: .milliseconds(30))
        let stoppedCount = UpdateFeedProtocol.count()
        try await Task.sleep(for: .milliseconds(50))
        guard UpdateFeedProtocol.count() == stoppedCount else { throw SchedulerFailure.disabledCheck }

        try await testFailedHigherPackageDoesNotPinEmergencyRelease()

        print("macOS updater scheduler tests passed")
    }

    @MainActor
    private static func testFailedHigherPackageDoesNotPinEmergencyRelease() async throws {
        let baselineManifest = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
        let highManifest = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[5]))
        let emergencyManifest = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[6]))
        let package = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[7]))
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [RollbackFeedProtocol.self]
        let session = URLSession(configuration: configuration)
        defer { session.invalidateAndCancel() }

        let suite = "com.ratelmesh.daemon.update-rollback.\(UUID().uuidString)"
        guard let defaults = UserDefaults(suiteName: suite) else { throw SchedulerFailure.defaults }
        defaults.set(false, forKey: "updates.automatic")
        defaults.set("9.9.9", forKey: "updates.highestManifestVersion")
        let cacheRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("ratelmesh-rollback-\(UUID().uuidString)", isDirectory: true)
        defer {
            defaults.removePersistentDomain(forName: suite)
            try? FileManager.default.removeItem(at: cacheRoot)
        }

        let updater = UpdateStore(
            defaults: defaults,
            feedURL: URL(string: "https://download.ratelmesh.com/download/macos/latest.json")!,
            publicKey: CommandLine.arguments[2],
            pqPublicKey: CommandLine.arguments[3],
            pqVerifierURL: URL(fileURLWithPath: CommandLine.arguments[4]),
            currentVersion: "0.1.27",
            cacheRoot: cacheRoot,
            session: session,
            scheduleAutomaticCheck: false
        )
        guard defaults.string(forKey: "updates.installedVersionFloor") == "0.1.27",
              defaults.string(forKey: "updates.verifiedPackageVersionFloor") == nil,
              defaults.string(forKey: "updates.highestManifestVersion") == nil
        else { throw SchedulerFailure.rollbackFloor }

        var corruptPackage = package
        guard !corruptPackage.isEmpty else { throw SchedulerFailure.arguments }
        corruptPackage[corruptPackage.startIndex] ^= 1
        RollbackFeedProtocol.configure(manifest: highManifest, package: corruptPackage, packageStatus: 200)
        await updater.check(manual: true)
        guard updater.phase == .available else { throw SchedulerFailure.rollbackFloor }
        await updater.downloadAvailableUpdate()
        guard updater.phase == .failed,
              updater.failure == .checksum,
              defaults.string(forKey: "updates.verifiedPackageVersionFloor") == nil
        else { throw SchedulerFailure.rollbackFloor }

        RollbackFeedProtocol.configure(manifest: emergencyManifest, package: package, packageStatus: 200)
        await updater.check(manual: true)
        guard updater.phase == .available else { throw SchedulerFailure.rollbackFloor }
        await updater.downloadAvailableUpdate()
        guard updater.phase == .ready,
              defaults.string(forKey: "updates.verifiedPackageVersionFloor") == "0.1.28"
        else { throw SchedulerFailure.rollbackFloor }

        RollbackFeedProtocol.configure(manifest: baselineManifest, package: package, packageStatus: 200)
        await updater.check(manual: true)
        guard updater.phase == .failed,
              updater.failure == .rollbackProtection,
              defaults.string(forKey: "updates.verifiedPackageVersionFloor") == "0.1.28"
        else { throw SchedulerFailure.rollbackFloor }
    }
}

private enum SchedulerFailure: Error {
    case arguments
    case defaults
    case disabledCheck
    case noRepeatCheck
    case concurrentState
    case rollbackFloor
}
