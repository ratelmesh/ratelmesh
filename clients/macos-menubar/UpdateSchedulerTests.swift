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

@main
private struct UpdateSchedulerTests {
    @MainActor
    static func main() async throws {
        guard CommandLine.arguments.count == 5 else { throw SchedulerFailure.arguments }
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

        print("macOS updater scheduler tests passed")
    }
}

private enum SchedulerFailure: Error {
    case arguments
    case defaults
    case disabledCheck
    case noRepeatCheck
    case concurrentState
}
