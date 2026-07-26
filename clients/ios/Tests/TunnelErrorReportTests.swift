import Foundation
import XCTest
#if SWIFT_PACKAGE
@testable import RatelMeshShared
#else
@testable import RatelMesh
#endif

final class TunnelErrorReportTests: XCTestCase {
    private struct DynamicSecretError: Error {}

    func testStableReportsRoundTripForEveryCode() throws {
        for code in TunnelErrorCode.allCases {
            let report = TunnelErrorReport(code: code)
            let data = try XCTUnwrap(report.encoded())
            XCTAssertEqual(TunnelErrorReport.decode(data), report)
            XCTAssertLessThan(data.count, 256)
        }
    }

    func testSchemaOneReportWithoutEventIDRemainsDecodable() throws {
        let legacy = Data(
            #"{"schema":1,"code":"configuration_timeout","category":"configuration","retryable":true}"#.utf8
        )
        let report = try XCTUnwrap(TunnelErrorReport.decode(legacy))
        XCTAssertEqual(report.code, .configurationTimeout)
        XCTAssertNil(report.eventID)
    }

    func testEventIDMustBeCanonicalUUIDWhenPresent() throws {
        let validID = UUID(uuidString: "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE")!
        let valid = try XCTUnwrap(TunnelErrorReport(
            code: .configurationTimeout,
            eventID: validID.uuidString
        ).encoded())
        XCTAssertEqual(TunnelErrorReport.decode(valid)?.eventID, validID.uuidString)

        for invalid in [
            "event-1",
            "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE-extra",
            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "secret-token",
        ] {
            let data = try XCTUnwrap(TunnelErrorReport(
                code: .configurationTimeout,
                eventID: invalid
            ).encoded())
            XCTAssertNil(TunnelErrorReport.decode(data))
        }
    }

    func testStrictSystemErrorReverseMappingForEveryCode() {
        let numbers = Set(TunnelErrorCode.allCases.map(\.systemErrorNumber))
        XCTAssertEqual(numbers.count, TunnelErrorCode.allCases.count)

        for code in TunnelErrorCode.allCases {
            let error = NSError(
                domain: TunnelErrorCode.systemErrorDomain,
                code: code.systemErrorNumber,
                userInfo: [NSLocalizedDescriptionKey: "fixed"]
            )
            XCTAssertEqual(TunnelErrorReport.sanitized(error).code, code)
        }

        let wrongDomain = NSError(
            domain: "com.example.untrusted",
            code: TunnelErrorCode.tunnelForcedTeardown.systemErrorNumber
        )
        XCTAssertEqual(TunnelErrorReport.sanitized(wrongDomain).code, .unknownProviderError)

        let unknownNumber = NSError(domain: TunnelErrorCode.systemErrorDomain, code: 8_888)
        XCTAssertEqual(TunnelErrorReport.sanitized(unknownNumber).code, .unknownProviderError)
    }

    func testDynamicErrorDetailsNeverEnterReport() throws {
        let secrets = [
            "203.0.113.9:51820",
            "https://coord.example/private",
            "/var/mobile/Containers/secret",
            "enrollment-token-value",
            "host.example\nInjected",
        ]
        for secret in secrets {
            let error = NSError(
                domain: secret,
                code: 7,
                userInfo: [
                    NSLocalizedDescriptionKey: secret,
                    NSFilePathErrorKey: secret,
                    NSURLErrorKey: URL(string: "https://coord.example/private") as Any,
                ]
            )
            let data = try XCTUnwrap(TunnelErrorReport.sanitized(error).encoded())
            let encoded = String(decoding: data, as: UTF8.self)
            XCTAssertEqual(TunnelErrorReport.decode(data)?.code, .unknownProviderError)
            for value in secrets {
                XCTAssertFalse(encoded.contains(value), "report leaked dynamic value: \(value)")
            }
        }

        let malformed = MobileConfigurationError.invalidField(secrets.joined(separator: "|"))
        let encoded = String(decoding: try XCTUnwrap(TunnelErrorReport.sanitized(malformed).encoded()), as: UTF8.self)
        XCTAssertEqual(TunnelErrorReport.sanitized(malformed).code, .tunnelConfigurationMalformed)
        for secret in secrets {
            XCTAssertFalse(encoded.contains(secret))
        }
    }

    func testUnknownAndLegacyStoreMigrationNeverReturnsStoredText() throws {
        try withStore { defaults, container in
            let legacySecret = "endpoint=203.0.113.9:51820 token=secret"
            defaults.set(legacySecret, forKey: AppConstants.legacyLastProviderErrorKey)
            let legacy = try XCTUnwrap(TunnelErrorStore.pendingEvents(
                from: defaults,
                containerURL: container
            ).first)
            XCTAssertEqual(legacy.code, .unknownProviderError)
            XCTAssertNil(defaults.object(forKey: AppConstants.legacyLastProviderErrorKey))
            XCTAssertNil(defaults.object(forKey: AppConstants.lastProviderErrorKey))
            XCTAssertFalse(storedDefaultsText(defaults).contains(legacySecret))
            let queue = try queueText(container)
            XCTAssertFalse(queue.contains(legacySecret))
            XCTAssertTrue(queue.contains(legacy.id.uuidString))
        }
    }

    func testProducerBeforeObserveQueuesMultipleSanitizedEventsAcrossRestart() throws {
        try withStore { defaults, container in
            let secret = "https://secret.example/path?token=value"
            let firstID = UUID(uuidString: "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE")!
            let secondID = UUID(uuidString: "11111111-2222-4333-8444-555555555555")!
            try TunnelErrorStore.record(
                NSError(domain: "private", code: 1, userInfo: [NSLocalizedDescriptionKey: secret]),
                in: defaults,
                containerURL: container,
                eventID: firstID
            )
            try TunnelErrorStore.record(
                NSError(domain: TunnelErrorCode.systemErrorDomain, code: 2003),
                in: defaults,
                containerURL: container,
                eventID: secondID
            )

            let firstRead = try TunnelErrorStore.pendingEvents(from: defaults, containerURL: container)
            let afterRestart = try TunnelErrorStore.pendingEvents(from: defaults, containerURL: container)
            XCTAssertEqual(firstRead.map(\.id), [firstID, secondID])
            XCTAssertEqual(afterRestart, firstRead)
            XCTAssertFalse(try queueText(container).contains(secret))
        }
    }

    func testAcknowledgementDeletesOnlyItsExactUUID() throws {
        try withStore { defaults, container in
            let firstID = UUID(uuidString: "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE")!
            let secondID = UUID(uuidString: "11111111-2222-4333-8444-555555555555")!
            try TunnelErrorStore.record(
                NSError(domain: TunnelErrorCode.systemErrorDomain, code: 1008),
                in: defaults,
                containerURL: container,
                eventID: firstID
            )
            try TunnelErrorStore.record(
                NSError(domain: TunnelErrorCode.systemErrorDomain, code: 2003),
                in: defaults,
                containerURL: container,
                eventID: secondID
            )
            try TunnelErrorStore.acknowledge(firstID, in: defaults, containerURL: container)
            XCTAssertEqual(
                try TunnelErrorStore.pendingEvents(from: defaults, containerURL: container).map(\.id),
                [secondID]
            )
            try TunnelErrorStore.acknowledge(UUID(), in: defaults, containerURL: container)
            XCTAssertEqual(
                try TunnelErrorStore.pendingEvents(from: defaults, containerURL: container).map(\.id),
                [secondID]
            )
        }
    }

    func testRepeatedCodeAndUUIDAreDeduplicatedAndQueueIsBounded() throws {
        try withStore { defaults, container in
            let duplicateID = UUID(uuidString: "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE")!
            let codes = Array(TunnelErrorCode.allCases.prefix(TunnelErrorStore.maximumPendingEvents + 1))
            for (index, code) in codes.enumerated() {
                try TunnelErrorStore.record(
                    NSError(domain: TunnelErrorCode.systemErrorDomain, code: code.systemErrorNumber),
                    in: defaults,
                    containerURL: container,
                    eventID: index == 0 ? duplicateID : UUID()
                )
            }
            try TunnelErrorStore.record(
                NSError(domain: TunnelErrorCode.systemErrorDomain, code: codes[0].systemErrorNumber),
                in: defaults,
                containerURL: container,
                eventID: duplicateID
            )
            let pending = try TunnelErrorStore.pendingEvents(from: defaults, containerURL: container)
            XCTAssertEqual(pending.count, TunnelErrorStore.maximumPendingEvents)
            XCTAssertEqual(pending.first?.id, duplicateID)
            XCTAssertEqual(Set(pending.map(\.id)).count, pending.count)
            XCTAssertEqual(Set(pending.map(\.code)).count, pending.count)
        }
    }

    func testMalformedQueueMigrationCannotEraseConcurrentProviderWrite() throws {
        try withStore { defaults, container in
            let secret = "malformed-secret-token"
            try Data(#"{"schema":99,"secret":"\#(secret)"}"#.utf8).write(
                to: container.appendingPathComponent(AppConstants.providerErrorQueueFile)
            )
            let eventID = UUID(uuidString: "11111111-2222-4333-8444-555555555555")!
            let group = DispatchGroup()
            let errors = LockedErrors()
            let sendableDefaults = SendableDefaults(defaults)
            group.enter()
            DispatchQueue.global().async {
                defer { group.leave() }
                do {
                    _ = try TunnelErrorStore.pendingEvents(
                        from: sendableDefaults.value,
                        containerURL: container
                    )
                } catch {
                    errors.append(error)
                }
            }
            group.enter()
            DispatchQueue.global().async {
                defer { group.leave() }
                do {
                    try TunnelErrorStore.record(
                        NSError(domain: TunnelErrorCode.systemErrorDomain, code: 2003),
                        in: sendableDefaults.value,
                        containerURL: container,
                        eventID: eventID
                    )
                } catch {
                    errors.append(error)
                }
            }
            XCTAssertEqual(group.wait(timeout: .now() + 5), .success)
            XCTAssertTrue(errors.values.isEmpty)
            let pending = try TunnelErrorStore.pendingEvents(from: defaults, containerURL: container)
            XCTAssertTrue(pending.contains { $0.id == eventID })
            XCTAssertFalse(try queueText(container).contains(secret))
        }
    }

    func testProviderSourceNeverClearsUnacknowledgedEventsOnSuccess() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let provider = try String(
            contentsOf: iosRoot.appendingPathComponent("PacketTunnel/PacketTunnelProvider.swift"),
            encoding: .utf8
        )
        XCTAssertFalse(provider.contains("clearProviderError"))
        XCTAssertFalse(provider.contains("TunnelErrorStore.clear"))
    }

    func testPresentationQueueAcknowledgesOnlyCurrentProviderEvent() throws {
        let firstID = UUID(uuidString: "AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE")!
        let secondID = UUID(uuidString: "11111111-2222-4333-8444-555555555555")!
        var queue = TunnelErrorPresentationQueue()

        queue.enqueueProvider(.init(id: firstID, code: .configurationTimeout))
        queue.enqueueProvider(.init(id: firstID, code: .configurationTimeout))
        queue.enqueueLocal(.appGroupUnavailable)
        queue.enqueueProvider(.init(id: secondID, code: .wireGuardDNSResolutionFailed))

        XCTAssertEqual(queue.current?.code, .configurationTimeout)
        XCTAssertEqual(queue.acknowledgeCurrent(), firstID)
        XCTAssertEqual(queue.current?.code, .appGroupUnavailable)
        XCTAssertNil(queue.acknowledgeCurrent())
        XCTAssertEqual(queue.current?.code, .wireGuardDNSResolutionFailed)
        XCTAssertEqual(queue.acknowledgeCurrent(), secondID)
        XCTAssertNil(queue.current)
    }

    func testUnavailableSharedSuiteNeverFallsBackToStandardDefaults() {
        let resolved = AppConstants.makeSharedDefaults(
            suiteName: "group.test.invalid",
            factory: { _ in nil }
        )
        XCTAssertNil(resolved)
    }

    func testMissingKeychainAccessGroupFailsBeforeSecurityAPICall() {
        XCTAssertThrowsError(try SecureConfigurationStore(accessGroup: nil).validateAccessGroup()) {
            guard case StoreError.missingKeychainAccessGroup = $0 else {
                return XCTFail("unexpected error: \($0)")
            }
        }
        XCTAssertThrowsError(
            try SecureConfigurationStore(accessGroup: "$(AppIdentifierPrefix)com.example").validateAccessGroup()
        )
    }

private final class LockedErrors: @unchecked Sendable {
        private let lock = NSLock()
        private var storage: [Error] = []

        var values: [Error] {
            lock.lock()
            defer { lock.unlock() }
            return storage
        }

        func append(_ error: Error) {
            lock.lock()
            storage.append(error)
            lock.unlock()
        }
    }

    private func withStore(_ body: (UserDefaults, URL) throws -> Void) throws {
        let suite = "TunnelErrorReportTests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
        let container = FileManager.default.temporaryDirectory
            .appendingPathComponent("TunnelErrorReportTests.\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: container, withIntermediateDirectories: true)
        defer {
            defaults.removePersistentDomain(forName: suite)
            try? FileManager.default.removeItem(at: container)
        }
        try body(defaults, container)
    }

    private func queueText(_ container: URL) throws -> String {
        let data = try Data(contentsOf: container.appendingPathComponent(
            AppConstants.providerErrorQueueFile
        ))
        return String(decoding: data, as: UTF8.self)
    }

    private func storedDefaultsText(_ defaults: UserDefaults) -> String {
        [
            AppConstants.lastProviderErrorKey,
            AppConstants.legacyLastProviderErrorKey,
            AppConstants.migratedProviderErrorKey,
        ]
        .compactMap { defaults.object(forKey: $0) }
        .map { value in
            if let data = value as? Data {
                return String(decoding: data, as: UTF8.self)
            }
            return String(describing: value)
        }
        .joined(separator: "|")
    }
}

private final class SendableDefaults: @unchecked Sendable {
    let value: UserDefaults

    init(_ value: UserDefaults) {
        self.value = value
    }
}
