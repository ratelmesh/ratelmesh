import Foundation
import Darwin

enum TunnelErrorCategory: String, Codable, Sendable {
    case configuration
    case wireGuard
    case lifecycle
    case request
    case system
    case unknown
}

enum TunnelErrorCode: String, Codable, CaseIterable, Hashable, Sendable {
    case configurationMissing = "configuration_missing"
    case appGroupUnavailable = "app_group_unavailable"
    case configurationInvalid = "configuration_invalid"
    case configurationInsecure = "configuration_insecure"
    case authenticationKeyMissing = "authentication_key_missing"
    case hostnameInvalid = "hostname_invalid"
    case configurationUnreadable = "configuration_unreadable"
    case configurationTimeout = "configuration_timeout"
    case configurationVersionMismatch = "configuration_version_mismatch"
    case tunnelConfigurationInactive = "tunnel_configuration_inactive"
    case tunnelConfigurationIncomplete = "tunnel_configuration_incomplete"
    case tunnelConfigurationMalformed = "tunnel_configuration_malformed"
    case wireGuardDescriptorUnavailable = "wireguard_descriptor_unavailable"
    case wireGuardInvalidState = "wireguard_invalid_state"
    case wireGuardDNSResolutionFailed = "wireguard_dns_resolution_failed"
    case networkSettingsRejected = "network_settings_rejected"
    case wireGuardBackendStartFailed = "wireguard_backend_start_failed"
    case tunnelCancelled = "tunnel_cancelled"
    case tunnelAlreadyActive = "tunnel_already_active"
    case tunnelForcedTeardown = "tunnel_forced_teardown"
    case invalidProviderMessage = "invalid_provider_message"
    case invalidExit = "invalid_exit"
    case unsupportedProviderAction = "unsupported_provider_action"
    case exitSelectionFailed = "exit_selection_failed"
    case vpnProfileUnavailable = "vpn_profile_unavailable"
    case keychainUnavailable = "keychain_unavailable"
    case controlCoreStartFailed = "control_core_start_failed"
    case unknownProviderError = "unknown_provider_error"

    static let systemErrorDomain = "com.ratelmesh.ios.tunnel"

    var category: TunnelErrorCategory {
        switch self {
        case .configurationMissing, .appGroupUnavailable, .configurationInvalid,
             .configurationInsecure, .authenticationKeyMissing, .hostnameInvalid,
             .configurationUnreadable, .configurationTimeout,
             .configurationVersionMismatch, .tunnelConfigurationInactive,
             .tunnelConfigurationIncomplete, .tunnelConfigurationMalformed:
            .configuration
        case .wireGuardDescriptorUnavailable, .wireGuardInvalidState,
             .wireGuardDNSResolutionFailed, .networkSettingsRejected,
             .wireGuardBackendStartFailed:
            .wireGuard
        case .tunnelCancelled, .tunnelAlreadyActive, .tunnelForcedTeardown:
            .lifecycle
        case .invalidProviderMessage, .invalidExit, .unsupportedProviderAction,
             .exitSelectionFailed:
            .request
        case .vpnProfileUnavailable, .keychainUnavailable, .controlCoreStartFailed:
            .system
        case .unknownProviderError:
            .unknown
        }
    }

    var retryable: Bool {
        switch self {
        case .configurationTimeout, .wireGuardDNSResolutionFailed,
             .networkSettingsRejected, .wireGuardBackendStartFailed,
             .tunnelCancelled, .tunnelAlreadyActive, .keychainUnavailable,
             .exitSelectionFailed, .controlCoreStartFailed, .unknownProviderError:
            true
        default:
            false
        }
    }

    var systemErrorNumber: Int {
        switch self {
        case .configurationMissing: 1001
        case .appGroupUnavailable: 1002
        case .configurationInvalid: 1003
        case .configurationInsecure: 1004
        case .authenticationKeyMissing: 1005
        case .hostnameInvalid: 1006
        case .configurationUnreadable: 1007
        case .configurationTimeout: 1008
        case .configurationVersionMismatch: 1009
        case .tunnelConfigurationInactive: 1010
        case .tunnelConfigurationIncomplete: 1011
        case .tunnelConfigurationMalformed: 1012
        case .wireGuardDescriptorUnavailable: 2001
        case .wireGuardInvalidState: 2002
        case .wireGuardDNSResolutionFailed: 2003
        case .networkSettingsRejected: 2004
        case .wireGuardBackendStartFailed: 2005
        case .tunnelCancelled: 3001
        case .tunnelAlreadyActive: 3002
        case .tunnelForcedTeardown: 3003
        case .invalidProviderMessage: 4001
        case .invalidExit: 4002
        case .unsupportedProviderAction: 4003
        case .exitSelectionFailed: 4004
        case .vpnProfileUnavailable: 5001
        case .keychainUnavailable: 5002
        case .controlCoreStartFailed: 5003
        case .unknownProviderError: 9000
        }
    }

    init?(systemError: Error) {
        let error = systemError as NSError
        guard error.domain == Self.systemErrorDomain else { return nil }
        switch error.code {
        case 1001: self = .configurationMissing
        case 1002: self = .appGroupUnavailable
        case 1003: self = .configurationInvalid
        case 1004: self = .configurationInsecure
        case 1005: self = .authenticationKeyMissing
        case 1006: self = .hostnameInvalid
        case 1007: self = .configurationUnreadable
        case 1008: self = .configurationTimeout
        case 1009: self = .configurationVersionMismatch
        case 1010: self = .tunnelConfigurationInactive
        case 1011: self = .tunnelConfigurationIncomplete
        case 1012: self = .tunnelConfigurationMalformed
        case 2001: self = .wireGuardDescriptorUnavailable
        case 2002: self = .wireGuardInvalidState
        case 2003: self = .wireGuardDNSResolutionFailed
        case 2004: self = .networkSettingsRejected
        case 2005: self = .wireGuardBackendStartFailed
        case 3001: self = .tunnelCancelled
        case 3002: self = .tunnelAlreadyActive
        case 3003: self = .tunnelForcedTeardown
        case 4001: self = .invalidProviderMessage
        case 4002: self = .invalidExit
        case 4003: self = .unsupportedProviderAction
        case 4004: self = .exitSelectionFailed
        case 5001: self = .vpnProfileUnavailable
        case 5002: self = .keychainUnavailable
        case 5003: self = .controlCoreStartFailed
        case 9000: self = .unknownProviderError
        default: return nil
        }
    }
}

protocol TunnelErrorCodeProviding {
    var tunnelErrorCode: TunnelErrorCode { get }
}

struct TunnelErrorReport: Codable, Equatable, Sendable {
    static let currentSchema = 1

    let schema: Int
    let eventID: String?
    let code: TunnelErrorCode
    let category: TunnelErrorCategory
    let retryable: Bool

    init(code: TunnelErrorCode, eventID: String? = nil) {
        schema = Self.currentSchema
        self.eventID = eventID
        self.code = code
        category = code.category
        retryable = code.retryable
    }

    static func sanitized(_ error: Error) -> TunnelErrorReport {
        let code = (error as? any TunnelErrorCodeProviding)?.tunnelErrorCode
            ?? TunnelErrorCode(systemError: error)
            ?? .unknownProviderError
        return TunnelErrorReport(code: code)
    }

    func encoded() -> Data? {
        try? JSONEncoder().encode(self)
    }

    static func decode(_ data: Data) -> TunnelErrorReport? {
        guard let report = try? JSONDecoder().decode(Self.self, from: data),
              report.schema == currentSchema,
              report.category == report.code.category,
              report.retryable == report.code.retryable,
              report.eventID == nil || canonicalEventID(report.eventID) != nil else {
            return nil
        }
        return report
    }

    static func canonicalEventID(_ value: String?) -> UUID? {
        guard let value,
              value.count == 36,
              let id = UUID(uuidString: value),
              id.uuidString == value else {
            return nil
        }
        return id
    }
}

enum TunnelErrorStore {
    private static let processLock = NSLock()

    struct Event: Equatable, Sendable {
        let id: UUID
        let code: TunnelErrorCode
        fileprivate let sequence: UInt64

        init(id: UUID, code: TunnelErrorCode, sequence: UInt64 = 0) {
            self.id = id
            self.code = code
            self.sequence = sequence
        }
    }

    static let maximumPendingEvents = 16

    private struct StoredEvent: Codable {
        let schema: Int
        let eventID: String
        let code: TunnelErrorCode
        let category: TunnelErrorCategory
        let retryable: Bool
        let sequence: UInt64

        init(code: TunnelErrorCode, id: UUID, sequence: UInt64) {
            schema = TunnelErrorReport.currentSchema
            eventID = id.uuidString
            self.code = code
            category = code.category
            retryable = code.retryable
            self.sequence = sequence
        }

        var validated: Event? {
            guard schema == TunnelErrorReport.currentSchema,
                  category == code.category,
                  retryable == code.retryable,
                  sequence > 0,
                  let id = TunnelErrorReport.canonicalEventID(eventID) else {
                return nil
            }
            return Event(id: id, code: code, sequence: sequence)
        }
    }

    private struct QueueEnvelope: Codable {
        static let currentSchema = 1
        var schema = currentSchema
        var nextSequence: UInt64
        var events: [StoredEvent]
    }

    private enum QueueError: Error {
        case lockUnavailable
        case sequenceExhausted
    }

    static func record(
        _ error: Error,
        in defaults: UserDefaults,
        containerURL: URL,
        eventID: UUID? = nil
    ) throws {
        let sanitized = TunnelErrorReport.sanitized(error)
        try withLockedQueue(in: containerURL, legacyDefaults: defaults) { queue in
            let id = eventID ?? UUID()
            guard !queue.events.contains(where: {
                $0.eventID.caseInsensitiveCompare(id.uuidString) == .orderedSame
            }) else {
                return
            }
            // One unacknowledged event per stable code prevents a repeated
            // one-second provider failure from crowding distinct errors out.
            guard !queue.events.contains(where: { $0.code == sanitized.code }),
                  queue.events.count < maximumPendingEvents else {
                return
            }
            queue.events.append(try makeStoredEvent(code: sanitized.code, id: id, queue: &queue))
        }
    }

    static func pendingEvents(from defaults: UserDefaults, containerURL: URL) throws -> [Event] {
        try withLockedQueue(in: containerURL, legacyDefaults: defaults) { queue in
            queue.events.compactMap(\.validated).sorted { $0.sequence < $1.sequence }
        }
    }

    static func acknowledge(
        _ eventID: UUID,
        in defaults: UserDefaults,
        containerURL: URL
    ) throws {
        try withLockedQueue(in: containerURL, legacyDefaults: defaults) { queue in
            queue.events.removeAll {
                $0.eventID.caseInsensitiveCompare(eventID.uuidString) == .orderedSame
            }
        }
    }

    private static func withLockedQueue<T>(
        in containerURL: URL,
        legacyDefaults: UserDefaults,
        _ body: (inout QueueEnvelope) throws -> T
    ) throws -> T {
        processLock.lock()
        defer { processLock.unlock() }

        try FileManager.default.createDirectory(
            at: containerURL,
            withIntermediateDirectories: true
        )
        let lockURL = containerURL.appendingPathComponent(AppConstants.providerErrorQueueLockFile)
        let descriptor = Darwin.open(lockURL.path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)
        guard descriptor >= 0 else { throw QueueError.lockUnavailable }
        defer { Darwin.close(descriptor) }
        var fileLock = flock()
        fileLock.l_type = Int16(F_WRLCK)
        fileLock.l_whence = Int16(SEEK_SET)
        guard Darwin.fcntl(descriptor, F_SETLKW, &fileLock) == 0 else {
            throw QueueError.lockUnavailable
        }
        defer {
            fileLock.l_type = Int16(F_UNLCK)
            _ = Darwin.fcntl(descriptor, F_SETLK, &fileLock)
        }

        let queueURL = containerURL.appendingPathComponent(AppConstants.providerErrorQueueFile)
        var queue = readQueue(at: queueURL)
        migrateLegacyEvents(from: legacyDefaults, into: &queue)
        let result = try body(&queue)
        queue.events = canonicalEvents(queue.events)
        try persist(queue, at: queueURL)
        return result
    }

    private static func readQueue(at url: URL) -> QueueEnvelope {
        guard let data = try? Data(contentsOf: url) else {
            return QueueEnvelope(nextSequence: 1, events: [])
        }
        guard let decoded = try? JSONDecoder().decode(QueueEnvelope.self, from: data),
              decoded.schema == QueueEnvelope.currentSchema else {
            return scrubbedMalformedQueue()
        }
        let canonical = canonicalEvents(decoded.events)
        guard canonical.count == decoded.events.count else {
            return scrubbedMalformedQueue()
        }
        guard canonical.last?.sequence != UInt64.max else {
            return scrubbedMalformedQueue()
        }
        let next = max(decoded.nextSequence, (canonical.last?.sequence ?? 0) + 1)
        return QueueEnvelope(nextSequence: next, events: canonical)
    }

    private static func scrubbedMalformedQueue() -> QueueEnvelope {
        QueueEnvelope(
            nextSequence: 2,
            events: [StoredEvent(code: .unknownProviderError, id: UUID(), sequence: 1)]
        )
    }

    private static func canonicalEvents(_ stored: [StoredEvent]) -> [StoredEvent] {
        var ids = Set<UUID>()
        var codes = Set<TunnelErrorCode>()
        var sequences = Set<UInt64>()
        return stored
            .sorted { $0.sequence < $1.sequence }
            .filter { value in
                guard let event = value.validated,
                      ids.insert(event.id).inserted,
                      codes.insert(event.code).inserted,
                      sequences.insert(event.sequence).inserted else {
                    return false
                }
                return true
            }
            .prefix(maximumPendingEvents)
            .map { $0 }
    }

    private static func migrateLegacyEvents(
        from defaults: UserDefaults,
        into queue: inout QueueEnvelope
    ) {
        var legacyCodes: [(TunnelErrorCode, UUID?)] = []
        for key in [AppConstants.lastProviderErrorKey, AppConstants.migratedProviderErrorKey] {
            if let data = defaults.data(forKey: key),
               let report = TunnelErrorReport.decode(data) {
                legacyCodes.append((
                    report.code,
                    TunnelErrorReport.canonicalEventID(report.eventID)
                ))
            } else if defaults.object(forKey: key) != nil {
                legacyCodes.append((.unknownProviderError, nil))
            }
        }
        if defaults.object(forKey: AppConstants.legacyLastProviderErrorKey) != nil {
            legacyCodes.append((.unknownProviderError, nil))
        }
        for (code, legacyID) in legacyCodes
            where queue.events.count < maximumPendingEvents
                && !queue.events.contains(where: { $0.code == code }) {
            guard let event = try? makeStoredEvent(
                code: code,
                id: legacyID ?? UUID(),
                queue: &queue
            ) else {
                break
            }
            queue.events.append(event)
        }
        defaults.removeObject(forKey: AppConstants.lastProviderErrorKey)
        defaults.removeObject(forKey: AppConstants.legacyLastProviderErrorKey)
        defaults.removeObject(forKey: AppConstants.migratedProviderErrorKey)
        defaults.removeObject(forKey: AppConstants.lastSeenProviderErrorEventKey)
    }

    private static func makeStoredEvent(
        code: TunnelErrorCode,
        id: UUID,
        queue: inout QueueEnvelope
    ) throws -> StoredEvent {
        guard queue.nextSequence > 0, queue.nextSequence < UInt64.max else {
            throw QueueError.sequenceExhausted
        }
        let event = StoredEvent(code: code, id: id, sequence: queue.nextSequence)
        queue.nextSequence += 1
        return event
    }

    private static func persist(_ queue: QueueEnvelope, at url: URL) throws {
        let data = try JSONEncoder().encode(queue)
        try data.write(to: url, options: .atomic)
        try FileManager.default.setAttributes(
            [.posixPermissions: NSNumber(value: 0o600)],
            ofItemAtPath: url.path
        )
    }
}

struct TunnelErrorPresentationQueue: Sendable {
    struct Item: Equatable, Sendable {
        let code: TunnelErrorCode
        let providerEventID: UUID?
    }

    private(set) var current: Item?
    private var pending: [Item] = []

    mutating func enqueueProvider(_ event: TunnelErrorStore.Event) {
        let item = Item(code: event.code, providerEventID: event.id)
        guard !contains(providerEventID: event.id) else { return }
        enqueue(item)
    }

    mutating func enqueueLocal(_ code: TunnelErrorCode) {
        let item = Item(code: code, providerEventID: nil)
        guard current != item, !pending.contains(item) else { return }
        enqueue(item)
    }

    @discardableResult
    mutating func acknowledgeCurrent() -> UUID? {
        let acknowledged = current?.providerEventID
        current = pending.isEmpty ? nil : pending.removeFirst()
        return acknowledged
    }

    private mutating func enqueue(_ item: Item) {
        if current == nil {
            current = item
        } else {
            pending.append(item)
        }
    }

    private func contains(providerEventID: UUID) -> Bool {
        current?.providerEventID == providerEventID
            || pending.contains { $0.providerEventID == providerEventID }
    }
}

extension ConfigurationError: TunnelErrorCodeProviding {
    var tunnelErrorCode: TunnelErrorCode {
        switch self {
        case .invalidCoordinatorURL: .configurationInvalid
        case .insecureCoordinatorURL: .configurationInsecure
        case .missingAuthKey: .authenticationKeyMissing
        case .invalidHostname: .hostnameInvalid
        }
    }
}

extension StoreError: TunnelErrorCodeProviding {
    var tunnelErrorCode: TunnelErrorCode {
        switch self {
        case .keychain, .missingKeychainAccessGroup: .keychainUnavailable
        case .invalidStoredConfiguration: .configurationUnreadable
        }
    }
}

extension MobileConfigurationError: TunnelErrorCodeProviding {
    var tunnelErrorCode: TunnelErrorCode {
        switch self {
        case .inactive: .tunnelConfigurationInactive
        case .missingInterface: .tunnelConfigurationIncomplete
        case .invalidCIDR, .invalidField: .tunnelConfigurationMalformed
        }
    }
}
