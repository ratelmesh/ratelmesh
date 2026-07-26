import Foundation

/// Serializes asynchronous WireGuard start/update/stop operations.
///
/// PacketTunnel polls the control core once per second, while WireGuard adapter
/// operations complete asynchronously. Without a gate, the same configuration
/// can be submitted repeatedly before the first callback arrives.
struct TunnelApplyGate: Sendable {
    private(set) var appliedVersion: UInt64 = 0
    private(set) var inFlightVersion: UInt64?

    mutating func begin(version: UInt64) -> Bool {
        guard version > appliedVersion, inFlightVersion == nil else { return false }
        inFlightVersion = version
        return true
    }

    mutating func finish(version: UInt64, succeeded: Bool) {
        guard inFlightVersion == version else { return }
        inFlightVersion = nil
        if succeeded {
            appliedVersion = max(appliedVersion, version)
        }
    }

    mutating func reset() {
        appliedVersion = 0
        inFlightVersion = nil
    }
}

/// Invalidates callbacks from an earlier provider lifecycle without relying on
/// callback arrival order.
struct TunnelLifecycleGeneration: Sendable {
    private(set) var value: UInt64 = 0
    private(set) var isClosing = true
    private(set) var isTerminal = false
    var canBegin: Bool { isClosing && !isTerminal }

    @discardableResult
    mutating func begin() -> UInt64 {
        precondition(canBegin, "a terminal tunnel provider cannot be restarted")
        value &+= 1
        isClosing = false
        return value
    }

    mutating func invalidate() {
        value &+= 1
        isClosing = true
    }

    mutating func markTerminal() {
        value &+= 1
        isClosing = true
        isTerminal = true
    }

    func accepts(_ generation: UInt64) -> Bool {
        !isClosing && !isTerminal && generation == value
    }
}

struct RuntimeStatsReadGate: Sendable {
    struct Token: Equatable, Sendable {
        fileprivate let generation: UInt64
        fileprivate let sequence: UInt64
    }

    private var sequence: UInt64 = 0
    private var inFlight: Token?

    mutating func begin(generation: UInt64) -> Token? {
        guard inFlight == nil else { return nil }
        sequence &+= 1
        let token = Token(generation: generation, sequence: sequence)
        inFlight = token
        return token
    }

    mutating func finish(_ token: Token, currentGeneration: UInt64) -> Bool {
        guard inFlight == token else { return false }
        inFlight = nil
        return token.generation == currentGeneration
    }

    mutating func invalidate() {
        inFlight = nil
        sequence &+= 1
    }
}
