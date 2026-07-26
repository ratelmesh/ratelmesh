import Foundation
import NetworkExtension
import OSLog
import WireGuardKit

private final class SendableCallback<Value>: @unchecked Sendable {
    private let callback: (Value) -> Void

    init(_ callback: @escaping (Value) -> Void) {
        self.callback = callback
    }

    func call(_ value: Value) {
        callback(value)
    }
}

final class PacketTunnelProvider: NEPacketTunnelProvider, @unchecked Sendable {
    private enum AdapterOperation: Equatable {
        case start
        case update
        case deactivate
    }

    private let queue = DispatchQueue(label: "com.ratelmesh.ios.packet-tunnel")
    private let logger = Logger(subsystem: "com.ratelmesh.ios", category: "PacketTunnel")
    private lazy var adapter = WireGuardAdapter(with: self) { [logger] level, message in
        switch level {
        case .error: logger.error("\(message, privacy: .private)")
        case .verbose: logger.debug("\(message, privacy: .private)")
        }
    }

    private var core: RatelMeshMobileClient?
    private var pollTimer: DispatchSourceTimer?
    private var initialTimeout: DispatchSourceTimer?
    private var applyGate = TunnelApplyGate()
    private var adapterStarted = false
    private var startCompletion: SendableCallback<Error?>?
    private var stopCompletions: [SendableCallback<Void>] = []
    private var closingWatchdog: DispatchSourceTimer?
    private var forcedTeardownWatchdog: DispatchSourceTimer?
    private var lastRequestedExit: String?
    private var statsReadGate = RuntimeStatsReadGate()
    private var lifecycle = TunnelLifecycleGeneration()
    private var adapterOperation: (kind: AdapterOperation, generation: UInt64)?
    private var adapterStopInFlight = false
    private var sharedDefaults: UserDefaults?
    private var sharedContainerURL: URL?

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let completion = SendableCallback(completionHandler)
        queue.async {
            guard self.core == nil,
                  self.startCompletion == nil,
                  !self.adapterStarted,
                  self.adapterOperation == nil,
                  !self.adapterStopInFlight,
                  self.stopCompletions.isEmpty,
                  self.lifecycle.canBegin
            else {
                completion.call(self.systemError(for: ProviderError.alreadyActive))
                return
            }
            do {
                self.lifecycle.begin()
                self.statsReadGate.invalidate()
                self.applyGate.reset()
                self.sharedDefaults = nil
                self.sharedContainerURL = nil
                guard let defaults = AppConstants.sharedDefaults,
                      let container = AppConstants.sharedContainerURL else {
                    throw ProviderError.missingAppGroup
                }
                guard AppConstants.keychainAccessGroup != nil else {
                    throw ProviderError.missingKeychainGroup
                }
                try SecureConfigurationStore().validateAccessGroup()
                self.sharedDefaults = defaults
                self.sharedContainerURL = container
                guard !AppConstants.enrollmentResetIsPending(in: container) else {
                    throw ProviderError.enrollmentResetPending
                }
                let configuration = try SecureConfigurationStore().load()?.validated()
                guard let configuration else { throw ProviderError.missingConfiguration }
                let state = try DeviceStateDirectory.prepare(in: container)
                let core = try RatelMeshMobileClient(configuration: configuration, stateDirectory: state)
                self.core = core
                self.startCompletion = completion
                core.start()
                self.startPolling()
                self.startInitialTimeout()
            } catch {
                self.invalidateLifecycle()
                self.recordProviderError(error)
                completion.call(self.systemError(for: error))
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        let completion = SendableCallback<Void> { completionHandler() }
        queue.async {
            if self.lifecycle.isClosing {
                if self.lifecycle.isTerminal {
                    if self.forcedTeardownWatchdog != nil {
                        self.stopCompletions.append(completion)
                    } else {
                        completion.call(())
                    }
                    return
                }
                if self.adapterOperation == nil, !self.adapterStopInFlight, !self.adapterStarted {
                    completion.call(())
                } else {
                    self.stopCompletions.append(completion)
                    self.startClosingWatchdogIfNeeded()
                }
                return
            }
            self.stopCompletions.append(completion)
            self.stopTimers()
            self.invalidateLifecycle()
            self.startClosingWatchdogIfNeeded()
            if let startCompletion = self.startCompletion {
                self.startCompletion = nil
                startCompletion.call(self.systemError(for: ProviderError.cancelled))
            }
            self.core?.stop()
            self.core = nil
            guard self.adapterOperation == nil else { return }
            self.stopAdapterForClosing(force: self.adapterStarted)
        }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        let completion = completionHandler.map(SendableCallback.init)
        queue.async {
            guard let object = try? JSONSerialization.jsonObject(with: messageData) as? [String: Any],
                  let action = object["action"] as? String else {
                completion?.call(self.response(ok: false, code: .invalidProviderMessage))
                return
            }
            guard self.lifecycle.accepts(self.lifecycle.value),
                  let core = self.core else {
                completion?.call(self.response(ok: false, code: .tunnelCancelled))
                return
            }
            do {
                switch action {
                case "status":
                    completion?.call(core.statusJSON.data(using: .utf8))
                    return
                case "useExit":
                    guard let name = object["name"] as? String, !name.isEmpty else { throw ProviderError.invalidExit }
                    try core.useExit(name)
                    self.lastRequestedExit = name
                case "clearExit":
                    try core.useExit("")
                    self.lastRequestedExit = ""
                case "networkDoctorDiagnose":
                    guard object["confirmed"] as? String == "true",
                          let disclosure = object["disclosureVersion"] as? String,
                          disclosure == core.doctorDisclosureVersion else {
                        throw ProviderError.unknownAction
                    }
                    let result = try core.runNetworkDoctor(disclosure, confirmed: true)
                    completion?.call(result.data(using: .utf8))
                    return
                case "networkDoctorExecute":
                    guard object["confirmed"] as? String == "true",
                          let disclosure = object["disclosureVersion"] as? String,
                          disclosure == core.doctorDisclosureVersion,
                          let planID = object["planID"] as? String,
                          let repairAction = object["repairAction"] as? String else {
                        throw ProviderError.unknownAction
                    }
                    let result = try core.applyNetworkDoctorRepair(
                        planID,
                        action: repairAction,
                        disclosureVersion: disclosure,
                        confirmed: true
                    )
                    completion?.call(result.data(using: .utf8))
                    return
				case "setSystemLocation":
					guard let latText = object["latitude"] as? String,
						  let lonText = object["longitude"] as? String,
						  let latitude = Double(latText), let longitude = Double(lonText) else {
						throw ProviderError.unknownAction
					}
					try core.setSystemLocation(latitude: latitude, longitude: longitude)
                default:
                    throw ProviderError.unknownAction
                }
                self.pollOnce()
                completion?.call(self.response(ok: true))
            } catch {
                completion?.call(self.response(ok: false, code: TunnelErrorReport.sanitized(error).code))
            }
        }
    }

    private func startPolling() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now(), repeating: .seconds(1), leeway: .milliseconds(150))
        timer.setEventHandler { [weak self] in self?.pollOnce() }
        pollTimer = timer
        timer.resume()
    }

    private func pollOnce() {
        guard let core else { return }
        persistStatus(core.statusJSON)
        reportRuntimeStats(core)
        applyDesiredExitIfNeeded(core)
        let version = core.tunnelConfigurationVersion
        guard applyGate.begin(version: version) else { return }
        do {
            let data = Data(core.tunnelConfigurationJSON.utf8)
            let mobile = try JSONDecoder().decode(MobileTunnelConfiguration.self, from: data)
            guard mobile.version == version else { throw ProviderError.configurationVersionMismatch }
            guard mobile.active else {
                deactivateAdapter(version: version)
                return
            }
            let configuration = try mobile.wireGuardConfiguration()
            if adapterStarted {
                let generation = lifecycle.value
                adapterOperation = (.update, generation)
                adapter.update(tunnelConfiguration: configuration) { [weak self] error in
                    guard let self else { return }
                    self.queue.async { self.finishApply(version: version, generation: generation, error: error) }
                }
            } else {
                let generation = lifecycle.value
                adapterOperation = (.start, generation)
                adapter.start(tunnelConfiguration: configuration) { [weak self] error in
                    guard let self else { return }
                    self.queue.async { self.finishInitialStart(version: version, generation: generation, error: error) }
                }
            }
        } catch {
            applyGate.finish(version: version, succeeded: false)
            if !adapterStarted, startCompletion != nil {
                failInitialStart(error)
            } else {
                recordProviderError(error)
            }
        }
    }

    private func reportRuntimeStats(_ core: RatelMeshMobileClient) {
        let generation = lifecycle.value
        guard adapterStarted, lifecycle.accepts(generation),
              adapterOperation?.kind != .deactivate,
              let token = statsReadGate.begin(generation: generation) else { return }
        adapter.getRuntimeConfiguration { [weak self, core] runtime in
            guard let self else { return }
            self.queue.async {
                guard self.statsReadGate.finish(token, currentGeneration: self.lifecycle.value),
                      self.lifecycle.accepts(generation),
                      self.core === core,
                      self.adapterStarted,
                      self.adapterOperation?.kind != .deactivate,
                      let runtime else { return }
                core.updatePeerStats(WireGuardRuntimeStats.decode(runtime))
            }
        }
    }

    private func finishInitialStart(version: UInt64, generation: UInt64, error: WireGuardAdapterError?) {
        guard finishAdapterOperation(.start, generation: generation) else {
            finishStaleAdapterOperation(.start, generation: generation, error: error)
            return
        }
        if let error {
            applyGate.finish(version: version, succeeded: false)
            failInitialStart(error)
            return
        }
        adapterStarted = true
        applyGate.finish(version: version, succeeded: true)
        initialTimeout?.cancel()
        initialTimeout = nil
        startCompletion?.call(nil)
        startCompletion = nil
    }

    private func finishApply(version: UInt64, generation: UInt64, error: WireGuardAdapterError?) {
        guard finishAdapterOperation(.update, generation: generation) else {
            finishStaleAdapterOperation(.update, generation: generation, error: error)
            return
        }
        if let error {
            applyGate.finish(version: version, succeeded: false)
            recordProviderError(error)
            logger.error("WireGuard update failed: \(error.localizedDescription, privacy: .private)")
            return
        }
        applyGate.finish(version: version, succeeded: true)
    }

    private func deactivateAdapter(version: UInt64) {
        guard adapterStarted else {
            applyGate.finish(version: version, succeeded: true)
            return
        }
        let generation = lifecycle.value
        statsReadGate.invalidate()
        adapterOperation = (.deactivate, generation)
        adapter.stop { [weak self] error in
            guard let self else { return }
            self.queue.async {
                guard self.finishAdapterOperation(.deactivate, generation: generation) else {
                    self.finishStaleAdapterOperation(.deactivate, generation: generation, error: error)
                    return
                }
                if let error {
                    self.applyGate.finish(version: version, succeeded: false)
                    self.recordProviderError(error)
                    self.logger.error("WireGuard stop failed: \(error.localizedDescription, privacy: .private)")
                    return
                }
                self.adapterStarted = false
                self.applyGate.finish(version: version, succeeded: true)
            }
        }
    }

    private func applyDesiredExitIfNeeded(_ core: RatelMeshMobileClient) {
        guard let sharedDefaults else { return }
        let desired = sharedDefaults.string(forKey: AppConstants.selectedExitKey) ?? ""
        guard desired != lastRequestedExit else { return }
        do {
            try core.useExit(desired)
            lastRequestedExit = desired
        } catch {
            // Netmap may not contain the exit yet. Retry on the next poll.
            logger.debug("Deferred exit selection: \(error.localizedDescription, privacy: .private)")
        }
    }

    private func startInitialTimeout() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + .seconds(30))
        timer.setEventHandler { [weak self] in self?.failInitialStart(ProviderError.configurationTimeout) }
        initialTimeout = timer
        timer.resume()
    }

    private func failInitialStart(_ error: Error) {
        guard let completion = startCompletion else { return }
        stopTimers()
        invalidateLifecycle()
        core?.stop()
        core = nil
        startCompletion = nil
        recordProviderError(error)
        completion.call(systemError(for: error))
        startClosingWatchdogIfNeeded()
        if adapterOperation == nil {
            stopAdapterForClosing(force: adapterStarted)
        }
    }

    private func invalidateLifecycle() {
        lifecycle.invalidate()
        statsReadGate.invalidate()
        applyGate.reset()
    }

    private func finishAdapterOperation(_ kind: AdapterOperation, generation: UInt64) -> Bool {
        guard let operation = adapterOperation,
              operation.kind == kind,
              operation.generation == generation else {
            return false
        }
        adapterOperation = nil
        return lifecycle.accepts(generation)
    }

    private func finishStaleAdapterOperation(
        _ kind: AdapterOperation,
        generation: UInt64,
        error: WireGuardAdapterError?
    ) {
        if let operation = adapterOperation,
           operation.kind == kind,
           operation.generation == generation {
            adapterOperation = nil
        }
        guard lifecycle.isClosing else { return }
        // A successful late start may have raised the interface after stop or
        // timeout. Updates and deactivation can also finish after stop, so force
        // a final idempotent stop instead of accepting any stale state/error.
        if kind == .deactivate, error == nil {
            adapterStarted = false
            completeStopIfNeeded()
            return
        }
        let forceStop = kind == .update || kind == .deactivate || error == nil
        stopAdapterForClosing(force: forceStop)
    }

    private func stopAdapterForClosing(force: Bool) {
        guard lifecycle.isClosing, !adapterStopInFlight else { return }
        guard force else {
            adapterStarted = false
            completeStopIfNeeded()
            return
        }
        adapterStopInFlight = true
        adapter.stop { [weak self] error in
            guard let self else { return }
            self.queue.async {
                self.adapterStopInFlight = false
                if let error {
                    self.logger.debug("WireGuard closing stop returned: \(error.localizedDescription, privacy: .private)")
                    self.forceProviderTeardown()
                    return
                }
                self.adapterStarted = false
                self.completeStopIfNeeded()
            }
        }
    }

    private func completeStopIfNeeded() {
        guard adapterOperation == nil, !adapterStopInFlight else { return }
        cancelTeardownWatchdogs()
        completeStopWaiters()
    }

    private func completeStopWaiters() {
        let completions = stopCompletions
        stopCompletions.removeAll()
        completions.forEach { $0.call(()) }
    }

    private func cancelTeardownWatchdogs() {
        closingWatchdog?.cancel()
        closingWatchdog = nil
        forcedTeardownWatchdog?.cancel()
        forcedTeardownWatchdog = nil
    }

    private func startClosingWatchdogIfNeeded() {
        guard !lifecycle.isTerminal, closingWatchdog == nil else { return }
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + .seconds(5))
        timer.setEventHandler { [weak self] in
            self?.forceProviderTeardown()
        }
        closingWatchdog = timer
        timer.resume()
    }

    private func forceProviderTeardown() {
        guard lifecycle.isClosing, !lifecycle.isTerminal else { return }
        lifecycle.markTerminal()
        statsReadGate.invalidate()
        cancelTeardownWatchdogs()
        recordProviderError(ProviderError.forcedTeardown)

        // NetworkExtension owns the packet flow and is the final authority for
        // teardown. This prevents a lost WireGuard callback from turning a
        // bookkeeping timeout into a falsely reported shutdown.
        cancelTunnelWithError(systemError(for: ProviderError.forcedTeardown))

        // Also ask WireGuard to release its userspace backend. The system
        // cancellation above remains authoritative if this callback is lost.
        adapterOperation = nil
        if !adapterStopInFlight {
            adapterStopInFlight = true
            adapter.stop { [weak self] error in
                guard let self else { return }
                self.queue.async {
                    self.adapterStopInFlight = false
                    self.adapterStarted = false
                    if let error {
                        self.logger.debug("WireGuard forced stop returned: \(error.localizedDescription, privacy: .private)")
                    }
                    self.completeStopIfNeeded()
                }
            }
        }

        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + .seconds(2))
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            // cancelTunnelWithError has handed teardown to NetworkExtension.
            // Bound stop callers without claiming that the unconfirmed adapter
            // has stopped. This provider remains terminal; a late callback can
            // only finish cleanup and can never mutate a new lifecycle.
            self.cancelTeardownWatchdogs()
            self.completeStopWaiters()
        }
        forcedTeardownWatchdog = timer
        timer.resume()
    }

    private func stopTimers() {
        pollTimer?.cancel()
        pollTimer = nil
        initialTimeout?.cancel()
        initialTimeout = nil
    }

    private func persistStatus(_ json: String) {
        sharedDefaults?.set(json, forKey: AppConstants.lastStatusKey)
    }

    private func recordProviderError(_ error: Error) {
        guard let sharedDefaults, let sharedContainerURL else { return }
        do {
            try TunnelErrorStore.record(
                error,
                in: sharedDefaults,
                containerURL: sharedContainerURL
            )
        } catch {
            logger.error("Unable to persist sanitized provider error")
        }
    }

    private func response(ok: Bool, code: TunnelErrorCode? = nil) -> Data? {
        var object: [String: Any] = ["ok": ok]
        if let code { object["code"] = code.rawValue }
        return try? JSONSerialization.data(withJSONObject: object)
    }

    private func systemError(for error: Error) -> NSError {
        let code = TunnelErrorReport.sanitized(error).code
        return NSError(
            domain: TunnelErrorCode.systemErrorDomain,
            code: code.systemErrorNumber,
            userInfo: nil
        )
    }
}

enum ProviderError: Error, TunnelErrorCodeProviding {
    case missingConfiguration
    case missingAppGroup
    case missingKeychainGroup
    case configurationTimeout
    case invalidExit
    case unknownAction
    case configurationVersionMismatch
    case cancelled
    case closing
    case alreadyActive
    case forcedTeardown
    case enrollmentResetPending

    var tunnelErrorCode: TunnelErrorCode {
        switch self {
        case .missingConfiguration: .configurationMissing
        case .missingAppGroup: .appGroupUnavailable
        case .missingKeychainGroup: .keychainUnavailable
        case .configurationTimeout: .configurationTimeout
        case .invalidExit: .invalidExit
        case .unknownAction: .unsupportedProviderAction
        case .configurationVersionMismatch: .configurationVersionMismatch
        case .cancelled: .tunnelCancelled
        case .closing, .alreadyActive: .tunnelAlreadyActive
        case .forcedTeardown: .tunnelForcedTeardown
        case .enrollmentResetPending: .configurationMissing
        }
    }
}

extension WireGuardAdapterError: TunnelErrorCodeProviding {
    var tunnelErrorCode: TunnelErrorCode {
        switch self {
        case .cannotLocateTunnelFileDescriptor: .wireGuardDescriptorUnavailable
        case .invalidState: .wireGuardInvalidState
        case .dnsResolution: .wireGuardDNSResolutionFailed
        case .setNetworkSettings: .networkSettingsRejected
        case .startWireGuardBackend: .wireGuardBackendStartFailed
        }
    }
}
