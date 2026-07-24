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
    private let queue = DispatchQueue(label: "com.ratelmesh.ios.packet-tunnel")
    private let logger = Logger(subsystem: "com.ratelmesh.ios", category: "PacketTunnel")
    private lazy var adapter = WireGuardAdapter(with: self) { [logger] level, message in
        switch level {
        case .error: logger.error("\(message, privacy: .public)")
        case .verbose: logger.debug("\(message, privacy: .public)")
        }
    }

    private var core: RatelMeshMobileClient?
    private var pollTimer: DispatchSourceTimer?
    private var initialTimeout: DispatchSourceTimer?
    private var appliedVersion: UInt64 = 0
    private var adapterStarted = false
    private var startCompletion: SendableCallback<Error?>?
    private var lastRequestedExit: String?
    private var statsReadInFlight = false

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let completion = SendableCallback(completionHandler)
        queue.async {
            do {
                let configuration = try SecureConfigurationStore().load()?.validated()
                guard let configuration else { throw ProviderError.missingConfiguration }
                guard let container = FileManager.default.containerURL(
                    forSecurityApplicationGroupIdentifier: AppConstants.appGroup
                ) else { throw ProviderError.missingAppGroup }
                let state = container.appendingPathComponent("State", isDirectory: true)
                try FileManager.default.createDirectory(at: state, withIntermediateDirectories: true)
                let core = try RatelMeshMobileClient(configuration: configuration, stateDirectory: state)
                self.core = core
                self.startCompletion = completion
                self.clearProviderError()
                core.start()
                self.startPolling()
                self.startInitialTimeout()
            } catch {
                self.recordProviderError(error)
                completion.call(error)
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        let completion = SendableCallback<Void> { completionHandler() }
        queue.async {
            self.stopTimers()
            let finish: @Sendable () -> Void = {
                self.core?.stop()
                self.core = nil
                self.adapterStarted = false
                self.appliedVersion = 0
                self.startCompletion = nil
                completion.call(())
            }
            guard self.adapterStarted else { finish(); return }
            self.adapter.stop { error in
                if let error { self.logger.error("WireGuard stop failed: \(error.localizedDescription, privacy: .public)") }
                self.queue.async(execute: finish)
            }
        }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)? = nil) {
        let completion = completionHandler.map(SendableCallback.init)
        queue.async {
            guard let object = try? JSONSerialization.jsonObject(with: messageData) as? [String: Any],
                  let action = object["action"] as? String else {
                completion?.call(self.response(ok: false, error: "消息格式无效。"))
                return
            }
            do {
                switch action {
                case "status":
                    completion?.call(self.core?.statusJSON.data(using: .utf8))
                    return
                case "useExit":
                    guard let name = object["name"] as? String, !name.isEmpty else { throw ProviderError.invalidExit }
                    try self.core?.useExit(name)
                    self.lastRequestedExit = name
                case "clearExit":
                    try self.core?.useExit("")
                    self.lastRequestedExit = ""
				case "setSystemLocation":
					guard let latText = object["latitude"] as? String,
						  let lonText = object["longitude"] as? String,
						  let latitude = Double(latText), let longitude = Double(lonText) else {
						throw ProviderError.unknownAction
					}
					try self.core?.setSystemLocation(latitude: latitude, longitude: longitude)
                default:
                    throw ProviderError.unknownAction
                }
                self.pollOnce()
                completion?.call(self.response(ok: true))
            } catch {
                completion?.call(self.response(ok: false, error: error.localizedDescription))
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
        guard version > appliedVersion else { return }
        do {
            let data = Data(core.tunnelConfigurationJSON.utf8)
            let mobile = try JSONDecoder().decode(MobileTunnelConfiguration.self, from: data)
            guard mobile.version == version, mobile.active else { return }
            let configuration = try mobile.wireGuardConfiguration()
            if adapterStarted {
                adapter.update(tunnelConfiguration: configuration) { [weak self] error in
                    guard let self else { return }
                    self.queue.async { self.finishApply(version: version, error: error) }
                }
            } else {
                adapter.start(tunnelConfiguration: configuration) { [weak self] error in
                    guard let self else { return }
                    self.queue.async { self.finishInitialStart(version: version, error: error) }
                }
            }
        } catch {
            recordProviderError(error)
            if !adapterStarted { failInitialStart(error) }
        }
    }

    private func reportRuntimeStats(_ core: RatelMeshMobileClient) {
        guard adapterStarted, !statsReadInFlight else { return }
        statsReadInFlight = true
        adapter.getRuntimeConfiguration { [weak self, core] runtime in
            guard let self else { return }
            self.queue.async {
                self.statsReadInFlight = false
                guard let runtime else { return }
                core.updatePeerStats(WireGuardRuntimeStats.decode(runtime))
            }
        }
    }

    private func finishInitialStart(version: UInt64, error: WireGuardAdapterError?) {
        if let error { failInitialStart(error); return }
        adapterStarted = true
        appliedVersion = version
        initialTimeout?.cancel()
        initialTimeout = nil
        startCompletion?.call(nil)
        startCompletion = nil
    }

    private func finishApply(version: UInt64, error: WireGuardAdapterError?) {
        if let error {
            recordProviderError(error)
            logger.error("WireGuard update failed: \(error.localizedDescription, privacy: .public)")
            return
        }
        appliedVersion = version
        clearProviderError()
    }

    private func applyDesiredExitIfNeeded(_ core: RatelMeshMobileClient) {
        let desired = AppConstants.sharedDefaults.string(forKey: AppConstants.selectedExitKey) ?? ""
        guard desired != lastRequestedExit else { return }
        do {
            try core.useExit(desired)
            lastRequestedExit = desired
        } catch {
            // Netmap may not contain the exit yet. Retry on the next poll.
            logger.debug("Deferred exit selection: \(error.localizedDescription, privacy: .public)")
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
        core?.stop()
        core = nil
        startCompletion = nil
        recordProviderError(error)
        completion.call(error)
    }

    private func stopTimers() {
        pollTimer?.cancel()
        pollTimer = nil
        initialTimeout?.cancel()
        initialTimeout = nil
    }

    private func persistStatus(_ json: String) {
        AppConstants.sharedDefaults.set(json, forKey: AppConstants.lastStatusKey)
    }

    private func recordProviderError(_ error: Error) {
        AppConstants.sharedDefaults.set(error.localizedDescription, forKey: AppConstants.lastProviderErrorKey)
    }

    private func clearProviderError() {
        AppConstants.sharedDefaults.removeObject(forKey: AppConstants.lastProviderErrorKey)
    }

    private func response(ok: Bool, error: String? = nil) -> Data? {
        var object: [String: Any] = ["ok": ok]
        if let error { object["error"] = error }
        return try? JSONSerialization.data(withJSONObject: object)
    }
}

enum ProviderError: LocalizedError {
    case missingConfiguration
    case missingAppGroup
    case configurationTimeout
    case invalidExit
    case unknownAction

    var errorDescription: String? {
        switch self {
        case .missingConfiguration: "请先在 RatelMesh 中保存连接设置。"
        case .missingAppGroup: "无法访问共享容器，请检查 App Group 签名权限。"
        case .configurationTimeout: "等待控制面下发隧道配置超时。"
        case .invalidExit: "出口节点名称无效。"
        case .unknownAction: "不支持的隧道操作。"
        }
    }
}

extension WireGuardAdapterError: @retroactive LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .cannotLocateTunnelFileDescriptor: "无法找到系统隧道文件描述符。"
        case .invalidState: "WireGuard 适配器状态无效。"
        case .dnsResolution(let failures): "端点 DNS 解析失败：\(failures.map(\.address).joined(separator: ", "))"
        case .setNetworkSettings(let error): "系统拒绝隧道路由设置：\(error.localizedDescription)"
        case .startWireGuardBackend(let code): "WireGuard 后端启动失败（\(code)）。"
        }
    }
}
