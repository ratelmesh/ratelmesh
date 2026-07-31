import Foundation
import CoreLocation
@preconcurrency import NetworkExtension
#if os(iOS)
import UIKit
#elseif os(macOS)
import AppKit
#endif

private final class SystemLocationProvider: NSObject, CLLocationManagerDelegate {
	private let manager = CLLocationManager()
	var onLocation: ((CLLocationCoordinate2D) -> Void)?

	override init() {
		super.init()
		manager.delegate = self
		manager.desiredAccuracy = kCLLocationAccuracyThreeKilometers
	}

	func start() {
		switch manager.authorizationStatus {
		case .authorizedAlways: manager.requestLocation()
#if os(iOS)
		case .authorizedWhenInUse: manager.requestLocation()
#endif
		case .notDetermined: manager.requestWhenInUseAuthorization()
		default: break
		}
	}

	func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
		var isAuthorized = manager.authorizationStatus == .authorizedAlways
#if os(iOS)
		isAuthorized = isAuthorized || manager.authorizationStatus == .authorizedWhenInUse
#endif
		if isAuthorized {
			manager.requestLocation()
		}
	}

	func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
		if let coordinate = locations.last?.coordinate { onLocation?(coordinate) }
	}

	func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {}
}

@MainActor
final class AppViewModel: ObservableObject {
    @Published var coordinatorURL = AppConstants.officialCoordinatorURL
    @Published var authKey = ""
    @Published var hostname = AppViewModel.defaultHostname
    @Published private(set) var vpnStatus: NEVPNStatus = .invalid
    @Published private(set) var meshStatus: MobileStatus?
    @Published private(set) var isBusy = false
    @Published private(set) var requestedExit: String?
    @Published private(set) var errorCode: TunnelErrorCode?
    @Published private(set) var appGroupReady = false
    @Published var showingSettings = false

    private let store = SecureConfigurationStore()
    private let tunnel: TunnelController
    let networkDoctor: NetworkDoctorStore
    private let systemLocation = SystemLocationProvider()
    private var refreshTask: Task<Void, Never>?
    private var sharedDefaults: UserDefaults?
    private var sharedContainerURL: URL?
    private var errorQueue = TunnelErrorPresentationQueue()

    init() {
        let tunnel = TunnelController()
        self.tunnel = tunnel
        networkDoctor = NetworkDoctorStore(service: TunnelNetworkDoctorService(tunnel: tunnel))
    }

    var isConnected: Bool { vpnStatus == .connected }
    var isTransitioning: Bool { vpnStatus == .connecting || vpnStatus == .disconnecting || vpnStatus == .reasserting }
    var exits: [MobilePeerStatus] { meshStatus?.exits ?? [] }
    var selectedExit: String { sharedDefaults?.string(forKey: AppConstants.selectedExitKey) ?? "" }
    var activeExit: String { meshStatus?.activeExit ?? "" }
    var reportedSelectedExit: String { meshStatus?.selectedExit ?? activeExit }
    var requiresReEnrollment: Bool { meshStatus?.enrollmentRequired == true }

    func prepare() async {
#if DEBUG
        if ProcessInfo.processInfo.environment["RATELMESH_APP_STORE_SCREENSHOTS"] == "1" {
            prepareAppStoreScreenshotFixture()
            return
        }
#endif
        appGroupReady = false
        sharedDefaults = nil
        sharedContainerURL = nil
        do {
            guard let defaults = AppConstants.sharedDefaults,
                  let container = AppConstants.sharedContainerURL else {
                throw AppGroupAccessError.unavailable
            }
            guard AppConstants.keychainAccessGroup != nil else {
                throw StoreError.missingKeychainAccessGroup
            }
            try store.validateAccessGroup()
            sharedDefaults = defaults
            sharedContainerURL = container
            try DeviceStateDirectory.excludeExistingFromBackup(in: container)
            try await tunnel.prepare()
            if enrollmentResetPending {
                tunnel.stop()
                guard await tunnel.waitUntilStopped() else {
                    throw TunnelError.provider(.tunnelForcedTeardown)
                }
                try store.delete()
                try resetEnrollmentState(deleteCredential: false)
            }
            if try store.prepareForCurrentInstallation(
                allowLegacyMigration: tunnel.manager != nil,
                onResetRequired: { try self.markEnrollmentResetPending() }
            ) {
                tunnel.stop()
                guard await tunnel.waitUntilStopped() else {
                    throw TunnelError.provider(.tunnelForcedTeardown)
                }
                try resetEnrollmentState(deleteCredential: false)
            }
            appGroupReady = true
            observeProviderError()
            if let saved = try store.load() {
                coordinatorURL = saved.coordinatorURL.isEmpty
                    ? AppConstants.officialCoordinatorURL
                    : saved.coordinatorURL
                authKey = saved.authKey
                hostname = saved.hostname
            } else {
                showingSettings = true
            }
            vpnStatus = tunnel.status
            if vpnStatus == .connected {
                systemLocation.start()
            }
            beginRefreshing()
			systemLocation.onLocation = { [weak self] coordinate in
				Task { @MainActor in
					guard let self, self.isConnected else { return }
					try? await self.tunnel.setSystemLocation(latitude: coordinate.latitude, longitude: coordinate.longitude)
				}
			}
        } catch {
            present(error)
        }
    }

#if DEBUG
    private func prepareAppStoreScreenshotFixture() {
        appGroupReady = true
        vpnStatus = .connected
        authKey = "review-enrollment-code"
#if os(macOS)
        hostname = "review-mac"
#else
        hostname = "review-iphone"
#endif
        showingSettings =
            ProcessInfo.processInfo.environment["RATELMESH_APP_STORE_SCREEN"] == "settings"
        meshStatus = MobileStatus(
            state: "Running",
            enrollmentRequired: false,
            coordURL: AppConstants.officialCoordinatorURL,
            netmapVersion: 42,
            peers: [
                MobilePeerStatus(
                    name: "home-exit",
                    meshIP: "100.64.0.1",
                    role: "exit",
                    online: true,
                    pathType: "direct",
                    platform: "macOS",
                    remoteAccessAllowed: false,
                    remoteServices: []
                ),
                MobilePeerStatus(
                    name: "office-mac",
                    meshIP: "100.64.0.2",
                    role: "device",
                    online: true,
                    pathType: "relay",
                    platform: "macOS",
                    remoteAccessAllowed: true,
                    remoteServices: [
                        MobileRemoteService(
                            kind: "ssh",
                            port: 22,
                            targetMeshIp: "100.64.0.2"
                        ),
                        MobileRemoteService(
                            kind: "vnc",
                            port: 5900,
                            targetMeshIp: "100.64.0.2"
                        ),
                    ]
                ),
                MobilePeerStatus(
                    name: "private-nas",
                    meshIP: "100.64.0.3",
                    role: "device",
                    online: true,
                    pathType: "direct",
                    platform: "Linux",
                    remoteAccessAllowed: true,
                    remoteServices: [
                        MobileRemoteService(
                            kind: "ssh",
                            port: 22,
                            targetMeshIp: "100.64.0.3"
                        ),
                    ]
                ),
            ],
            activeExit: "home-exit",
            selectedExit: "home-exit",
            exitTrafficVerified: true,
            exitClients: nil,
            killSwitch: true,
            dns: "1.1.1.1"
        )
    }
#endif

    func connect() async {
        guard !isBusy else { return }
        guard appGroupReady, sharedDefaults != nil else {
            present(AppGroupAccessError.unavailable)
            return
        }
        isBusy = true
        defer { isBusy = false }
        do {
            let config = try currentConfiguration().validated()
            try store.save(config)
            try await tunnel.installIfNeeded()
            try tunnel.start()
            showingSettings = false
        } catch {
            present(error)
        }
    }

    func disconnect() {
        tunnel.stop()
    }

    func beginReEnrollment() {
        guard !isBusy else { return }
        isBusy = true
        authKey = ""
        showingSettings = true
        do {
            try markEnrollmentResetPending()
            try store.delete()
        } catch {
            isBusy = false
            present(error)
            return
        }
        tunnel.stop()
        Task {
            defer { isBusy = false }
            guard await tunnel.waitUntilStopped() else {
                present(TunnelError.provider(.tunnelForcedTeardown))
                return
            }
            do {
                try resetEnrollmentState(deleteCredential: false)
            } catch {
                present(error)
            }
        }
    }

    func saveSettings() async {
        guard !isBusy else { return }
        guard appGroupReady, sharedDefaults != nil else {
            present(AppGroupAccessError.unavailable)
            return
        }
        do {
            let config = try currentConfiguration().validated()
            try store.save(config)
            try await tunnel.installIfNeeded()
            showingSettings = false
        } catch {
            present(error)
        }
    }

    func selectExit(_ name: String) async {
        guard requestedExit == nil else { return }
        guard appGroupReady, let sharedDefaults else {
            present(AppGroupAccessError.unavailable)
            return
        }
        requestedExit = name
        defer { requestedExit = nil }
        sharedDefaults.set(name, forKey: AppConstants.selectedExitKey)
        guard isConnected else { return }
        do {
            try await tunnel.setExit(name)
            await refreshStatus()
        } catch {
            present(error)
        }
    }

    func acknowledgeError() {
        guard errorQueue.current != nil else { return }
        if let eventID = errorQueue.current?.providerEventID {
            guard let sharedDefaults, let sharedContainerURL else {
                present(AppGroupAccessError.unavailable)
                return
            }
            do {
                try TunnelErrorStore.acknowledge(
                    eventID,
                    in: sharedDefaults,
                    containerURL: sharedContainerURL
                )
            } catch {
                present(error)
                return
            }
        }
        _ = errorQueue.acknowledgeCurrent()
        refreshPresentedError()
        observeProviderError()
    }

    private func beginRefreshing() {
        refreshTask?.cancel()
        refreshTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                let nextStatus = self.tunnel.status
                if nextStatus == .connected && self.vpnStatus != .connected {
                    self.systemLocation.start()
                }
                self.vpnStatus = nextStatus
                await self.refreshStatus()
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    private func refreshStatus() async {
        do {
            if let data = try await tunnel.statusData(), !data.isEmpty {
                meshStatus = try JSONDecoder().decode(MobileStatus.self, from: data)
            } else if let json = sharedDefaults?.string(forKey: AppConstants.lastStatusKey),
                      let data = json.data(using: .utf8) {
                meshStatus = try? JSONDecoder().decode(MobileStatus.self, from: data)
            }
            observeProviderError()
        } catch {
            // The provider can disappear between status observation and IPC.
        }
    }

    private func currentConfiguration() -> ClientConfiguration {
        ClientConfiguration(coordinatorURL: coordinatorURL, authKey: authKey, hostname: hostname)
    }

    private func resetEnrollmentState(deleteCredential: Bool) throws {
        if deleteCredential {
            try store.delete()
        }
        sharedDefaults?.removeObject(forKey: AppConstants.selectedExitKey)
        sharedDefaults?.removeObject(forKey: AppConstants.lastStatusKey)
        sharedDefaults?.removeObject(forKey: AppConstants.lastProviderErrorKey)
        sharedDefaults?.removeObject(forKey: AppConstants.legacyLastProviderErrorKey)
        sharedDefaults?.removeObject(forKey: AppConstants.migratedProviderErrorKey)
        sharedDefaults?.removeObject(forKey: AppConstants.lastSeenProviderErrorEventKey)

        if let sharedContainerURL {
            let state = sharedContainerURL.appendingPathComponent("State", isDirectory: true)
            if FileManager.default.fileExists(atPath: state.path) {
                try FileManager.default.removeItem(at: state)
            }
            for file in [
                AppConstants.providerErrorQueueFile,
                AppConstants.providerErrorQueueLockFile,
            ] {
                let url = sharedContainerURL.appendingPathComponent(file)
                if FileManager.default.fileExists(atPath: url.path) {
                    try FileManager.default.removeItem(at: url)
                }
            }
            let marker = sharedContainerURL.appendingPathComponent(
                AppConstants.enrollmentResetPendingFile
            )
            if FileManager.default.fileExists(atPath: marker.path) {
                try FileManager.default.removeItem(at: marker)
            }
        }
        meshStatus = nil
        requestedExit = nil
        errorQueue = TunnelErrorPresentationQueue()
        errorCode = nil
    }

    private var enrollmentResetPending: Bool {
        guard let sharedContainerURL else { return false }
        return FileManager.default.fileExists(
            atPath: sharedContainerURL.appendingPathComponent(
                AppConstants.enrollmentResetPendingFile
            ).path
        )
    }

    private func markEnrollmentResetPending() throws {
        guard let sharedContainerURL else { throw AppGroupAccessError.unavailable }
        let marker = sharedContainerURL.appendingPathComponent(
            AppConstants.enrollmentResetPendingFile
        )
        try Data("pending\n".utf8).write(to: marker, options: .atomic)
    }

    private func present(_ error: Error) {
        errorQueue.enqueueLocal(TunnelErrorReport.sanitized(error).code)
        refreshPresentedError()
    }

    private func observeProviderError() {
        guard let sharedDefaults, let sharedContainerURL else { return }
        do {
            for event in try TunnelErrorStore.pendingEvents(
                from: sharedDefaults,
                containerURL: sharedContainerURL
            ) {
                errorQueue.enqueueProvider(event)
            }
            refreshPresentedError()
        } catch {
            present(error)
        }
    }

    private func refreshPresentedError() {
        errorCode = errorQueue.current?.code
    }

    private static var defaultHostname: String {
#if os(macOS)
        let deviceName = Host.current().localizedName ?? ProcessInfo.processInfo.hostName
#else
        let deviceName = UIDevice.current.name
#endif
        let raw = deviceName
            .lowercased()
            .replacingOccurrences(of: #"[^a-z0-9-]"#, with: "-", options: .regularExpression)
            .trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        return String((raw.isEmpty ? "device" : raw).prefix(63))
    }
}
