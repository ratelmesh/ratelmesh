import Foundation
	import CoreLocation
@preconcurrency import NetworkExtension
import UIKit

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
		case .authorizedWhenInUse, .authorizedAlways: manager.requestLocation()
		case .notDetermined: manager.requestWhenInUseAuthorization()
		default: break
		}
	}

	func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
		if manager.authorizationStatus == .authorizedWhenInUse || manager.authorizationStatus == .authorizedAlways {
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
    @Published var coordinatorURL = ""
    @Published var authKey = ""
    @Published var hostname = AppViewModel.defaultHostname
    @Published private(set) var vpnStatus: NEVPNStatus = .invalid
    @Published private(set) var meshStatus: MobileStatus?
    @Published private(set) var isBusy = false
    @Published private(set) var requestedExit: String?
    @Published var errorMessage: String?
    @Published var showingSettings = false

    private let store = SecureConfigurationStore()
    private let tunnel = TunnelController()
	private let systemLocation = SystemLocationProvider()
    private var refreshTask: Task<Void, Never>?

    var isConnected: Bool { vpnStatus == .connected }
    var isTransitioning: Bool { vpnStatus == .connecting || vpnStatus == .disconnecting || vpnStatus == .reasserting }
    var exits: [MobilePeerStatus] { meshStatus?.exits ?? [] }
    var selectedExit: String { AppConstants.sharedDefaults.string(forKey: AppConstants.selectedExitKey) ?? "" }
    var activeExit: String { meshStatus?.activeExit ?? "" }
    var reportedSelectedExit: String { meshStatus?.selectedExit ?? activeExit }

    func prepare() async {
        do {
            if let saved = try store.load() {
                coordinatorURL = saved.coordinatorURL
                authKey = saved.authKey
                hostname = saved.hostname
            } else {
                showingSettings = true
            }
            try await tunnel.prepare()
            vpnStatus = tunnel.status
            beginRefreshing()
			systemLocation.onLocation = { [weak self] coordinate in
				Task { @MainActor in
					guard let self, self.isConnected else { return }
					try? await self.tunnel.setSystemLocation(latitude: coordinate.latitude, longitude: coordinate.longitude)
				}
			}
			systemLocation.start()
        } catch {
            present(error)
        }
    }

    func connect() async {
        guard !isBusy else { return }
        isBusy = true
        defer { isBusy = false }
        do {
            let config = try currentConfiguration().validated()
            try store.save(config)
            try await tunnel.installIfNeeded()
            try tunnel.start()
			systemLocation.start()
            showingSettings = false
        } catch {
            present(error)
        }
    }

    func disconnect() {
        tunnel.stop()
    }

    func saveSettings() async {
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
        requestedExit = name
        defer { requestedExit = nil }
        AppConstants.sharedDefaults.set(name, forKey: AppConstants.selectedExitKey)
        guard isConnected else { return }
        do {
            try await tunnel.setExit(name)
            await refreshStatus()
        } catch {
            present(error)
        }
    }

    func clearError() { errorMessage = nil }

    private func beginRefreshing() {
        refreshTask?.cancel()
        refreshTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                self.vpnStatus = self.tunnel.status
                await self.refreshStatus()
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }

    private func refreshStatus() async {
        do {
            if let data = try await tunnel.statusData(), !data.isEmpty {
                meshStatus = try JSONDecoder().decode(MobileStatus.self, from: data)
            } else if let json = AppConstants.sharedDefaults.string(forKey: AppConstants.lastStatusKey),
                      let data = json.data(using: .utf8) {
                meshStatus = try? JSONDecoder().decode(MobileStatus.self, from: data)
            }
            if let providerError = AppConstants.sharedDefaults.string(forKey: AppConstants.lastProviderErrorKey),
               !providerError.isEmpty, vpnStatus == .invalid {
                errorMessage = providerError
            }
        } catch {
            // The provider can disappear between status observation and IPC.
        }
    }

    private func currentConfiguration() -> ClientConfiguration {
        ClientConfiguration(coordinatorURL: coordinatorURL, authKey: authKey, hostname: hostname)
    }

    private func present(_ error: Error) {
        errorMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
    }

    private static var defaultHostname: String {
        let raw = UIDevice.current.name
            .lowercased()
            .replacingOccurrences(of: #"[^a-z0-9-]"#, with: "-", options: .regularExpression)
            .trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        return String((raw.isEmpty ? "iphone" : raw).prefix(63))
    }
}
