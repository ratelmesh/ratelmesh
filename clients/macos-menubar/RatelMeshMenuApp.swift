import AppKit
import CoreLocation
import SwiftUI
import UniformTypeIdentifiers

private final class SystemLocationReporter: NSObject, CLLocationManagerDelegate {
	private let manager = CLLocationManager()
	private let report: (CLLocationCoordinate2D) -> Void

	init(report: @escaping (CLLocationCoordinate2D) -> Void) {
		self.report = report
		super.init()
		manager.delegate = self
		manager.desiredAccuracy = kCLLocationAccuracyThreeKilometers
	}

	func start() {
		switch manager.authorizationStatus {
		case .authorized, .authorizedAlways:
			manager.requestLocation()
		case .notDetermined:
			manager.requestWhenInUseAuthorization()
		default:
			break
		}
	}

	func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
		if manager.authorizationStatus == .authorized || manager.authorizationStatus == .authorizedAlways {
			manager.requestLocation()
		}
	}

	func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
		guard let location = locations.last else { return }
		report(location.coordinate)
	}

	func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {}
}

private enum Copy {
    enum Language: String, CaseIterable, Identifiable {
        case system
        case english
        case spanish = "es"
        case german = "de"
        case french = "fr"
        case japanese = "ja"
        case korean = "ko"
        case italian = "it"
        case dutch = "nl"
        case polish = "pl"
        case swedish = "sv"
        case portugueseBrazil = "pt-BR"
        case chinese = "chinese"
        case traditionalChinese = "zh-Hant"
        var id: String { rawValue }
    }

    static var language: Language {
        Language(rawValue: UserDefaults.standard.string(forKey: "ratelmesh.language") ?? "system") ?? .system
    }

    static var chinese: Bool {
        language == .chinese || language == .traditionalChinese
            || (language == .system && Locale.preferredLanguages.first?.lowercased().hasPrefix("zh") == true)
    }

    static func text(_ english: String, _ chinese: String) -> String {
        let selected = language
        let systemChinese = Locale.preferredLanguages.first?.lowercased().hasPrefix("zh") == true
        let fallback = selected == .chinese || selected == .traditionalChinese || (selected == .system && systemChinese) ? chinese : english
        if selected == .english { return english }
        if selected == .system {
            let localized = Bundle.main.localizedString(forKey: english, value: english, table: nil)
            if localized != english { return localized }
            return Bundle.main.localizedString(forKey: english, value: fallback, table: "NetworkDoctor")
        }
        let tag = selected == .chinese ? "zh-Hans" : selected.rawValue
        guard let path = Bundle.main.path(forResource: tag, ofType: "lproj"),
              let bundle = Bundle(path: path) else { return fallback }
        let localized = bundle.localizedString(forKey: english, value: english, table: nil)
        if localized != english { return localized }
        return bundle.localizedString(forKey: english, value: fallback, table: "NetworkDoctor")
    }

    static func format(_ english: String, _ chinese: String, _ arguments: CVarArg...) -> String {
        String(format: text(english, chinese), arguments: arguments)
    }

    static func select(_ language: Language) {
        UserDefaults.standard.set(language.rawValue, forKey: "ratelmesh.language")
    }

    static func languageName(_ language: Language) -> String {
        switch language {
        case .system: text("System", "跟随系统")
        case .english: "English"
        case .spanish: "Español"
        case .german: "Deutsch"
        case .french: "Français"
        case .japanese: "日本語"
        case .korean: "한국어"
        case .italian: "Italiano"
        case .dutch: "Nederlands"
        case .polish: "Polski"
        case .swedish: "Svenska"
        case .portugueseBrazil: "Português (Brasil)"
        case .chinese: "简体中文"
        case .traditionalChinese: "繁體中文"
        }
    }
}

private enum LocalEnrollment {
    static var complete: Bool {
        FileManager.default.fileExists(atPath: "/var/db/ratelmesh/enrolled")
    }
}

private enum RatelMeshBrand {
    static let black = Color(red: 11 / 255, green: 15 / 255, blue: 20 / 255)
    static let white = Color(red: 244 / 255, green: 247 / 255, blue: 249 / 255)
    static let cyan = Color(red: 32 / 255, green: 185 / 255, blue: 232 / 255)
    static let accessibleCyan = Color(red: 0 / 255, green: 106 / 255, blue: 140 / 255)
    static let accessibleGreen = Color(red: 0 / 255, green: 106 / 255, blue: 78 / 255)

    static func action(for colorScheme: ColorScheme) -> Color {
        colorScheme == .dark ? cyan : accessibleCyan
    }

    static func critical(for colorScheme: ColorScheme) -> Color {
        colorScheme == .dark
            ? Color(red: 1, green: 180 / 255, blue: 171 / 255)
            : Color(red: 179 / 255, green: 38 / 255, blue: 30 / 255)
    }

    static func warning(for colorScheme: ColorScheme) -> Color {
        colorScheme == .dark
            ? Color(red: 1, green: 196 / 255, blue: 107 / 255)
            : Color(red: 138 / 255, green: 79 / 255, blue: 0)
    }
}

@MainActor
private enum RatelMeshBrandAssets {
    static func image(size: CGFloat, template: Bool) -> NSImage {
        // The transparent menu mark is already bundled as Info.plist data; no runtime file lookup is required.
        if template,
           let data = Bundle.main.object(forInfoDictionaryKey: "RatelMeshMenuTemplatePNG") as? Data,
           let original = NSImage(data: data),
           let copy = original.copy() as? NSImage {
            copy.isTemplate = true
            copy.size = NSSize(width: size, height: size)
            return copy
        }

        let original = Bundle.main.url(forResource: "BrandMarkDark", withExtension: "png")
            .flatMap(NSImage.init(contentsOf:))
            ?? NSApplication.shared.applicationIconImage
            ?? NSImage(size: NSSize(width: size, height: size))
        guard let copy = original.copy() as? NSImage else { return original }
        copy.size = NSSize(width: size, height: size)
        return copy
    }
}

private struct RatelMeshBrandMark: View {
    let size: CGFloat
    var template = false
    var decorative = true

    var body: some View {
        Image(nsImage: RatelMeshBrandAssets.image(size: size, template: template))
            .interpolation(.high)
            .frame(width: size, height: size)
            .accessibilityHidden(decorative)
    }
}

@MainActor
private final class Store: ObservableObject {
    @Published var status: MeshStatus?
    @Published var reachable = true
    @Published var requestedExit: String?
    private let base = URL(string: "http://127.0.0.1:8088")!
    private var refreshTask: Task<Void, Never>?
	private var locationReporter: SystemLocationReporter?
    private var requestedLocationForActiveSession = false

    init() {
        locationReporter = SystemLocationReporter { [weak self] coordinate in
            self?.reportSystemLocation(coordinate)
        }
        Task { await refresh() }
        refreshTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(2))
                guard !Task.isCancelled else { return }
                await self?.refresh()
            }
        }
    }

	private func reportSystemLocation(_ coordinate: CLLocationCoordinate2D) {
		var components = URLComponents(url: base.appending(path: "/localapi/location/system"), resolvingAgainstBaseURL: false)!
		components.queryItems = [
			URLQueryItem(name: "latitude", value: String(coordinate.latitude)),
			URLQueryItem(name: "longitude", value: String(coordinate.longitude)),
		]
		var request = URLRequest(url: components.url!)
		request.httpMethod = "POST"
		Task { _ = try? await URLSession.shared.data(for: request) }
	}

    deinit { refreshTask?.cancel() }

    func refresh() async {
        do {
            let (data, response) = try await URLSession.shared.data(from: base.appending(path: "/localapi/status"))
            guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw URLError(.badServerResponse) }
            let decoded = try JSONDecoder().decode(MeshStatus.self, from: data)
            status = decoded
            reachable = true
            if decoded.state == "Running" {
                if !requestedLocationForActiveSession {
                    requestedLocationForActiveSession = true
                    locationReporter?.start()
                }
            } else {
                requestedLocationForActiveSession = false
            }
        } catch {
            reachable = false
            requestedLocationForActiveSession = false
        }
    }

    func useExit(_ name: String) {
        requestedExit = name
        mutate(path: "/localapi/exit/use", query: [URLQueryItem(name: "name", value: name)])
    }

    func clearExit() {
        requestedExit = ""
        mutate(path: "/localapi/exit/clear", query: [])
    }

    func setInternetFallback(_ enabled: Bool) {
        mutate(
            path: "/localapi/settings/internet-fallback",
            query: [URLQueryItem(name: "enabled", value: enabled ? "true" : "false")]
        )
    }

    private func mutate(path: String, query: [URLQueryItem]) {
        var components = URLComponents(url: base.appending(path: path), resolvingAgainstBaseURL: false)!
        components.queryItems = query.isEmpty ? nil : query
        var request = URLRequest(url: components.url!)
        request.httpMethod = "POST"
        Task {
            do {
                let (_, response) = try await URLSession.shared.data(for: request)
				guard let status = (response as? HTTPURLResponse)?.statusCode, (200..<300).contains(status) else { throw URLError(.badServerResponse) }
                await refresh()
                requestedExit = nil
            } catch {
                reachable = false
                requestedExit = nil
            }
        }
    }
}

@MainActor
private protocol NetworkDoctorGateway {
    func diagnose() async throws -> NetworkDoctorDiagnosis
    func execute(planID: String, action: String, confirmed: Bool) async throws -> NetworkDoctorExecutionReport
}

@MainActor
private final class LocalNetworkDoctorGateway: NetworkDoctorGateway {
    private let base: URL

    init(base: URL = URL(string: "http://127.0.0.1:8088")!) {
        self.base = base
    }

    func diagnose() async throws -> NetworkDoctorDiagnosis {
        var request = URLRequest(url: base.appending(path: "/localapi/doctor"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: [
            "confirm": true,
            "disclosureVersion": "v1",
        ])
        return try await response(NetworkDoctorDiagnosis.self, request: request)
    }

    func execute(planID: String, action: String, confirmed: Bool) async throws -> NetworkDoctorExecutionReport {
        guard confirmed else { throw NetworkDoctorContractError.invalidResponse }
        var request = URLRequest(url: base.appending(path: "/localapi/doctor/repair"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: [
            "planID": planID,
            "action": action,
            "confirm": true,
            "disclosureVersion": "v1",
        ])
        let envelope = try await response(NetworkDoctorExecutionEnvelope.self, request: request)
        guard envelope.schema == networkDoctorAPIExecutionSchema else {
            throw NetworkDoctorContractError.unsupportedSchema
        }
        return envelope.execution
    }

    private func response<T: Decodable>(_ type: T.Type, request: URLRequest) async throws -> T {
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let status = (response as? HTTPURLResponse)?.statusCode,
                  (200..<300).contains(status) else {
                throw NetworkDoctorContractError.unavailable
            }
            guard data.count <= 1_048_576 else { throw NetworkDoctorContractError.responseTooLarge }
            return try JSONDecoder().decode(type, from: data)
        } catch let error as NetworkDoctorContractError {
            throw error
        } catch is DecodingError {
            throw NetworkDoctorContractError.invalidResponse
        } catch {
            throw NetworkDoctorContractError.unavailable
        }
    }
}

@MainActor
private final class NetworkDoctorStore: ObservableObject {
    @Published private(set) var phase: NetworkDoctorPhase = .idle
    @Published private(set) var diagnosis: NetworkDoctorDiagnosis?
    @Published private(set) var execution: NetworkDoctorExecutionReport?
    @Published private(set) var error: NetworkDoctorContractError?
    private let gateway: NetworkDoctorGateway

    init(gateway: NetworkDoctorGateway? = nil) {
        self.gateway = gateway ?? LocalNetworkDoctorGateway()
    }

    var canRepair: Bool {
        phase == .review && diagnosis?.executableRepairs.isEmpty == false
    }

    func run() async {
        guard phase != .running && phase != .executing else { return }
        phase = .running
        diagnosis = nil
        execution = nil
        error = nil
        do {
            let result = try await gateway.diagnose()
            guard result.schema == networkDoctorAPISchema,
                  result.report.schema == networkDoctorReportSchema,
                  result.plan.schema == networkDoctorPlanSchema,
                  result.plan.dryRun,
                  result.planID.utf8.count <= 256,
                  (result.executableRepairs.isEmpty || !result.planID.isEmpty) else {
                throw NetworkDoctorContractError.unsupportedSchema
            }
            diagnosis = result
            phase = .review
        } catch {
            self.error = error as? NetworkDoctorContractError ?? .unavailable
            phase = .failed
        }
    }

    func requestConfirmation() {
        guard canRepair else {
            error = .noApplicableRepairs
            phase = .failed
            return
        }
        phase = .confirming
    }

    func cancelConfirmation() {
        guard diagnosis != nil else { return }
        phase = .review
    }

    func confirmAndRepair() async {
        guard phase == .confirming, let diagnosis,
              let repair = diagnosis.executableRepairs.first else {
            error = .noApplicableRepairs
            phase = .failed
            return
        }
        phase = .executing
        do {
            let result = try await gateway.execute(
                planID: diagnosis.planID,
                action: repair.action,
                confirmed: true
            )
            guard result.schema == networkDoctorExecutionSchema else {
                throw NetworkDoctorContractError.unsupportedSchema
            }
            execution = result
            phase = .finished
        } catch {
            self.error = error as? NetworkDoctorContractError ?? .unavailable
            phase = .failed
        }
    }
}

private struct Panel: View {
    @ObservedObject var store: Store
    @ObservedObject var updater: UpdateStore
    @Environment(\.colorScheme) private var colorScheme
    @State private var picked = ""
    @State private var enrollmentCode = ""
    @State private var enrollmentBusy = false
    @State private var enrollmentError = ""
    @State private var language = Copy.language
    @State private var showingNetworkDoctor = false
    @StateObject private var networkDoctor = NetworkDoctorStore()

    private var exits: [Peer] {
        store.status?.peers.filter { $0.role == "exit" } ?? []
    }

    var body: some View {
        ScrollView { panelContent }
            .frame(width: 430)
            .frame(maxHeight: 720)
    }

    @ViewBuilder
    private var panelContent: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                HStack(spacing: 8) {
                    RatelMeshBrandMark(size: 20, template: true)
                    Text("RatelMesh").font(.headline)
                }
                .accessibilityElement(children: .combine)
                Spacer()
                Picker(Copy.text("Language", "语言"), selection: $language) {
                    ForEach(Copy.Language.allCases) { option in
                        Text(Copy.languageName(option)).tag(option)
                    }
                }
                .labelsHidden()
                .frame(width: 120)
            }
            if shouldShowEnrollment(status: store.status, locallyEnrolled: LocalEnrollment.complete) {
                enrollmentPrompt
            } else if let status = store.status {
                let remotePeers = status.peers.filter { !$0.authorizedRemoteServices.isEmpty }
                let exitVerificationPending = !status.activeExit.isEmpty && !status.exitTrafficVerified
                let routePending = store.requestedExit != nil || (!status.selectedExit.isEmpty && status.activeExit.isEmpty) || exitVerificationPending
                let routeVerified = store.requestedExit == nil && (status.exitTrafficVerified || (status.selectedExit.isEmpty && status.activeExit.isEmpty))
                let routeColor: Color = routePending
                    ? RatelMeshBrand.warning(for: colorScheme)
                    : (status.activeExit.isEmpty ? RatelMeshBrand.action(for: colorScheme) : RatelMeshBrand.accessibleGreen)
                HStack(spacing: 7) {
                    if routePending { ProgressView().controlSize(.small) }
                    else {
                        Image(systemName: routeVerified ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                            .foregroundStyle(routeColor)
                            .accessibilityHidden(true)
                    }
                    Text(routeStatus(status, requested: store.requestedExit))
                        .font(.headline)
                }
                .padding(9)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(routeColor.opacity(0.10), in: RoundedRectangle(cornerRadius: 9))

                Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 5) {
                    GridRow { Text(Copy.text("State", "状态")).foregroundStyle(.secondary); Text(localState(status.state)) }
                    GridRow { Text(Copy.text("This device", "本机")).foregroundStyle(.secondary); Text("\(status.selfNode.meshIP)  \(status.selfNode.name)").lineLimit(1) }
                    GridRow { Text(Copy.text("Exit", "出口")).foregroundStyle(.secondary); Text(status.activeExit.isEmpty ? (status.selectedExit.isEmpty ? Copy.text("none (direct)", "无（直连）") : Copy.format("connecting %@", "正在连接 %@", status.selectedExit)) : status.activeExit).lineLimit(1) }
                    GridRow { Text(Copy.text("Leak protection", "泄漏保护")).foregroundStyle(.secondary); Text(status.killSwitch ? Copy.text("On", "已开启") : Copy.text("Off", "关闭")) }
                }

                Divider()
                Picker(Copy.text("Exit device", "出口设备"), selection: $picked) {
                    ForEach(exits) { peer in
                        Text("\(peer.name) (\(peer.meshIP))").tag(peer.name)
                    }
                }
                .disabled(exits.isEmpty)
                ViewThatFits(in: .horizontal) {
                    HStack { routeButtons(status) }
                    VStack(alignment: .leading, spacing: 6) { routeButtons(status) }
                }

                if exits.isEmpty {
                    Text(Copy.text("No exit devices available.", "暂无可用出口设备。"))
                        .font(.caption).foregroundStyle(.secondary)
                }

                if status.selfNode.role == "exit" {
                    Divider()
                    Text(Copy.text("Devices using this Mac as EXIT", "正在使用本机出口的设备"))
                        .font(.headline)
                    if status.exitClients.isEmpty {
                        Text(Copy.text("No device has selected this Mac as its exit.", "目前没有设备选择本机作为出口。"))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(status.exitClients) { client in
                            HStack(alignment: .top, spacing: 8) {
                                Image(systemName: exitClientIcon(client.state))
                                    .foregroundStyle(exitClientColor(client.state))
                                    .accessibilityHidden(true)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("\(client.name)  \(client.meshIP)")
                                        .lineLimit(1)
                                    Text(exitClientState(client.state))
                                        .font(.caption)
                                        .foregroundStyle(exitClientColor(client.state))
                                }
                                Spacer()
                            }
                        }
                    }
                }

                if !remotePeers.isEmpty {
                    Divider()
                    Text(Copy.text("Remote access", "远程访问"))
                        .font(.headline)
                    ForEach(remotePeers) { peer in
                        ViewThatFits(in: .horizontal) {
                            HStack {
                                remotePeerIdentity(peer)
                                Spacer()
                                remoteServiceButtons(peer)
                            }
                            VStack(alignment: .leading, spacing: 5) {
                                remotePeerIdentity(peer)
                                remoteServiceButtons(peer)
                            }
                        }
                    }
                    Text(Copy.text(
                        "The target service must already be enabled. Credentials stay in the selected system app or Keychain.",
                        "目标机器必须已启用对应服务；凭据由系统客户端或钥匙串保存。"
                    ))
                    .font(.caption).foregroundStyle(.secondary)
                }

                Divider()
                Toggle(
                    Copy.text("Keep internet available if RatelMesh fails", "RatelMesh 故障时仍保持联网"),
                    isOn: Binding(
                        get: { status.internetFallback == true },
                        set: { store.setInternetFallback($0) }
                    )
                )
                .toggleStyle(.checkbox)
                Text(status.internetFallback == true
                     ? Copy.text("Direct internet is allowed if the exit or RatelMesh data plane fails. Your real IP may be exposed.", "出口或 RatelMesh 数据通道故障时会自动回到本机直连，真实 IP 可能暴露。")
                     : Copy.text("Leak protection stays fail-closed while an exit is selected.", "使用出口时保持故障即断网，防止真实 IP 泄漏。"))
                    .font(.caption)
                    .foregroundStyle(status.internetFallback == true ? RatelMeshBrand.warning(for: colorScheme) : Color.secondary)
            } else if LocalEnrollment.complete {
                Label(Copy.text("Daemon not running", "后台服务未运行"), systemImage: "exclamationmark.triangle")
                    .foregroundStyle(RatelMeshBrand.warning(for: colorScheme))
                Text(Copy.text(
                    "This device is registered, but the background service is unavailable.",
                    "这台设备已经注册，但后台服务当前不可用。"
                ))
                .font(.caption)
                .foregroundStyle(.secondary)
            }

            Divider()
            Button {
                showingNetworkDoctor = true
            } label: {
                Label(Copy.text("Network Doctor", "一键网络医生"), systemImage: "stethoscope")
            }
            .accessibilityHint(Copy.text(
                "Checks connectivity and creates a redacted support report.",
                "检查连接并生成脱敏支持报告。"
            ))

            Divider()
            VStack(alignment: .leading, spacing: 7) {
                HStack {
                    Toggle(Copy.text("Automatic updates", "自动更新"), isOn: $updater.automaticUpdates)
                        .toggleStyle(.checkbox)
                    Spacer()
                    Button(Copy.text("Check now", "检查更新")) {
                        Task { await updater.check(manual: true) }
                    }
                    .disabled(updater.phase.busy)
                }
                updateStatus
            }

            Divider()
            VStack(spacing: 8) {
                let connection = localConnectionPhase(
                    status: store.status,
                    reachable: store.reachable,
                    locallyEnrolled: LocalEnrollment.complete
                )
                HStack {
                    Circle().fill(connectionColor(connection)).frame(width: 9, height: 9)
                        .accessibilityHidden(true)
                    Text(connectionText(connection))
                        .foregroundStyle(.secondary)
                    Spacer()
                    Text("v\(ProductInfo.version)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .accessibilityLabel(Copy.format("Version %@", "版本 %@", ProductInfo.version))
                }
                ViewThatFits(in: .horizontal) {
                    lifecycleButtons
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Button(Copy.text("Privacy center…", "隐私中心…")) { LocationPrivacyReminder.openPrivacyCenter() }
                            Button(Copy.text("Location settings…", "定位设置…")) { LocationPrivacyReminder.openSettings() }
                        }
                        HStack {
                            Button(Copy.text("Help", "帮助")) { ProductInfo.openHelp() }
                            Button(Copy.text("Uninstall…", "卸载…")) { ProductLifecycle.confirmUninstall() }
                            Spacer()
                            Button(Copy.text("Quit", "退出")) { NSApplication.shared.terminate(nil) }
                        }
                    }
                }
            }
        }
        .padding(14)
        .tint(RatelMeshBrand.action(for: colorScheme))
        .onAppear {
            if picked.isEmpty { picked = store.status?.activeExit ?? exits.first?.name ?? "" }
        }
        .onChange(of: store.status?.activeExit ?? "") { active in
            if !active.isEmpty { picked = active }
        }
        .onChange(of: exits.map(\.name)) { names in
            if !names.contains(picked) { picked = names.first ?? "" }
        }
        .onChange(of: language) { selected in
            Copy.select(selected)
            store.objectWillChange.send()
        }
        .sheet(isPresented: $showingNetworkDoctor) {
            NetworkDoctorPanel(store: networkDoctor)
        }
    }

    @ViewBuilder
    private func routeButtons(_ status: MeshStatus) -> some View {
        Button(status.activeExit == picked && status.exitTrafficVerified && !picked.isEmpty && store.requestedExit == nil
               ? Copy.text("✓ EXIT verified", "✓ EXIT 已验证")
               : Copy.text("Use EXIT", "使用 EXIT")) {
            if !picked.isEmpty { store.useExit(picked) }
        }
        .buttonStyle(RouteButtonStyle(
            selected: status.activeExit == picked && status.exitTrafficVerified && !picked.isEmpty && store.requestedExit == nil,
            color: RatelMeshBrand.accessibleGreen
        ))
        .disabled(picked.isEmpty || store.requestedExit != nil)

        Button(status.activeExit.isEmpty && status.selectedExit.isEmpty && store.requestedExit == nil
               ? Copy.text("✓ DIRECT verified", "✓ DIRECT 已验证")
               : Copy.text("Use DIRECT", "使用 DIRECT")) {
            store.clearExit()
        }
        .buttonStyle(RouteButtonStyle(
            selected: status.activeExit.isEmpty && status.selectedExit.isEmpty && store.requestedExit == nil,
            color: RatelMeshBrand.accessibleCyan
        ))
        .disabled(store.requestedExit != nil)
    }

    @ViewBuilder
    private func remotePeerIdentity(_ peer: Peer) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(peer.name).lineLimit(1)
            Text("\(peer.meshIP) · \(peer.platform ?? Copy.text("unknown", "未知平台"))")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private func remoteServiceButtons(_ peer: Peer) -> some View {
        HStack {
            ForEach(peer.authorizedRemoteServices) { service in
                Button(remoteServiceLabel(service.kind)) {
                    openRemoteAccess(service)
                }
                .accessibilityLabel(Text(remoteAccessAccessibilityLabel(service, peer: peer)))
            }
        }
    }

    @ViewBuilder
    private var lifecycleButtons: some View {
        HStack {
            Button(Copy.text("Privacy center…", "隐私中心…")) { LocationPrivacyReminder.openPrivacyCenter() }
            Button(Copy.text("Location settings…", "定位设置…")) { LocationPrivacyReminder.openSettings() }
            Button(Copy.text("Help", "帮助")) { ProductInfo.openHelp() }
            Button(Copy.text("Uninstall…", "卸载…")) { ProductLifecycle.confirmUninstall() }
            Spacer()
            Button(Copy.text("Quit", "退出")) { NSApplication.shared.terminate(nil) }
        }
    }

    private func openRemoteAccess(_ service: RemoteService) {
        guard let url = RemoteAccessURL.make(service) else { return }
        NSWorkspace.shared.open(url)
    }

    private func remoteServiceLabel(_ kind: String) -> String {
        kind == "vnc" ? Copy.text("Screen", "屏幕") : kind.uppercased()
    }

    private func remoteAccessAccessibilityLabel(_ service: RemoteService, peer: Peer) -> String {
        "\(remoteServiceLabel(service.kind)), \(peer.name.isEmpty ? peer.meshIP : peer.name)"
    }

    private func routeStatus(_ status: MeshStatus, requested: String?) -> String {
        if let requested {
            return requested.isEmpty
                ? Copy.text("Switching to DIRECT…", "正在切换到 DIRECT…")
                : Copy.format("Selecting EXIT · %@…", "正在选择 EXIT · %@…", requested)
        }
        if !status.activeExit.isEmpty {
            if !status.exitTrafficVerified {
                return Copy.text("EXIT route active · verifying traffic…", "EXIT 路由已启用 · 正在验证流量…")
            }
            return Copy.format("EXIT verified · %@", "EXIT 已验证 · %@", status.activeExit)
        }
        if !status.selectedExit.isEmpty {
            return Copy.format("Establishing EXIT · %@…", "正在建立 EXIT · %@…", status.selectedExit)
        }
        return Copy.text("DIRECT verified", "DIRECT 已验证")
    }

    private func connectionText(_ phase: LocalConnectionPhase) -> String {
        switch phase {
        case .disconnected: Copy.text("disconnected", "未连接")
        case .enrollment: Copy.text("waiting for enrollment", "等待输入入网码")
        case .connecting: Copy.text("connecting", "正在连接")
        case .connected: Copy.text("connected", "已连接")
        }
    }

    private func connectionColor(_ phase: LocalConnectionPhase) -> Color {
        switch phase {
        case .disconnected: RatelMeshBrand.critical(for: colorScheme)
        case .enrollment: RatelMeshBrand.action(for: colorScheme)
        case .connecting: RatelMeshBrand.warning(for: colorScheme)
        case .connected: RatelMeshBrand.accessibleGreen
        }
    }

    private func exitClientState(_ state: String) -> String {
        switch state {
        case "active": Copy.text("Verified — traffic is using this EXIT", "已验证——流量正在使用本机出口")
        case "offline": Copy.text("Offline — EXIT is not active", "设备离线——出口未生效")
        default: Copy.text("Selected — waiting for a verified path", "已选择——正在等待通道验证")
        }
    }

    private func exitClientIcon(_ state: String) -> String {
        switch state {
        case "active": "checkmark.seal.fill"
        case "offline": "wifi.slash"
        default: "clock.arrow.circlepath"
        }
    }

    private func exitClientColor(_ state: String) -> Color {
        switch state {
        case "active": RatelMeshBrand.accessibleGreen
        case "offline": .secondary
        default: RatelMeshBrand.warning(for: colorScheme)
        }
    }

    private func completeEnrollment() {
        let code = EnrollmentCode.normalized(enrollmentCode)
        guard EnrollmentCode.valid(code), !enrollmentBusy else { return }
        enrollmentBusy = true
        enrollmentError = ""
        Task {
            do {
                try await PrivilegedEnrollment.run(code: code)
                enrollmentCode = ""
                await store.refresh()
            } catch {
                enrollmentError = enrollmentFailureMessage(error)
            }
            enrollmentBusy = false
        }
    }

    @ViewBuilder
    private var enrollmentPrompt: some View {
        HStack(spacing: 8) {
            RatelMeshBrandMark(size: 20, template: true)
            Text(Copy.text("Waiting for enrollment", "等待注册")).font(.headline)
        }
        .foregroundStyle(.primary)
        .accessibilityElement(children: .combine)
        Text(Copy.text(
            "Paste the one-use code from your RatelMesh account. No Terminal commands are required.",
            "粘贴 RatelMesh 账户生成的一次性入网码，无需使用终端命令。"
        ))
        .font(.caption)
        .foregroundStyle(.secondary)
        SecureField("ratelmesh-xxxx-xxxx-xxxx", text: $enrollmentCode)
            .textFieldStyle(.roundedBorder)
            .privacySensitive()
            .disabled(enrollmentBusy)
        HStack {
            Button(Copy.text("Open account", "打开账户")) {
                guard let url = URL(string: "https://ratelmesh.com/console") else { return }
                NSWorkspace.shared.open(url)
            }
            Button(Copy.text("Complete setup", "完成设置")) {
                completeEnrollment()
            }
            .keyboardShortcut(.defaultAction)
            .disabled(enrollmentBusy || !EnrollmentCode.valid(enrollmentCode))
            if enrollmentBusy { ProgressView().controlSize(.small) }
        }
        if !enrollmentError.isEmpty {
            Text(enrollmentError)
                .font(.caption)
                .foregroundStyle(RatelMeshBrand.critical(for: colorScheme))
        }
    }

    private func enrollmentFailureMessage(_ error: Error) -> String {
        switch error as? EnrollmentFailure {
        case .invalidCode:
            Copy.text(
                "Enter a valid one-use code in the form ratelmesh-xxxx-xxxx-xxxx.",
                "请输入格式为 ratelmesh-xxxx-xxxx-xxxx 的有效一次性入网码。"
            )
        case .authorization:
            Copy.text(
                "Administrator authorization was cancelled. Approve it to finish setup.",
                "管理员授权已取消。请批准授权以完成设置。"
            )
        case .unavailable, .execution, .delivery:
            Copy.text(
                "The secure setup helper is unavailable. Reinstall RatelMesh or contact your administrator.",
                "安全设置助手不可用。请重新安装 RatelMesh 或联系管理员。"
            )
        case .rejected:
            Copy.text(
                "The one-use code was rejected or expired. Request a new code and try again.",
                "一次性入网码已被拒绝或过期。请获取新入网码后重试。"
            )
        case nil:
            Copy.text(
                "Enrollment did not complete. Check your connection and try again.",
                "注册未完成。请检查网络连接后重试。"
            )
        }
    }

    @ViewBuilder
    private var updateStatus: some View {
        switch updater.phase {
        case .idle:
            EmptyView()
        case .checking:
            HStack(spacing: 7) {
                ProgressView().controlSize(.small)
                Text(Copy.text("Checking for updates…", "正在检查更新…"))
            }
            .font(.caption).foregroundStyle(.secondary)
        case .upToDate:
            Text(Copy.text("You have the latest version.", "当前已是最新版本。"))
                .font(.caption).foregroundStyle(.secondary)
        case .available:
            HStack {
                Text(Copy.format("v%@ is available.", "发现 v%@。", updater.manifest?.version ?? ""))
                Spacer()
                Button(Copy.text("Download", "下载")) {
                    Task { await updater.downloadAvailableUpdate() }
                }
            }
            .font(.caption)
        case .downloading:
            HStack(spacing: 7) {
                ProgressView().controlSize(.small)
                Text(Copy.text("Downloading and verifying…", "正在下载并校验…"))
            }
            .font(.caption).foregroundStyle(.secondary)
        case .ready:
            HStack {
                Text(Copy.format("v%@ is ready.", "v%@ 已准备好。", updater.manifest?.version ?? ""))
                Spacer()
                Button(Copy.text("Install", "安装")) { updater.installDownloadedUpdate() }
            }
            .font(.caption)
        case .failed:
            Text(Copy.text(
                updater.failureMessage(chinese: false),
                updater.failureMessage(chinese: true)
            ))
                .font(.caption).foregroundStyle(RatelMeshBrand.critical(for: colorScheme))
        }
    }

    private func localState(_ state: String) -> String {
        switch state {
        case "Running": return Copy.text("Running", "运行中")
        case "Starting": return Copy.text("Starting", "启动中")
        case "Stopped": return Copy.text("Stopped", "已停止")
        default: return Copy.text("Unavailable", "不可用")
        }
    }
}

private struct NetworkDoctorPanel: View {
    @ObservedObject var store: NetworkDoctorStore
    @Environment(\.dismiss) private var dismiss
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label(Copy.text("Network Doctor", "一键网络医生"), systemImage: "stethoscope")
                    .font(.title2.bold())
                Spacer()
                Button(Copy.text("Close", "关闭")) { dismiss() }
            }

            HStack(spacing: 9) {
                if store.phase == .running || store.phase == .executing {
                    ProgressView().controlSize(.small)
                } else {
                    Image(systemName: store.phase == .failed ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                        .foregroundStyle(store.phase == .failed ? RatelMeshBrand.critical(for: colorScheme) : RatelMeshBrand.accessibleGreen)
                        .accessibilityHidden(true)
                }
                VStack(alignment: .leading, spacing: 2) {
                    Text(phaseTitle).font(.headline)
                    Text(phaseDetail).font(.caption).foregroundStyle(.secondary)
                }
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel("\(phaseTitle). \(phaseDetail)")

            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    if store.phase == .idle {
                        GroupBox(Copy.text("Ready to diagnose", "准备诊断")) {
                            VStack(alignment: .leading, spacing: 8) {
                                Text(Copy.text(
                                    "Checks connectivity and creates a redacted support report.",
                                    "检查连接并生成脱敏支持报告。"
                                ))
                                Text(Copy.text(
                                    "Checking Coordinator, Relay, EXIT, WireGuard, MTU, DNS, IP, routes, and video connectivity.",
                                    "正在检查 Coordinator、Relay、EXIT、WireGuard、MTU、DNS、IP、路由和视频连接。"
                                ))
                                .foregroundStyle(.secondary)
                                Text(Copy.text(
                                    "Active tests reveal the request time and current source or EXIT address to RatelMesh-operated test services.",
                                    "主动测试会向 RatelMesh 运营的测试服务显示请求时间以及当前来源地址或 EXIT 地址。"
                                ))
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                    if let diagnosis = store.diagnosis {
                        report(diagnosis.report)
                        repairs(diagnosis)
                    }
                    if let execution = store.execution {
                        results(execution)
                    }
                    if store.phase == .failed {
                        failure
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            Divider()
            HStack {
                if store.phase == .idle {
                    Button(Copy.text("Network Doctor", "一键网络医生")) {
                        Task { await store.run() }
                    }
                    .buttonStyle(.borderedProminent)
                }
                if store.diagnosis != nil {
                    Button(Copy.text("Export redacted report…", "导出脱敏报告…")) {
                        exportReport()
                    }
                    .accessibilityHint(Copy.text(
                        "Exports only the redacted JSON report shown here.",
                        "仅导出当前显示的脱敏 JSON 报告。"
                    ))
                }
                Spacer()
                if store.canRepair {
                    Button(
                        store.diagnosis?.executableRepairs.first?.title
                            ?? Copy.text("Ready", "可执行")
                    ) {
                        store.requestConfirmation()
                    }
                    .buttonStyle(.borderedProminent)
                }
                if store.phase == .failed || store.phase == .finished || store.phase == .review {
                    Button(Copy.text("Run again", "重新诊断")) {
                        Task { await store.run() }
                    }
                }
            }
        }
        .padding(18)
        .frame(width: 560, height: 620)
        .tint(RatelMeshBrand.action(for: colorScheme))
        .confirmationDialog(
            store.diagnosis?.executableRepairs.first?.title
                ?? Copy.text("Ready", "可执行"),
            isPresented: Binding(
                get: { store.phase == .confirming },
                set: { if !$0 && store.phase == .confirming { store.cancelConfirmation() } }
            ),
            titleVisibility: .visible
        ) {
            Button(
                store.diagnosis?.executableRepairs.first?.title
                    ?? Copy.text("Ready", "可执行")
            ) {
                Task { await store.confirmAndRepair() }
            }
            Button(Copy.text("Cancel", "取消"), role: .cancel) { store.cancelConfirmation() }
        } message: {
            Text(store.diagnosis?.executableRepairs.first?.action ?? "")
        }
    }

    @ViewBuilder
    private func report(_ report: NetworkDoctorReport) -> some View {
        GroupBox(Copy.text("Redacted report preview", "脱敏报告预览")) {
            VStack(alignment: .leading, spacing: 8) {
                Grid(alignment: .leading) {
                    GridRow { Text(Copy.text("Result", "结论")).foregroundStyle(.secondary); Text(report.summary.ok ? Copy.text("No issue found", "未发现问题") : Copy.text("Needs attention", "需要处理")) }
                    GridRow { Text(Copy.text("Checks", "检查项")).foregroundStyle(.secondary); Text("\(report.probes.count)") }
                    GridRow { Text(Copy.text("Findings", "发现")).foregroundStyle(.secondary); Text("\(report.summary.totalFindings)") }
                }
                ForEach(report.findings) { finding in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(finding.summary).font(.headline)
                        Text("\(finding.severity.uppercased()) · \(finding.code)")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    .accessibilityElement(children: .combine)
                }
                Text(Copy.text(
                    "Preview and export use only the redacted Network Doctor report. Passwords, keys, and raw addresses are excluded.",
                    "预览和导出只使用 Network Doctor 返回的脱敏报告；不包含密码、密钥或原始地址。"
                ))
                .font(.caption)
                .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 4)
        }
    }

    @ViewBuilder
    private func repairs(_ diagnosis: NetworkDoctorDiagnosis) -> some View {
        let executable = Set(diagnosis.availableRepairs)
        GroupBox(Copy.text("Safe repair plan", "安全修复计划")) {
            VStack(alignment: .leading, spacing: 8) {
                if diagnosis.plan.repairs.isEmpty {
                    Text(Copy.text("No repairs are recommended.", "没有建议的修复。"))
                        .foregroundStyle(.secondary)
                }
                ForEach(diagnosis.plan.repairs) { repair in
                    HStack(alignment: .top) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(repair.title).font(.headline)
                            Text(repair.action).font(.caption).foregroundStyle(.secondary)
                            if repair.rollback?.isEmpty == false {
                                Label(Copy.text("Automatic rollback available", "支持自动回滚"), systemImage: "arrow.uturn.backward.circle")
                                    .font(.caption)
                            }
                        }
                        Spacer()
                        Text(repair.applicable && executable.contains(repair.action) ? Copy.text("Ready", "可执行") : Copy.text("Skipped", "已跳过"))
                            .font(.caption)
                            .foregroundStyle(repair.applicable && executable.contains(repair.action) ? RatelMeshBrand.accessibleGreen : Color.secondary)
                    }
                    .accessibilityElement(children: .combine)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 4)
        }
    }

    @ViewBuilder
    private func results(_ report: NetworkDoctorExecutionReport) -> some View {
        GroupBox(Copy.text("Repair and rollback results", "修复结果与回滚状态")) {
            VStack(alignment: .leading, spacing: 8) {
                ForEach(report.repairs) { repair in
                    VStack(alignment: .leading, spacing: 2) {
                        Label(resultTitle(repair.status), systemImage: resultIcon(repair.status))
                            .font(.headline)
                            .foregroundStyle(repair.needsManualAttention ? RatelMeshBrand.critical(for: colorScheme) : Color.primary)
                        Text(repair.action).font(.caption).foregroundStyle(.secondary)
                        if repair.needsManualAttention {
                            Text(Copy.text(
                                "The current network state is uncertain. Stop making changes and contact your administrator.",
                                "当前网络状态无法确认。请停止继续更改，并联系管理员。"
                            ))
                            .font(.caption)
                            .foregroundStyle(RatelMeshBrand.critical(for: colorScheme))
                        }
                    }
                    .accessibilityElement(children: .combine)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 4)
        }
    }

    private var failure: some View {
        GroupBox(Copy.text("Diagnosis unavailable", "诊断不可用")) {
            VStack(alignment: .leading, spacing: 6) {
                Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(RatelMeshBrand.critical(for: colorScheme))
                Text(Copy.text(
                    "No repair was run. Try again, or update to a client and background service that support Network Doctor.",
                    "没有执行任何修复。你可以重试，或升级到支持 Network Doctor 的客户端与后台服务。"
                ))
                .font(.caption).foregroundStyle(.secondary)
            }
            .padding(.top, 4)
        }
    }

    private func exportReport() {
        guard let report = store.diagnosis?.report,
              let data = try? report.redactedJSON() else { return }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "ratelmesh-network-doctor-redacted.json"
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        try? data.write(to: url, options: .atomic)
    }

    private var phaseTitle: String {
        switch store.phase {
        case .idle: Copy.text("Ready to diagnose", "准备诊断")
        case .running: Copy.text("Checking your network", "正在检查网络")
        case .review, .confirming: Copy.text("Diagnosis complete", "诊断完成")
        case .executing: Copy.text("Applying safe repairs", "正在安全修复")
        case .finished: Copy.text("Repair process complete", "修复流程完成")
        case .failed: Copy.text("Could not complete diagnosis", "无法完成诊断")
        }
    }

    private var phaseDetail: String {
        switch store.phase {
        case .running: Copy.text("Checking Coordinator, Relay, EXIT, WireGuard, MTU, DNS, IP, routes, and video connectivity.", "正在检查 Coordinator、Relay、EXIT、WireGuard、MTU、DNS、IP、路由和视频连接。")
        case .executing: Copy.text("Keep RatelMesh open. Each change is verified and rolled back when needed.", "请保持 RatelMesh 打开；每项更改都会验证并在需要时回滚。")
        case .finished: Copy.text("Review the final status of every repair.", "请查看每项修复的最终状态。")
        default: Copy.text("Device and network identifiers in the report are redacted.", "报告中的设备和网络标识已脱敏。")
        }
    }

    private var errorMessage: String {
        switch store.error {
        case .responseTooLarge: Copy.text("The diagnostic response exceeded the safe size limit.", "诊断响应超出安全大小限制。")
        case .unsupportedSchema: Copy.text("The background service returned an unsupported diagnostic format.", "后台服务返回了不受支持的诊断格式。")
        case .invalidResponse: Copy.text("The background service returned an invalid diagnostic response.", "后台服务返回了无效的诊断响应。")
        case .noApplicableRepairs: Copy.text("There are no repairs that can be run safely.", "当前没有可安全执行的修复。")
        default: Copy.text("This background-service version does not support Network Doctor yet.", "此版本的后台服务暂不支持 Network Doctor。")
        }
    }

    private func resultTitle(_ status: String) -> String {
        switch status {
        case "applied": Copy.text("Applied and verified", "已修复并验证")
        case "rolled_back": Copy.text("Repair failed; rolled back", "修复失败，已回滚")
        case "postcondition_failed": Copy.text("Verification failed; rolled back", "验证失败，已回滚")
        case "snapshot_failed": Copy.text("Could not save state; unchanged", "无法备份状态，未更改")
        case "skipped": Copy.text("Safely skipped", "已安全跳过")
        case "rollback_failed": Copy.text("Rollback failed; manual action required", "回滚失败，需要人工处理")
        default: Copy.text("State uncertain; manual action required", "状态不确定，需要人工处理")
        }
    }

    private func resultIcon(_ status: String) -> String {
        switch status {
        case "applied": "checkmark.seal.fill"
        case "rolled_back", "postcondition_failed": "arrow.uturn.backward.circle.fill"
        case "snapshot_failed", "skipped": "minus.circle.fill"
        default: "exclamationmark.octagon.fill"
        }
    }
}

private struct RouteButtonStyle: ButtonStyle {
    let selected: Bool
    let color: Color

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .foregroundStyle(selected ? Color.white : Color.primary)
            .background(selected ? color.opacity(configuration.isPressed ? 0.75 : 1) : Color.clear)
            .overlay(RoundedRectangle(cornerRadius: 6).stroke(color.opacity(selected ? 0 : 0.65)))
            .clipShape(RoundedRectangle(cornerRadius: 6))
            .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

@MainActor
private enum ProductLifecycle {
    static func confirmUninstall() {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = Copy.text("Uninstall RatelMesh?", "卸载 RatelMesh？")
        alert.informativeText = Copy.text(
            "This stops RatelMesh, restores direct networking, and removes the app, device identity, settings, and logs from this Mac.",
            "这会停止 RatelMesh、恢复本机直连，并删除这台 Mac 上的应用、设备身份、设置和日志。"
        )
        alert.addButton(withTitle: Copy.text("Uninstall", "卸载"))
        alert.addButton(withTitle: Copy.text("Cancel", "取消"))
        guard alert.runModal() == .alertFirstButtonReturn else { return }

        let helper = "/usr/local/ratelmesh/bin/ratelmesh-uninstall"
        do {
            try TrustedPrivilegedHelper.validate(helper)
        } catch {
            showUninstallFailure()
            return
        }
        var error: NSDictionary?
        let script = NSAppleScript(source: "do shell script \"\(helper)\" with administrator privileges")
        script?.executeAndReturnError(&error)
        if let error {
            _ = error
            showUninstallFailure()
            return
        }
        NSApplication.shared.terminate(nil)
    }

    private static func showUninstallFailure() {
        let failure = NSAlert()
        failure.alertStyle = .critical
        failure.messageText = Copy.text("Uninstall did not finish", "卸载未完成")
        failure.informativeText = Copy.text(
            "Administrator authorization was cancelled or the uninstall helper failed.",
            "管理员授权被取消，或卸载程序执行失败。"
        )
        failure.runModal()
    }
}

@MainActor
private enum LocationPrivacyReminder {
    private static let reminderKey = "locationPrivacyReminder.0.1.22"

    static func showIfNeeded() {
        guard !UserDefaults.standard.bool(forKey: reminderKey) else { return }
        let alert = NSAlert()
        alert.alertStyle = .informational
        alert.messageText = Copy.text("Review location privacy", "检查定位隐私")
        alert.informativeText = Copy.text(
            "An exit device changes your public IP address, but it does not change this Mac’s system location. If you do not want websites to receive your physical location, review Location Services and browser permissions.",
            "出口设备只会改变公网 IP，不会改变这台 Mac 的系统定位。如果不希望网站获取实际位置，请检查“定位服务”和浏览器的定位权限。"
        )
        alert.addButton(withTitle: Copy.text("Open Privacy Center", "打开隐私中心"))
        alert.addButton(withTitle: Copy.text("Got it", "知道了"))
        alert.addButton(withTitle: Copy.text("Remind me next time", "下次提醒"))
        let response = alert.runModal()
        if response == .alertFirstButtonReturn {
            UserDefaults.standard.set(true, forKey: reminderKey)
            openPrivacyCenter()
        } else if response == .alertSecondButtonReturn {
            UserDefaults.standard.set(true, forKey: reminderKey)
        }
    }

    static func openSettings() {
        guard let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_LocationServices") else { return }
        NSWorkspace.shared.open(url)
    }

    static func openPrivacyCenter() {
        guard let url = URL(string: "https://ratelmesh.com/privacy") else { return }
        NSWorkspace.shared.open(url)
    }
}

@MainActor
private final class AppDelegate: NSObject, NSApplicationDelegate {
    private let store = Store()
    private let updater = UpdateStore()
    private let popover = NSPopover()
    private var statusItem: NSStatusItem?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApplication.shared.setActivationPolicy(.accessory)
        installStatusItem()

        DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
            LocationPrivacyReminder.showIfNeeded()
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        if let statusItem {
            NSStatusBar.system.removeStatusItem(statusItem)
        }
        statusItem = nil
    }

    func applicationShouldHandleReopen(
        _ sender: NSApplication,
        hasVisibleWindows flag: Bool
    ) -> Bool {
        showPopover()
        return false
    }

    private func installStatusItem() {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        guard let button = item.button else {
            NSStatusBar.system.removeStatusItem(item)
            return
        }

        button.image = RatelMeshBrandAssets.image(size: 18, template: true)
        button.imagePosition = .imageOnly
        button.toolTip = "RatelMesh"
        button.setAccessibilityLabel("RatelMesh")
        button.target = self
        button.action = #selector(togglePopover(_:))
        button.sendAction(on: [.leftMouseUp])

        popover.behavior = .transient
        popover.animates = false
        popover.contentSize = NSSize(width: 430, height: 720)
        popover.contentViewController = NSHostingController(
            rootView: Panel(store: store, updater: updater)
        )
        statusItem = item
    }

    @objc private func togglePopover(_ sender: Any?) {
        if popover.isShown {
            popover.performClose(sender)
        } else {
            showPopover()
        }
    }

    private func showPopover() {
        guard let button = statusItem?.button else { return }
        popover.show(
            relativeTo: button.bounds,
            of: button,
            preferredEdge: .minY
        )
        popover.contentViewController?.view.window?.makeKey()
    }
}

@main
private struct RatelMeshMenuApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    var body: some Scene {
        Settings {
            EmptyView()
        }
    }
}
