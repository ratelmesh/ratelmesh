import AppKit
	import CoreLocation
import SwiftUI

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
        case system, chinese, english
        var id: String { rawValue }
    }

    static var language: Language {
        Language(rawValue: UserDefaults.standard.string(forKey: "ratelmesh.language") ?? "system") ?? .system
    }

    static var chinese: Bool {
        switch language {
        case .chinese: true
        case .english: false
        case .system: Locale.preferredLanguages.first?.lowercased().hasPrefix("zh") == true
        }
    }

    static func text(_ english: String, _ chinese: String) -> String {
        Self.chinese ? chinese : english
    }

    static func select(_ language: Language) {
        UserDefaults.standard.set(language.rawValue, forKey: "ratelmesh.language")
    }

    static func languageName(_ language: Language) -> String {
        switch language {
        case .system: text("System", "跟随系统")
        case .chinese: "简体中文"
        case .english: "English"
        }
    }
}

private enum LocalEnrollment {
    static var complete: Bool {
        FileManager.default.fileExists(atPath: "/var/db/ratelmesh/enrolled")
    }
}

@MainActor
private final class Store: ObservableObject {
    @Published var status: MeshStatus?
    @Published var reachable = true
    @Published var requestedExit: String?
    private let base = URL(string: "http://127.0.0.1:8088")!
    private var timer: Timer?
	private var locationReporter: SystemLocationReporter?

    init() {
		locationReporter = SystemLocationReporter { [weak self] coordinate in
			self?.reportSystemLocation(coordinate)
		}
		locationReporter?.start()
        Task { await refresh() }
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in await self?.refresh() }
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

    deinit { timer?.invalidate() }

    func refresh() async {
        do {
            let (data, response) = try await URLSession.shared.data(from: base.appending(path: "/localapi/status"))
            guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw URLError(.badServerResponse) }
            status = try JSONDecoder().decode(MeshStatus.self, from: data)
            reachable = true
        } catch {
            reachable = false
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

private struct Panel: View {
    @ObservedObject var store: Store
    @ObservedObject var updater: UpdateStore
    @State private var picked = ""
    @State private var enrollmentCode = ""
    @State private var enrollmentBusy = false
    @State private var enrollmentError = ""
    @State private var language = Copy.language

    private var exits: [Peer] {
        store.status?.peers.filter { $0.role == "exit" } ?? []
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Label("RatelMesh", systemImage: "shield.lefthalf.filled")
                    .font(.headline)
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
                let remotePeers = status.peers.filter { $0.remoteAccessAllowed == true && !$0.meshIP.isEmpty }
                let exitVerificationPending = !status.activeExit.isEmpty && !status.exitTrafficVerified
                let routePending = store.requestedExit != nil || (!status.selectedExit.isEmpty && status.activeExit.isEmpty) || exitVerificationPending
                let routeVerified = store.requestedExit == nil && (status.exitTrafficVerified || (status.selectedExit.isEmpty && status.activeExit.isEmpty))
                let routeColor: Color = routePending ? .orange : (status.activeExit.isEmpty ? .blue : .green)
                HStack(spacing: 7) {
                    if routePending { ProgressView().controlSize(.small) }
                    else { Image(systemName: routeVerified ? "checkmark.seal.fill" : "exclamationmark.triangle.fill").foregroundStyle(routeColor) }
                    Text(routeStatus(status, requested: store.requestedExit))
                        .font(.headline)
                }
                .padding(9)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(routeColor.opacity(0.10), in: RoundedRectangle(cornerRadius: 9))

                Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 5) {
                    GridRow { Text(Copy.text("State", "状态")).foregroundStyle(.secondary); Text(localState(status.state)) }
                    GridRow { Text(Copy.text("This device", "本机")).foregroundStyle(.secondary); Text("\(status.selfNode.meshIP)  \(status.selfNode.name)").lineLimit(1) }
                    GridRow { Text(Copy.text("Exit", "出口")).foregroundStyle(.secondary); Text(status.activeExit.isEmpty ? (status.selectedExit.isEmpty ? Copy.text("none (direct)", "无（直连）") : Copy.text("connecting \(status.selectedExit)", "正在连接 \(status.selectedExit)")) : status.activeExit).lineLimit(1) }
                    GridRow { Text(Copy.text("Leak protection", "泄漏保护")).foregroundStyle(.secondary); Text(status.killSwitch ? Copy.text("On", "已开启") : Copy.text("Off", "关闭")) }
                }

                Divider()
                Picker(Copy.text("Exit device", "出口设备"), selection: $picked) {
                    ForEach(exits) { peer in
                        Text("\(peer.name) (\(peer.meshIP))").tag(peer.name)
                    }
                }
                .disabled(exits.isEmpty)
                HStack {
                    Button(status.activeExit == picked && status.exitTrafficVerified && !picked.isEmpty && store.requestedExit == nil
                           ? Copy.text("✓ EXIT verified", "✓ EXIT 已验证")
                           : Copy.text("Use EXIT", "使用 EXIT")) {
                        if !picked.isEmpty { store.useExit(picked) }
                    }
                    .buttonStyle(RouteButtonStyle(selected: status.activeExit == picked && status.exitTrafficVerified && !picked.isEmpty && store.requestedExit == nil, color: .green))
                    .disabled(picked.isEmpty || store.requestedExit != nil)
                    Button(status.activeExit.isEmpty && status.selectedExit.isEmpty && store.requestedExit == nil
                           ? Copy.text("✓ DIRECT verified", "✓ DIRECT 已验证")
                           : Copy.text("Use DIRECT", "使用 DIRECT")) { store.clearExit() }
                        .buttonStyle(RouteButtonStyle(selected: status.activeExit.isEmpty && status.selectedExit.isEmpty && store.requestedExit == nil, color: .blue))
                        .disabled(store.requestedExit != nil)
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
                        HStack {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(peer.name).lineLimit(1)
                                Text("\(peer.meshIP) · \(peer.platform ?? Copy.text("unknown", "未知平台"))")
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            if peer.platform == "windows" {
                                Button("RDP") { openRemoteAccess("rdp", peer: peer) }
                                Button("SSH") { openRemoteAccess("ssh", peer: peer) }
                            } else if peer.platform == "macos" {
                                Button(Copy.text("Screen", "屏幕")) { openRemoteAccess("vnc", peer: peer) }
                                Button("SSH") { openRemoteAccess("ssh", peer: peer) }
                            } else if peer.platform == "linux" {
                                Button("SSH") { openRemoteAccess("ssh", peer: peer) }
                                Button("VNC") { openRemoteAccess("vnc", peer: peer) }
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
                    .foregroundStyle(status.internetFallback == true ? Color.orange : Color.secondary)
            } else if LocalEnrollment.complete {
                Label(Copy.text("Daemon not running", "后台服务未运行"), systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
                Text(Copy.text(
                    "This device is registered, but the background service is unavailable.",
                    "这台设备已经注册，但后台服务当前不可用。"
                ))
                .font(.caption)
                .foregroundStyle(.secondary)
            }

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
                    Text(connectionText(connection))
                        .foregroundStyle(.secondary)
                    Spacer()
                    Text("v\(ProductInfo.version)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .accessibilityLabel(Copy.text("Version \(ProductInfo.version)", "版本 \(ProductInfo.version)"))
                }
                HStack {
                    Button(Copy.text("Privacy center…", "隐私中心…")) { LocationPrivacyReminder.openPrivacyCenter() }
                    Button(Copy.text("Location settings…", "定位设置…")) { LocationPrivacyReminder.openSettings() }
                    Button(Copy.text("Help", "帮助")) { ProductInfo.openHelp() }
                    Button(Copy.text("Uninstall…", "卸载…")) { ProductLifecycle.confirmUninstall() }
                    Spacer()
                    Button(Copy.text("Quit", "退出")) { NSApplication.shared.terminate(nil) }
                }
            }
        }
        .padding(14)
        .frame(width: 430)
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
    }

    private func openRemoteAccess(_ scheme: String, peer: Peer) {
        let host = peer.meshIP.contains(":") ? "[\(peer.meshIP)]" : peer.meshIP
        guard ["ssh", "rdp", "vnc"].contains(scheme), let url = URL(string: "\(scheme)://\(host)") else { return }
        NSWorkspace.shared.open(url)
    }

    private func routeStatus(_ status: MeshStatus, requested: String?) -> String {
        if let requested {
            return requested.isEmpty
                ? Copy.text("Switching to DIRECT…", "正在切换到 DIRECT…")
                : Copy.text("Selecting EXIT · \(requested)…", "正在选择 EXIT · \(requested)…")
        }
        if !status.activeExit.isEmpty {
            if !status.exitTrafficVerified {
                return Copy.text("EXIT route active · verifying traffic…", "EXIT 路由已启用 · 正在验证流量…")
            }
            return Copy.text("EXIT verified · \(status.activeExit)", "EXIT 已验证 · \(status.activeExit)")
        }
        if !status.selectedExit.isEmpty {
            return Copy.text("Establishing EXIT · \(status.selectedExit)…", "正在建立 EXIT · \(status.selectedExit)…")
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
        case .disconnected: .red
        case .enrollment: .blue
        case .connecting: .orange
        case .connected: .green
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
        case "active": .green
        case "offline": .secondary
        default: .orange
        }
    }

    private func completeEnrollment() {
        let code = EnrollmentCode.normalized(enrollmentCode)
        guard EnrollmentCode.valid(code), !enrollmentBusy else { return }
        enrollmentBusy = true
        enrollmentError = ""
        Task {
            do {
                _ = try await PrivilegedEnrollment.run(code: code)
                enrollmentCode = ""
                await store.refresh()
            } catch {
                enrollmentError = Copy.chinese
                    ? "注册未完成：\(error.localizedDescription)"
                    : "Enrollment did not complete: \(error.localizedDescription)"
            }
            enrollmentBusy = false
        }
    }

    @ViewBuilder
    private var enrollmentPrompt: some View {
        Label(Copy.text("Waiting for enrollment", "等待注册"), systemImage: "shield.lefthalf.filled")
            .foregroundStyle(.blue)
        Text(Copy.text(
            "Paste the one-use code from your RatelMesh account. No Terminal commands are required.",
            "粘贴 RatelMesh 账户生成的一次性入网码，无需使用终端命令。"
        ))
        .font(.caption)
        .foregroundStyle(.secondary)
        SecureField("ratelmesh-xxxx-xxxx-xxxx", text: $enrollmentCode)
            .textFieldStyle(.roundedBorder)
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
                .foregroundStyle(.red)
                .textSelection(.enabled)
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
                Text(Copy.text("v\(updater.manifest?.version ?? "") is available.", "发现 v\(updater.manifest?.version ?? "")。"))
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
                Text(Copy.text("v\(updater.manifest?.version ?? "") is ready.", "v\(updater.manifest?.version ?? "") 已准备好。"))
                Spacer()
                Button(Copy.text("Install", "安装")) { updater.installDownloadedUpdate() }
            }
            .font(.caption)
        case .failed:
            Text(updater.failureMessage(chinese: Copy.chinese))
                .font(.caption).foregroundStyle(.red)
        }
    }

    private func localState(_ state: String) -> String {
        guard Copy.chinese else { return state }
        switch state {
        case "Running": return "运行中"
        case "Starting": return "启动中"
        case "Stopped": return "已停止"
        default: return state
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

        var error: NSDictionary?
        let script = NSAppleScript(source: "do shell script \"/usr/local/ratelmesh/bin/ratelmesh-uninstall\" with administrator privileges")
        script?.executeAndReturnError(&error)
        if let error {
            let failure = NSAlert()
            failure.alertStyle = .critical
            failure.messageText = Copy.text("Uninstall did not finish", "卸载未完成")
            failure.informativeText = (error[NSAppleScript.errorMessage] as? String)
                ?? Copy.text("Administrator authorization was cancelled or the uninstall helper failed.", "管理员授权被取消，或卸载程序执行失败。")
            failure.runModal()
            return
        }
        NSApplication.shared.terminate(nil)
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

private final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
            LocationPrivacyReminder.showIfNeeded()
        }
    }
}

@main
private struct RatelMeshMenuApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var store = Store()
    @StateObject private var updater = UpdateStore()

    var body: some Scene {
        MenuBarExtra {
            Panel(store: store, updater: updater)
        } label: {
            Label("RatelMesh", systemImage: "shield.lefthalf.filled")
        }
        .menuBarExtraStyle(.window)
    }
}
