import AppKit
import NetworkExtension
import SwiftUI

private enum MacDestination: String, CaseIterable, Identifiable {
    case overview
    case devices
    case doctor
    case privacy
    case settings

    var id: String { rawValue }
}

private enum MacBrand {
    static let ink = Color(red: 11 / 255, green: 15 / 255, blue: 20 / 255)
    static let cyan = Color(red: 32 / 255, green: 185 / 255, blue: 232 / 255)
    static let green = Color(red: 102 / 255, green: 222 / 255, blue: 175 / 255)
}

struct MacContentView: View {
    @ObservedObject var model: AppViewModel
    @Binding var language: ProductLanguage
    @AppStorage("geographicPrivacyAcknowledgedV1") private var privacyAcknowledged = false
    @State private var selection: MacDestination? = .overview
    @State private var showingPrivacyDisclosure = false
    @Environment(\.openURL) private var openURL

    var body: some View {
        NavigationSplitView {
            List(MacDestination.allCases, selection: $selection) { destination in
                Label(title(for: destination), systemImage: icon(for: destination))
                    .tag(destination)
            }
            .navigationTitle("RatelMesh")
            .navigationSplitViewColumnWidth(min: 190, ideal: 210, max: 250)
        } detail: {
            detail
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(Color(nsColor: .windowBackgroundColor))
                .toolbar {
                    ToolbarItemGroup(placement: .primaryAction) {
                        routeBadge
                        Button {
                            if model.isConnected {
                                model.disconnect()
                            } else {
                                Task { await model.connect() }
                            }
                        } label: {
                            Label(
                                model.isConnected ? t("断开", "Disconnect") : t("连接", "Connect"),
                                systemImage: model.isConnected ? "stop.circle" : "play.circle.fill"
                            )
                        }
                        .disabled(
                            !privacyAcknowledged || !model.appGroupReady
                                || model.isBusy || model.isTransitioning
                        )
                    }
                }
        }
        .navigationSplitViewStyle(.balanced)
        .sheet(isPresented: $showingPrivacyDisclosure) {
            privacyDisclosure
                .frame(minWidth: 600, minHeight: 520)
                .interactiveDismissDisabled(!privacyAcknowledged)
        }
        .alert(
            t("操作失败", "Operation failed"),
            isPresented: Binding(
                get: { model.errorCode != nil },
                set: { if !$0 { model.acknowledgeError() } }
            )
        ) {
            Button(t("好", "OK")) {}
        } message: {
            Text(macErrorMessage)
        }
        .onAppear {
#if DEBUG
            if ProcessInfo.processInfo.environment["RATELMESH_APP_STORE_SCREENSHOTS"] == "1" {
                privacyAcknowledged = true
            }
#endif
            showingPrivacyDisclosure = !privacyAcknowledged
            if model.showingSettings { selection = .settings }
#if DEBUG
            switch ProcessInfo.processInfo.environment["RATELMESH_APP_STORE_SCREEN"] {
            case "devices":
                selection = .devices
            case "doctor":
                selection = .doctor
            case "privacy":
                selection = .privacy
            case "settings":
                selection = .settings
            default:
                break
            }
#endif
        }
        .onChange(of: model.showingSettings) { show in
            if show { selection = .settings }
        }
        .onChange(of: privacyAcknowledged) { acknowledged in
            if acknowledged { showingPrivacyDisclosure = false }
        }
    }

    @ViewBuilder
    private var detail: some View {
        switch selection ?? .overview {
        case .overview:
            overview
        case .devices:
            devices
        case .doctor:
            MacNetworkDoctorView(store: model.networkDoctor, language: language)
        case .privacy:
            privacy
        case .settings:
            settings
        }
    }

    private var overview: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                statusHero
                HStack(alignment: .top, spacing: 18) {
                    routeCard
                    networkCard
                }
                if model.requiresReEnrollment {
                    GroupBox {
                        VStack(alignment: .leading, spacing: 10) {
                            Label(
                                t("需要重新入网", "Enrollment required"),
                                systemImage: "exclamationmark.triangle.fill"
                            )
                            .font(.headline)
                            .foregroundStyle(.orange)
                            Text(t(
                                "入网授权已过期或被撤销。请输入新的一次性入网码。",
                                "Your enrollment expired or was revoked. Enter a new one-use enrollment code."
                            ))
                            Button(t("重新入网此设备", "Re-enroll this device")) {
                                model.beginReEnrollment()
                                selection = .settings
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
            .padding(28)
            .frame(maxWidth: 980, alignment: .leading)
        }
        .navigationTitle(t("概览", "Overview"))
    }

    private var statusHero: some View {
        HStack(spacing: 22) {
            MacBrandMark()
                .scaledToFit()
                .frame(width: 88, height: 88)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 7) {
                HStack(spacing: 8) {
                    Circle()
                        .fill(model.isConnected ? MacBrand.green : .secondary)
                        .frame(width: 10, height: 10)
                    Text(connectionTitle)
                        .font(.system(size: 28, weight: .semibold, design: .rounded))
                }
                Text(connectionDetail)
                    .foregroundStyle(.white.opacity(0.72))
                HStack {
                    Label(
                        shownExit.isEmpty ? "DIRECT" : "EXIT · \(shownExit)",
                        systemImage: shownExit.isEmpty ? "arrow.left.arrow.right" : "network"
                    )
                    if model.meshStatus?.killSwitch == true {
                        Label(t("泄漏保护已开启", "Leak protection on"), systemImage: "checkmark.shield")
                    }
                }
                .font(.callout)
                .foregroundStyle(.white.opacity(0.82))
            }
            Spacer()
            Button {
                if model.isConnected {
                    model.disconnect()
                } else {
                    Task { await model.connect() }
                }
            } label: {
                Text(model.isConnected ? t("断开", "Disconnect") : t("连接", "Connect"))
                    .frame(minWidth: 100)
            }
            .buttonStyle(.borderedProminent)
            .tint(model.isConnected ? .red : MacBrand.cyan)
            .controlSize(.large)
            .disabled(
                !privacyAcknowledged || !model.appGroupReady
                    || model.isBusy || model.isTransitioning
            )
        }
        .padding(26)
        .foregroundStyle(.white)
        .background(
            LinearGradient(
                colors: [MacBrand.ink, MacBrand.ink.opacity(0.91)],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            ),
            in: RoundedRectangle(cornerRadius: 22)
        )
        .overlay(
            RoundedRectangle(cornerRadius: 22)
                .stroke(MacBrand.cyan.opacity(model.isConnected ? 0.52 : 0.18))
        )
    }

    private var routeCard: some View {
        GroupBox(t("互联网线路", "Internet route")) {
            VStack(alignment: .leading, spacing: 12) {
                routeChoice(
                    name: t("使用直连 DIRECT", "Use DIRECT"),
                    detail: t("不使用出口设备", "Do not use an exit device"),
                    exitName: "",
                    enabled: true
                )
                ForEach(model.exits) { exit in
                    routeChoice(
                        name: exit.name,
                        detail: "\(exit.meshIP) · \(exit.online ? t("在线", "Online") : t("离线", "Offline"))",
                        exitName: exit.name,
                        enabled: exit.online
                    )
                }
                if model.exits.isEmpty {
                    Text(
                        model.isConnected
                            ? t("暂未发现出口设备", "No exit devices are available")
                            : t("连接后显示可用出口", "Available exits appear after connecting")
                    )
                    .foregroundStyle(.secondary)
                    .padding(.vertical, 8)
                }
            }
            .padding(.top, 4)
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }

    private var networkCard: some View {
        GroupBox(t("网络", "Network")) {
            Grid(alignment: .leading, horizontalSpacing: 24, verticalSpacing: 13) {
                GridRow {
                    Text(t("状态", "State")).foregroundStyle(.secondary)
                    Text(localizedCoreState(model.meshStatus?.state ?? "Stopped"))
                }
                GridRow {
                    Text(t("设备", "Devices")).foregroundStyle(.secondary)
                    Text("\((model.meshStatus?.peers.count ?? 0) + 1)")
                }
                GridRow {
                    Text(t("当前线路", "Current route")).foregroundStyle(.secondary)
                    Text(shownExit.isEmpty ? "DIRECT" : "EXIT · \(shownExit)")
                }
                GridRow {
                    Text("DNS").foregroundStyle(.secondary)
                    Text(model.meshStatus?.dns ?? "—")
                }
            }
            .padding(.top, 5)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }

    private var devices: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 14) {
                if let peers = model.meshStatus?.peers, !peers.isEmpty {
                    ForEach(peers) { peer in
                        deviceCard(peer)
                    }
                } else {
                    VStack(spacing: 12) {
                        Image(systemName: "desktopcomputer")
                            .font(.system(size: 38))
                            .foregroundStyle(.secondary)
                        Text(t("未发现其他设备", "No other devices"))
                            .font(.title3.bold())
                        Text(t(
                            "连接后显示你的 Mesh 设备。",
                            "Your mesh devices appear after connecting."
                        ))
                        .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 80)
                }
            }
            .padding(28)
            .frame(maxWidth: 980, alignment: .leading)
        }
        .navigationTitle(t("设备", "Devices"))
    }

    private func deviceCard(_ peer: MobilePeerStatus) -> some View {
        GroupBox {
            HStack(alignment: .top, spacing: 15) {
                Image(systemName: deviceIcon(peer.platform))
                    .font(.title2)
                    .frame(width: 32)
                    .foregroundStyle(peer.online ? MacBrand.cyan : .secondary)
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Text(peer.name.isEmpty ? peer.meshIP : peer.name)
                            .font(.headline)
                        Text(peer.online ? t("在线", "Online") : t("离线", "Offline"))
                            .font(.caption)
                            .padding(.horizontal, 7)
                            .padding(.vertical, 3)
                            .background(
                                peer.online ? MacBrand.green.opacity(0.17) : Color.secondary.opacity(0.12),
                                in: Capsule()
                            )
                    }
                    Text("\(peer.meshIP) · \(peer.platform ?? t("未知平台", "Unknown platform"))")
                        .foregroundStyle(.secondary)
                    if !peer.authorizedRemoteServices.isEmpty {
                        HStack {
                            ForEach(peer.authorizedRemoteServices) { service in
                                Button(remoteLabel(service.kind)) {
                                    openRemote(service)
                                }
                                .buttonStyle(.bordered)
                            }
                        }
                    } else {
                        Text(t(
                            "未授权远程访问服务",
                            "No remote access service is authorized"
                        ))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    }
                }
                Spacer()
                Text(peer.pathType?.uppercased() ?? "—")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
            .padding(5)
        }
    }

    private var privacy: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                privacySection(
                    t("RatelMesh 使用的数据", "Data RatelMesh uses"),
                    t(
                        "RatelMesh 会将设备名和设备标识发送给你的 RatelMesh 租户，用于入网和识别本设备。如果你允许定位权限，它只会发送用于私人网络地图的粗略区域。",
                        "RatelMesh sends your device name and a device identifier to your RatelMesh tenant so it can enroll and identify this device. If you allow location access, it sends only a coarse region for the private network map."
                    )
                )
                privacySection(
                    t("不出售或向第三方披露", "No sale or third-party disclosure"),
                    t(
                        "RatelMesh 不会出售这些数据、将其用于第三方目的或向第三方披露，也不会收集浏览内容或明文隧道流量。",
                        "RatelMesh does not sell this data, use it for third-party purposes, or disclose it to third parties. It does not collect browsing content or plaintext tunnel traffic."
                    )
                )
                privacySection(
                    t("系统边界", "System boundary"),
                    t(
                        "Mac App Store 版本使用 Apple Network Extension。只有在你启动 VPN 后，系统才会把选定流量交给 RatelMesh。",
                        "The Mac App Store edition uses Apple Network Extension. macOS gives selected traffic to RatelMesh only after you start the VPN."
                    )
                )
                HStack {
                    if let url = URL(string: "https://ratelmesh.com/privacy") {
                        Link(t("阅读隐私政策", "Read the privacy policy"), destination: url)
                    }
                    Button(t("重新查看隐私说明", "Review privacy disclosure")) {
                        showingPrivacyDisclosure = true
                    }
                }
            }
            .padding(28)
            .frame(maxWidth: 820, alignment: .leading)
        }
        .navigationTitle(t("隐私", "Privacy"))
    }

    private var settings: some View {
        Form {
            Section(t("设备入网", "Device enrollment")) {
                SecureField(t("一次性入网码", "One-use enrollment code"), text: $model.authKey)
                    .privacySensitive()
                TextField(t("设备名", "Device name"), text: $model.hostname)
                LabeledContent(t("协调器", "Coordinator"), value: AppConstants.officialCoordinatorURL)
            }
            Section(t("语言", "Language")) {
                Picker(t("界面语言", "App language"), selection: $language) {
                    ForEach(ProductLanguage.allCases) { option in
                        Text(option.displayName).tag(option)
                    }
                }
                .pickerStyle(.menu)
            }
            Section {
                HStack {
                    Button(t("保存", "Save")) {
                        Task { await model.saveSettings() }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(!model.appGroupReady || model.isBusy)
                    if model.requiresReEnrollment {
                        Text(t(
                            "保存新入网码后重新连接。",
                            "Save the new enrollment code, then connect again."
                        ))
                        .foregroundStyle(.secondary)
                    }
                }
            }
        }
        .formStyle(.grouped)
        .padding(20)
        .frame(maxWidth: 780, maxHeight: .infinity, alignment: .topLeading)
        .navigationTitle(t("连接设置", "Connection settings"))
    }

    private var privacyDisclosure: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(spacing: 14) {
                MacBrandMark()
                    .scaledToFit()
                    .frame(width: 58, height: 58)
                VStack(alignment: .leading) {
                    Text(t("连接前的隐私说明", "Privacy before connecting"))
                        .font(.title2.bold())
                    Text(t(
                        "你的网络属于你。",
                        "Your network remains yours."
                    ))
                    .foregroundStyle(.secondary)
                }
            }
            Divider()
            privacySection(
                t("RatelMesh 使用的数据", "Data RatelMesh uses"),
                t(
                    "RatelMesh 会将设备名和设备标识发送给你的 RatelMesh 租户，用于入网和识别本设备。如果你允许定位权限，它只会发送用于私人网络地图的粗略区域。",
                    "RatelMesh sends your device name and a device identifier to your RatelMesh tenant so it can enroll and identify this device. If you allow location access, it sends only a coarse region for the private network map."
                )
            )
            privacySection(
                t("不出售或向第三方披露", "No sale or third-party disclosure"),
                t(
                    "RatelMesh 不会出售这些数据、将其用于第三方目的或向第三方披露，也不会收集浏览内容或明文隧道流量。",
                    "RatelMesh does not sell this data, use it for third-party purposes, or disclose it to third parties. It does not collect browsing content or plaintext tunnel traffic."
                )
            )
            Spacer()
            HStack {
                if let url = URL(string: "https://ratelmesh.com/privacy") {
                    Link(t("阅读隐私政策", "Read the privacy policy"), destination: url)
                }
                Spacer()
                Button(t("我已了解并继续", "I understand and continue")) {
                    privacyAcknowledged = true
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(28)
    }

    private func routeChoice(
        name: String,
        detail: String,
        exitName: String,
        enabled: Bool
    ) -> some View {
        Button {
            Task { await model.selectExit(exitName) }
        } label: {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(name).foregroundStyle(.primary)
                    Text(detail).font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                if shownExit == exitName {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(MacBrand.cyan)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(!enabled || model.requestedExit != nil || model.requiresReEnrollment)
    }

    private var routeBadge: some View {
        Label(
            shownExit.isEmpty ? "DIRECT" : "EXIT",
            systemImage: shownExit.isEmpty ? "arrow.left.arrow.right" : "network"
        )
        .font(.caption.bold())
        .foregroundStyle(model.isConnected ? MacBrand.green : .secondary)
        .accessibilityLabel(routeStatus)
    }

    private func privacySection(_ title: String, _ body: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.headline)
            Text(body).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func openRemote(_ service: MobileRemoteService) {
        guard let url = RemoteAccessURL.make(
            scheme: service.kind,
            address: service.targetMeshIp,
            port: service.port
        ) else { return }
        openURL(url)
    }

    private func title(for destination: MacDestination) -> String {
        switch destination {
        case .overview: t("概览", "Overview")
        case .devices: t("设备", "Devices")
        case .doctor: t("一键网络医生", "Network Doctor")
        case .privacy: t("隐私", "Privacy")
        case .settings: t("设置", "Settings")
        }
    }

    private func icon(for destination: MacDestination) -> String {
        switch destination {
        case .overview: "gauge.with.dots.needle.50percent"
        case .devices: "desktopcomputer"
        case .doctor: "stethoscope"
        case .privacy: "hand.raised"
        case .settings: "gearshape"
        }
    }

    private func deviceIcon(_ platform: String?) -> String {
        switch platform?.lowercased() {
        case "macos", "darwin": "desktopcomputer"
        case "ios": "iphone"
        case "android": "smartphone"
        case "linux": "server.rack"
        case "windows": "pc"
        default: "network"
        }
    }

    private func remoteLabel(_ kind: String) -> String {
        kind == "vnc" ? t("屏幕", "Screen") : kind.uppercased()
    }

    private var shownExit: String {
        model.requestedExit ?? model.meshStatus?.selectedExit ?? model.activeExit
    }

    private var connectionTitle: String {
        switch model.vpnStatus {
        case .connected: t("已连接", "Connected")
        case .connecting: t("正在连接", "Connecting")
        case .disconnecting: t("正在断开", "Disconnecting")
        case .reasserting: t("正在恢复连接", "Restoring connection")
        default: t("未连接", "Disconnected")
        }
    }

    private var connectionDetail: String {
        if model.requiresReEnrollment {
            return t(
                "重新入网前，设备流量无法使用 RatelMesh。",
                "Device traffic is unavailable until enrollment is renewed."
            )
        }
        if model.isConnected {
            return shownExit.isEmpty
                ? t("通过私人 Mesh 直接连接", "Connected through your private mesh")
                : t("互联网流量使用你选择的出口设备", "Internet traffic uses your selected exit device")
        }
        return t(
            "连接后访问你的设备和私人服务。",
            "Connect to reach your devices and private services."
        )
    }

    private var routeStatus: String {
        shownExit.isEmpty ? "DIRECT" : "EXIT · \(shownExit)"
    }

    private func localizedCoreState(_ state: String) -> String {
        switch state.lowercased() {
        case "running": t("运行中", "Running")
        case "starting": t("启动中", "Starting")
        case "stopped": t("已停止", "Stopped")
        default: state
        }
    }

    private var macErrorMessage: String {
        TunnelErrorCopy.message(
            for: model.errorCode ?? .unknownProviderError,
            language: language
        )
        .replacingOccurrences(of: "iOS", with: "macOS")
    }

    private func t(_ chinese: String, _ english: String) -> String {
        language.localized(english, chineseFallback: chinese)
    }
}

private struct MacBrandMark: View {
    var body: some View {
        if let url = Bundle.main.url(forResource: "BrandMarkDark", withExtension: "png"),
           let image = NSImage(contentsOf: url) {
            Image(nsImage: image)
                .resizable()
        } else {
            Image(systemName: "network")
                .resizable()
                .symbolRenderingMode(.hierarchical)
        }
    }
}
