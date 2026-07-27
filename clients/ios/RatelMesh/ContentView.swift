import NetworkExtension
import SwiftUI
import UIKit

private enum RatelMeshBrand {
    static let black = Color(red: 11 / 255, green: 15 / 255, blue: 20 / 255)
    static let white = Color(red: 244 / 255, green: 247 / 255, blue: 249 / 255)
    static let cyan = Color(red: 32 / 255, green: 185 / 255, blue: 232 / 255)
    static let accessibleCyan = Color(red: 0 / 255, green: 106 / 255, blue: 140 / 255)
    static let accessibleGreen = Color(red: 0 / 255, green: 106 / 255, blue: 78 / 255)

    static func action(for colorScheme: ColorScheme) -> Color {
        colorScheme == .dark ? cyan : accessibleCyan
    }

    static func success(for colorScheme: ColorScheme) -> Color {
        colorScheme == .dark ? Color(red: 102 / 255, green: 222 / 255, blue: 175 / 255) : accessibleGreen
    }
}

struct ContentView: View {
    @ObservedObject var model: AppViewModel
    @Binding var language: ProductLanguage
    @AppStorage("geographicPrivacyAcknowledgedV1") private var privacyAcknowledged = false
    @State private var showingPrivacy = false
    @State private var showingNetworkDoctor = false
    @Environment(\.colorScheme) private var colorScheme
    @Environment(\.openURL) private var openURL

    var body: some View {
        NavigationStack {
            List {
                Section {
                    statusCard
                }
                .listRowBackground(Color.clear)
                .listRowInsets(EdgeInsets())

                if model.requiresReEnrollment {
                    Section(t("需要重新入网", "Enrollment required")) {
                        Text(t(
                            "入网授权已过期或被撤销。请断开连接，然后输入新的一次性入网码。",
                            "Your enrollment expired or was revoked. Disconnect and enter a new one-use code."
                        ))
                        Button(t("重新入网此设备", "Re-enroll this device")) {
                            model.beginReEnrollment()
                        }
                    }
                }

                Section {
                    HStack(spacing: 10) {
                        if model.requestedExit != nil { ProgressView() }
                        else if !model.activeExit.isEmpty && model.meshStatus?.exitTrafficVerified != true { ProgressView() }
                        else {
                            Image(systemName: model.isConnected && !model.requiresReEnrollment ? "checkmark.circle.fill" : "wifi.slash")
                                .foregroundStyle(routeIndicatorColor)
                                .accessibilityHidden(true)
                        }
                        VStack(alignment: .leading, spacing: 3) {
                            Text(t("当前互联网线路", "CURRENT INTERNET ROUTE"))
                                .font(.caption).foregroundStyle(.secondary)
                            Text(routeStatus).font(.headline)
                        }
                    }

                    Button {
                        Task { await model.selectExit("") }
                    } label: {
                        exitRow(
                            name: t("使用直连 DIRECT", "Use DIRECT"),
                            detail: t("不使用出口设备", "Do not use an exit device"),
                            selected: shownExit.isEmpty
                        )
                    }
                    .buttonStyle(.plain)
                    .disabled(model.requestedExit != nil || model.requiresReEnrollment)

                    ForEach(model.exits) { exit in
                        Button {
                            Task { await model.selectExit(exit.name) }
                        } label: {
                            exitRow(
                                name: exit.name,
                                detail: exit.online ? "\(exit.meshIP) · \(t("在线", "Online"))" : "\(exit.meshIP) · \(t("离线", "Offline"))",
                                selected: shownExit == exit.name
                            )
                        }
                        .buttonStyle(.plain)
                        .disabled(!exit.online || model.requestedExit != nil || model.requiresReEnrollment)
                    }

                    if model.exits.isEmpty {
                        Text(model.isConnected ? t("暂未发现出口设备", "No exit devices are available") : t("连接后显示可用出口", "Available exits appear after connecting"))
                            .foregroundStyle(.secondary)
                    }
                } header: { Text(t("互联网线路", "Internet route")) }

                if model.isConnected, !model.requiresReEnrollment, let status = model.meshStatus {
                    Section(t("网络", "Network")) {
                        LabeledContent(t("控制核心", "Control core"), value: localizedCoreState(status.state))
                        LabeledContent(t("设备", "Devices"), value: "\(status.peers.count + 1)")
                        LabeledContent(t("当前线路", "Current route"), value: status.activeExit.isEmpty ? "DIRECT" : "EXIT · \(status.activeExit)")
                    }
                }

                if model.isConnected, !model.requiresReEnrollment,
                   let peers = model.meshStatus?.peers.filter({ !$0.authorizedRemoteServices.isEmpty }),
                   !peers.isEmpty {
                    Section(t("远程访问", "Remote access")) {
                        ForEach(peers) { peer in
                            VStack(alignment: .leading, spacing: 6) {
                                Text(peer.name.isEmpty ? peer.meshIP : peer.name).font(.headline)
                                Text("\(peer.meshIP) · \(peer.platform ?? t("未知平台", "Unknown platform"))")
                                    .font(.caption).foregroundStyle(.secondary)
                                remoteServiceButtons(peer)
                            }
                        }
                        Text(t("目标机器必须已启用对应服务；凭据由所选远程访问应用或系统钥匙串管理。", "The target service must already be enabled. Credentials stay in the selected app or system Keychain."))
                            .font(.footnote).foregroundStyle(.secondary)
                    }
                }

                if model.isConnected, !model.requiresReEnrollment,
                   let exitClients = model.meshStatus?.exitClients,
                   !exitClients.isEmpty {
                    Section(t("正在使用本机出口的设备", "Devices using this EXIT")) {
                        ForEach(exitClients) { client in
                            LabeledContent(client.name.isEmpty ? client.meshIP : client.name) {
                                Text(exitClientState(client.state))
                                    .foregroundStyle(client.state == "active" ? RatelMeshBrand.success(for: colorScheme) : .secondary)
                            }
                        }
                    }
                }

                Section(t("隐私", "Privacy")) {
                    Button(t("地理位置隐私", "Geographic privacy"), systemImage: "location.slash") {
                        showingPrivacy = true
                    }
                }

                Section(t("支持", "Support")) {
                    Button(t("一键网络医生", "Network Doctor"), systemImage: "stethoscope") {
                        showingNetworkDoctor = true
                    }
                    Text(t(
                        "检查连接、生成脱敏报告，并在你确认后执行可回滚的安全修复。",
                        "Check connectivity, create a redacted report, and run rollback-safe repairs only after you confirm."
                    ))
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("RatelMesh")
            .tint(RatelMeshBrand.action(for: colorScheme))
            .toolbar {
                Button(t("设置", "Settings"), systemImage: "gearshape") { model.showingSettings = true }
            }
            .sheet(isPresented: $model.showingSettings) {
                settings
            }
            .sheet(isPresented: $showingPrivacy) {
                privacyGuide
            }
            .sheet(isPresented: $showingNetworkDoctor) {
                NetworkDoctorView(store: model.networkDoctor, language: language)
            }
            .onAppear {
                if !privacyAcknowledged && !model.showingSettings { showingPrivacy = true }
            }
            .onChange(of: model.showingSettings) { isShowing in
                if !isShowing && !privacyAcknowledged { showingPrivacy = true }
            }
            .alert(t("操作失败", "Operation failed"), isPresented: Binding(
                get: { model.errorCode != nil },
                set: { if !$0 { model.acknowledgeError() } }
            )) {
                Button(t("好", "OK")) {}
            } message: {
                Text(TunnelErrorCopy.message(for: model.errorCode ?? .unknownProviderError, language: language))
            }
        }
    }

    private var privacyGuide: some View {
        NavigationStack {
            List {
                Section(t("系统定位", "System location")) {
                    Text(t("VPN 出口只改变公网 IP，不会替换 iPhone 或 iPad 的系统定位。请在“设置 → 隐私与安全性 → 定位服务”中，将非必要应用设为“永不”“下次询问”，或只提供模糊位置。", "A VPN exit changes your public IP, not the iPhone or iPad system location. Review Settings → Privacy & Security → Location Services and limit location access for apps that do not need it."))
                }
                Section(t("浏览器和 WebRTC", "Browser and WebRTC")) {
                    Text(t("在 Safari、Chrome 或 Brave 中，将网站定位权限设为拒绝或每次询问。RatelMesh 接管 VPN 网络路由，但不能替浏览器修改网站权限。", "Set website location permission to Deny or Ask in Safari, Chrome or Brave. RatelMesh controls VPN routing but cannot change browser permissions."))
                }
                Section(t("Wi-Fi、蓝牙和广告", "Wi-Fi, Bluetooth and advertising")) {
                    Text(t("在“定位服务 → 系统服务”中检查网络与无线功能；在“跟踪”中关闭不需要的应用权限。关闭这些功能可能影响地图、查找和附近设备。", "Review networking and wireless options under Location Services → System Services, and disable unnecessary app tracking permissions. These changes can affect maps, Find My and nearby devices."))
                }
                Section {
                    Button(t("打开 RatelMesh 系统设置", "Open RatelMesh system settings")) {
                        if let url = URL(string: UIApplication.openSettingsURLString) { openURL(url) }
                    }
                    Button(t("知道了", "Got it")) {
                        privacyAcknowledged = true
                        showingPrivacy = false
                    }
                    Button(t("下次提醒", "Remind me next time")) { showingPrivacy = false }
                }
                Section {
                    Text(t("iOS 不允许第三方应用静默关闭全局定位、Wi-Fi 扫描、蓝牙或其他应用的权限。RatelMesh 只提供风险说明和设置入口，由用户确认。", "iOS does not allow third-party apps to silently disable global location, Wi-Fi scanning, Bluetooth or another app's permissions. RatelMesh explains the risk and opens Settings; you remain in control."))
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            .navigationTitle(t("地理位置隐私", "Geographic privacy"))
            .navigationBarTitleDisplayMode(.inline)
        }
    }

    private func openRemote(_ scheme: String, _ meshIP: String, _ port: UInt16) {
        guard let url = RemoteAccessURL.make(
            scheme: scheme,
            address: meshIP,
            port: port
        ) else { return }
        openURL(url)
    }

    @ViewBuilder
    private func remoteServiceButtons(_ peer: MobilePeerStatus) -> some View {
        ViewThatFits(in: .horizontal) {
            HStack {
                ForEach(peer.authorizedRemoteServices) { service in
                    remoteServiceButton(service, peer: peer)
                }
            }
            VStack(alignment: .leading) {
                ForEach(peer.authorizedRemoteServices) { service in
                    remoteServiceButton(service, peer: peer)
                }
            }
        }
    }

    private func remoteServiceButton(
        _ service: MobileRemoteService,
        peer: MobilePeerStatus
    ) -> some View {
        let label = service.kind == "vnc" ? t("屏幕", "Screen") : service.kind.uppercased()
        return Button(label) {
            openRemote(service.kind, service.targetMeshIp, service.port)
        }
        .accessibilityLabel(Text(remoteAccessAccessibilityLabel(label, peer: peer)))
    }

    private func remoteAccessAccessibilityLabel(
        _ serviceLabel: String,
        peer: MobilePeerStatus
    ) -> String {
        "\(serviceLabel), \(peer.name.isEmpty ? peer.meshIP : peer.name)"
    }

    private var statusCard: some View {
        VStack(spacing: 18) {
            Image("BrandMarkDark")
                .resizable()
                .scaledToFit()
                .frame(width: 76, height: 76)
                .accessibilityHidden(true)
            VStack(spacing: 4) {
                HStack(spacing: 8) {
                    Circle()
                        .fill(model.isConnected ? RatelMeshBrand.cyan : Color.secondary)
                        .frame(width: 9, height: 9)
                        .accessibilityHidden(true)
                    Text(statusTitle).font(.title2.bold())
                }
                .accessibilityElement(children: .combine)
                Text(statusDetail)
                    .font(.subheadline)
                    .foregroundStyle(RatelMeshBrand.white.opacity(0.72))
            }
            Button {
                if model.isConnected { model.disconnect() }
                else { Task { await model.connect() } }
            } label: {
                Text(model.isConnected ? t("断开", "Disconnect") : t("连接", "Connect"))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
            }
            .buttonStyle(.borderedProminent)
            .tint(model.isConnected ? .red : RatelMeshBrand.action(for: colorScheme))
            .disabled(!model.appGroupReady || model.isBusy || model.isTransitioning)
        }
        .padding(24)
        .frame(maxWidth: .infinity)
        .foregroundStyle(RatelMeshBrand.white)
        .background(RatelMeshBrand.black, in: RoundedRectangle(cornerRadius: 22))
        .overlay(
            RoundedRectangle(cornerRadius: 22)
                .stroke(RatelMeshBrand.cyan.opacity(model.isConnected ? 0.55 : 0.20))
        )
        .padding(.horizontal)
    }

    private func exitRow(name: String, detail: String, selected: Bool) -> some View {
        HStack {
            VStack(alignment: .leading) {
                Text(name).foregroundStyle(.primary)
                Text(detail).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if selected { Image(systemName: "checkmark").foregroundStyle(.tint) }
        }
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }

    private var settings: some View {
        NavigationStack {
            Form {
                Section(t("设备入网", "Device enrollment")) {
                    SecureField(t("一次性入网码", "One-use enrollment code"), text: $model.authKey)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .textContentType(.oneTimeCode)
                        .privacySensitive()
                    TextField(t("设备名", "Device name"), text: $model.hostname)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }
                Section {
                    Text(t("一次性入网码保存在仅本机可用的共享钥匙串中，供 Packet Tunnel Extension 在系统唤醒时读取。", "The enrollment code is stored in the device-only shared Keychain so the Packet Tunnel extension can restore the connection."))
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                Section(t("语言", "Language")) {
                    Picker(t("界面语言", "App language"), selection: $language) {
                        ForEach(ProductLanguage.allCases) { option in
                            Text(option.displayName).tag(option)
                        }
                    }
                }
            }
            .navigationTitle(t("连接设置", "Connection settings"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button(t("取消", "Cancel")) { model.showingSettings = false } }
                ToolbarItem(placement: .confirmationAction) {
                    Button(t("保存", "Save")) { Task { await model.saveSettings() } }
                        .disabled(!model.appGroupReady)
                }
            }
        }
        .interactiveDismissDisabled(model.authKey.isEmpty)
    }

    private var statusTitle: String {
        switch model.vpnStatus {
        case .connected: t("已连接", "Connected")
        case .connecting: t("正在连接", "Connecting")
        case .disconnecting: t("正在断开", "Disconnecting")
        case .reasserting: t("正在恢复连接", "Restoring connection")
        default: t("未连接", "Disconnected")
        }
    }

    private var statusDetail: String {
        if model.requiresReEnrollment {
            return t(
                "重新入网前，设备流量无法使用 RatelMesh。",
                "Device traffic is unavailable until enrollment is renewed."
            )
        }
        guard model.isConnected else {
            return t("设备流量未进入隧道", "Device traffic is not using the tunnel")
        }
        if let active = model.meshStatus?.activeExit, !active.isEmpty {
            return model.meshStatus?.exitTrafficVerified == true
                ? f("互联网线路：EXIT 已验证 · %@", "Internet route: EXIT verified · %@", active)
                : f("已选择 EXIT，正在验证流量 · %@", "EXIT selected; verifying traffic · %@", active)
        }
        if !model.reportedSelectedExit.isEmpty { return f("正在建立 EXIT · %@", "Connecting EXIT · %@", model.reportedSelectedExit) }
        return t("互联网线路：DIRECT 直连", "Internet route: DIRECT")
    }

    private var shownExit: String { model.requestedExit ?? model.reportedSelectedExit }

    private var routeStatus: String {
        if model.requiresReEnrollment {
            return t(
                "重新入网前，设备流量无法使用 RatelMesh。",
                "Device traffic is unavailable until enrollment is renewed."
            )
        }
        guard model.isConnected else {
            return t("设备流量未进入隧道", "Device traffic is not using the tunnel")
        }
        if let requested = model.requestedExit {
            return requested.isEmpty ? t("正在切换到 DIRECT…", "Switching to DIRECT…") : f("正在切换到 EXIT · %@…", "Switching to EXIT · %@…", requested)
        }
        if !model.reportedSelectedExit.isEmpty && model.activeExit.isEmpty {
            return f("正在建立 EXIT · %@…", "Connecting EXIT · %@…", model.reportedSelectedExit)
        }
        if model.activeExit.isEmpty { return t("当前线路：DIRECT 直连", "Current route: DIRECT") }
        return model.meshStatus?.exitTrafficVerified == true
            ? f("当前线路：EXIT 已验证 · %@", "Current route: EXIT verified · %@", model.activeExit)
            : f("已选择 EXIT，正在验证流量 · %@", "EXIT selected; verifying traffic · %@", model.activeExit)
    }

    private func exitClientState(_ state: String) -> String {
        switch state {
        case "active": t("已验证", "Verified")
        case "offline": t("离线", "Offline")
        default: t("正在连接", "Connecting")
        }
    }

    private var routeIndicatorColor: Color {
        guard model.isConnected, !model.requiresReEnrollment else { return .secondary }
        return model.activeExit.isEmpty
            ? RatelMeshBrand.action(for: colorScheme)
            : RatelMeshBrand.success(for: colorScheme)
    }

    private func localizedCoreState(_ state: String) -> String {
        switch state {
        case "Running": t("运行中", "Running")
        case "Starting": t("正在启动", "Starting")
        case "Stopped": t("已停止", "Stopped")
        default: t("不可用", "Unavailable")
        }
    }

    private func t(_ chinese: String, _ english: String) -> String {
        language.localized(english, chineseFallback: chinese)
    }

    private func f(_ chinese: String, _ english: String, _ arguments: CVarArg...) -> String {
        String(format: t(chinese, english), arguments: arguments)
    }
}
