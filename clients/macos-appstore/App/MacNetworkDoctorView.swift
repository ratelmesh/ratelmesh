import SwiftUI

struct MacNetworkDoctorView: View {
    @ObservedObject var store: NetworkDoctorStore
    let language: ProductLanguage
    @State private var exportURL: URL?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                GroupBox {
                    HStack(spacing: 12) {
                        if store.phase == .running || store.phase == .executing {
                            ProgressView()
                        } else {
                            Image(systemName: phaseIcon)
                                .font(.title2)
                                .foregroundStyle(store.phase == .failed ? .red : .blue)
                        }
                        VStack(alignment: .leading, spacing: 3) {
                            Text(phaseTitle).font(.headline)
                            Text(phaseDetail).foregroundStyle(.secondary)
                        }
                        Spacer()
                    }
                    .padding(5)
                }

                if let report = store.diagnosis?.report {
                    GroupBox(t("脱敏报告预览", "Redacted report preview")) {
                        VStack(alignment: .leading, spacing: 10) {
                            HStack {
                                Label(
                                    report.summary.ok
                                        ? t("未发现问题", "No issue found")
                                        : t("需要处理", "Needs attention"),
                                    systemImage: report.summary.ok
                                        ? "checkmark.circle.fill"
                                        : "exclamationmark.triangle.fill"
                                )
                                Spacer()
                                Text("\(report.probes.count) \(t("项检查", "checks"))")
                                    .foregroundStyle(.secondary)
                            }
                            ForEach(report.findings) { finding in
                                Divider()
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(finding.summary).font(.headline)
                                    Text("\(finding.severity.uppercased()) · \(finding.code)")
                                        .font(.caption.monospaced())
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                        .padding(.top, 4)
                    }
                }

                if let execution = store.execution {
                    GroupBox(t("修复结果与回滚状态", "Repair and rollback results")) {
                        VStack(alignment: .leading, spacing: 8) {
                            ForEach(execution.repairs) { repair in
                                Label(
                                    "\(repair.action) · \(repair.status)",
                                    systemImage: repair.needsManualAttention
                                        ? "exclamationmark.triangle.fill"
                                        : "checkmark.circle"
                                )
                                .foregroundStyle(repair.needsManualAttention ? .red : .primary)
                            }
                        }
                        .padding(.top, 4)
                    }
                }

                if store.phase == .failed {
                    Label(
                        t("无法完成诊断。没有执行任何修复。", "Diagnosis could not complete. No repair was run."),
                        systemImage: "exclamationmark.triangle.fill"
                    )
                    .foregroundStyle(.red)
                }

                HStack {
                    Button {
                        Task { await store.run() }
                    } label: {
                        Label(
                            store.phase == .idle
                                ? t("一键网络医生", "Network Doctor")
                                : t("重新诊断", "Run again"),
                            systemImage: "play.fill"
                        )
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(store.phase == .running || store.phase == .executing)

                    if store.canRepair {
                        Button {
                            store.requestConfirmation()
                        } label: {
                            Label(t("执行安全修复", "Apply safe repair"), systemImage: "wrench.and.screwdriver")
                        }
                    }

                    if let exportURL {
                        ShareLink(item: exportURL) {
                            Label(t("导出脱敏报告", "Export redacted report"), systemImage: "square.and.arrow.up")
                        }
                    }
                }
            }
            .padding(28)
            .frame(maxWidth: 900, alignment: .leading)
        }
        .navigationTitle(t("一键网络医生", "Network Doctor"))
        .confirmationDialog(
            store.diagnosis?.executableRepairs.first?.title
                ?? t("执行安全修复", "Apply safe repair"),
            isPresented: Binding(
                get: { store.phase == .confirming },
                set: {
                    if !$0 && store.phase == .confirming {
                        store.cancelConfirmation()
                    }
                }
            )
        ) {
            Button(
                store.diagnosis?.executableRepairs.first?.title
                    ?? t("执行安全修复", "Apply safe repair")
            ) {
                Task { await store.confirmAndRepair() }
            }
            Button(t("取消", "Cancel"), role: .cancel) {
                store.cancelConfirmation()
            }
        }
        .onAppear { refreshExport() }
        .onChange(of: store.phase) { _ in refreshExport() }
    }

    private func refreshExport() {
        guard let report = store.diagnosis?.report,
              let data = try? report.redactedJSON() else {
            exportURL = nil
            return
        }
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("ratelmesh-network-doctor-redacted.json")
        do {
            try data.write(to: url, options: .atomic)
            exportURL = url
        } catch {
            exportURL = nil
        }
    }

    private var phaseTitle: String {
        switch store.phase {
        case .idle: t("准备诊断", "Ready to diagnose")
        case .running: t("正在检查网络", "Checking your network")
        case .review, .confirming: t("诊断完成", "Diagnosis complete")
        case .executing: t("正在安全修复", "Applying safe repair")
        case .finished: t("修复流程完成", "Repair process complete")
        case .failed: t("无法完成诊断", "Could not complete diagnosis")
        }
    }

    private var phaseDetail: String {
        switch store.phase {
        case .running:
            t(
                "正在检查 Coordinator、Relay、EXIT、WireGuard、MTU、DNS、IP、路由和视频连接。",
                "Checking Coordinator, Relay, EXIT, WireGuard, MTU, DNS, IP, routes, and video connectivity."
            )
        case .executing:
            t(
                "每项更改都会验证，并在需要时回滚。",
                "Each change is verified and rolled back when needed."
            )
        default:
            t(
                "报告中的设备和网络标识已脱敏。",
                "Device and network identifiers in the report are redacted."
            )
        }
    }

    private var phaseIcon: String {
        switch store.phase {
        case .failed: "exclamationmark.triangle.fill"
        case .idle: "stethoscope"
        default: "checkmark.circle.fill"
        }
    }

    private func t(_ chinese: String, _ english: String) -> String {
        language.localized(english, chineseFallback: chinese)
    }
}
