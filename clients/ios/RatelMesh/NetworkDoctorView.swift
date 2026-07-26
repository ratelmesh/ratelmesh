import SwiftUI
import UIKit

struct NetworkDoctorView: View {
    @ObservedObject var store: NetworkDoctorStore
    let language: ProductLanguage
    @Environment(\.dismiss) private var dismiss
    @State private var exportURL: URL?

    var body: some View {
        NavigationStack {
            List {
                Section {
                    phaseHeader
                        .accessibilityElement(children: .combine)
                        .accessibilityLabel(phaseAccessibilityLabel)
                }

                if store.phase == .idle {
                    Section(t("准备诊断", "Ready to diagnose")) {
                        Text(t(
                            "检查连接并生成脱敏支持报告。",
                            "Checks connectivity and creates a redacted support report."
                        ))
                        Text(t(
                            "正在检查 Coordinator、Relay、EXIT、WireGuard、MTU、DNS、IP、路由和视频连接。",
                            "Checking Coordinator, Relay, EXIT, WireGuard, MTU, DNS, IP, routes, and video connectivity."
                        ))
                        .foregroundStyle(.secondary)
                        Text(t(
                            "主动测试会向 RatelMesh 运营的测试服务显示请求时间以及当前来源地址或 EXIT 地址。",
                            "Active tests reveal the request time and current source or EXIT address to RatelMesh-operated test services."
                        ))
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    }
                }

                if let diagnosis = store.diagnosis {
                    reportSection(diagnosis.report)
                    repairSection(diagnosis)
                }
                if let execution = store.execution {
                    resultSection(execution)
                }
                if store.phase == .failed {
                    errorSection
                }

                Section {
                    actions
                }
            }
            .navigationTitle(t("一键网络医生", "Network Doctor"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(t("关闭", "Close")) { dismiss() }
                }
            }
            .confirmationDialog(
                store.diagnosis?.executableRepairs.first?.title
                    ?? t("可执行", "Ready"),
                isPresented: Binding(
                    get: { store.phase == .confirming },
                    set: { if !$0 && store.phase == .confirming { store.cancelConfirmation() } }
                ),
                titleVisibility: .visible
            ) {
                Button(store.diagnosis?.executableRepairs.first?.title
                       ?? t("可执行", "Ready")) {
                    Task { await store.confirmAndRepair() }
                }
                Button(t("取消", "Cancel"), role: .cancel) { store.cancelConfirmation() }
            } message: {
                Text(store.diagnosis?.executableRepairs.first?.action ?? "")
            }
            .onChange(of: store.phase) { _ in
                UIAccessibility.post(notification: .announcement, argument: phaseAccessibilityLabel)
                refreshExport()
            }
            .onAppear { refreshExport() }
        }
    }

    @ViewBuilder
    private var phaseHeader: some View {
        HStack(spacing: 10) {
            if store.phase == .running || store.phase == .executing {
                ProgressView()
            } else {
                Image(systemName: phaseIcon)
                    .foregroundStyle(phaseColor)
                    .accessibilityHidden(true)
            }
            VStack(alignment: .leading, spacing: 3) {
                Text(phaseTitle).font(.headline)
                Text(phaseDetail).font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private func reportSection(_ report: NetworkDoctorReport) -> some View {
        Section(t("脱敏报告预览", "Redacted report preview")) {
            LabeledContent(t("结论", "Result"), value: report.summary.ok ? t("未发现问题", "No issue found") : t("需要处理", "Needs attention"))
            LabeledContent(t("检查项", "Checks"), value: "\(report.probes.count)")
            LabeledContent(t("发现", "Findings"), value: "\(report.summary.totalFindings)")
            ForEach(report.findings) { finding in
                VStack(alignment: .leading, spacing: 4) {
                    Text(finding.summary).font(.headline)
                    Text("\(finding.severity.uppercased()) · \(finding.code)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .accessibilityElement(children: .combine)
            }
            Text(t(
                "预览和导出只使用 Network Doctor 返回的脱敏报告；不包含密码、密钥或原始地址。",
                "Preview and export use only the redacted Network Doctor report. Passwords, keys, and raw addresses are excluded."
            ))
            .font(.footnote)
            .foregroundStyle(.secondary)
        }
    }

    private func repairSection(_ diagnosis: NetworkDoctorDiagnosis) -> some View {
        let executable = Set(diagnosis.availableRepairs)
        return Section(t("安全修复计划", "Safe repair plan")) {
            if diagnosis.plan.repairs.isEmpty {
                Text(t("没有建议的修复。", "No repairs are recommended."))
                    .foregroundStyle(.secondary)
            }
            ForEach(diagnosis.plan.repairs) { repair in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(repair.title).font(.headline)
                        Spacer()
                        Text(repair.applicable && executable.contains(repair.action) ? t("可执行", "Ready") : t("已跳过", "Skipped"))
                            .font(.caption)
                            .foregroundStyle(repair.applicable && executable.contains(repair.action) ? .green : .secondary)
                    }
                    Text(repair.action).font(.caption).foregroundStyle(.secondary)
                    if repair.rollback?.isEmpty == false {
                        Label(t("支持自动回滚", "Automatic rollback available"), systemImage: "arrow.uturn.backward.circle")
                            .font(.caption)
                    }
                }
                .accessibilityElement(children: .combine)
            }
        }
    }

    private func resultSection(_ report: NetworkDoctorExecutionReport) -> some View {
        Section(t("修复结果与回滚状态", "Repair and rollback results")) {
            ForEach(report.repairs) { repair in
                VStack(alignment: .leading, spacing: 4) {
                    Label(resultTitle(repair.status), systemImage: resultIcon(repair.status))
                        .font(.headline)
                        .foregroundStyle(repair.needsManualAttention ? .red : .primary)
                    Text(repair.action).font(.caption).foregroundStyle(.secondary)
                    if repair.needsManualAttention {
                        Text(t(
                            "当前网络状态无法确认。请停止继续更改，并联系管理员。",
                            "The current network state is uncertain. Stop making changes and contact your administrator."
                        ))
                        .font(.caption)
                        .foregroundStyle(.red)
                    }
                }
                .accessibilityElement(children: .combine)
            }
        }
    }

    private var errorSection: some View {
        Section(t("诊断不可用", "Diagnosis unavailable")) {
            Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.red)
            Text(t(
                "没有执行任何修复。你可以重试，或升级到支持 Network Doctor 的客户端与后台服务。",
                "No repair was run. Try again, or update to a client and background service that support Network Doctor."
            ))
            .font(.footnote)
            .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private var actions: some View {
        if store.phase == .idle {
            Button {
                Task { await store.run() }
            } label: {
                Label(t("一键网络医生", "Network Doctor"), systemImage: "play.fill")
            }
        }
        if let exportURL {
            ShareLink(item: exportURL) {
                Label(t("导出脱敏报告", "Export redacted report"), systemImage: "square.and.arrow.up")
            }
            .accessibilityHint(t("仅导出当前显示的脱敏 JSON 报告", "Exports only the redacted JSON report shown here"))
        }
        if store.canRepair {
            Button {
                store.requestConfirmation()
            } label: {
                Label(
                    store.diagnosis?.executableRepairs.first?.title
                        ?? t("可执行", "Ready"),
                    systemImage: "wrench.and.screwdriver"
                )
            }
        }
        if store.phase == .failed || store.phase == .finished || store.phase == .review {
            Button {
                Task { await store.run() }
            } label: {
                Label(t("重新诊断", "Run again"), systemImage: "arrow.clockwise")
            }
        }
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
            try data.write(to: url, options: [.atomic, .completeFileProtection])
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
        case .executing: t("正在安全修复", "Applying safe repairs")
        case .finished: t("修复流程完成", "Repair process complete")
        case .failed: t("无法完成诊断", "Could not complete diagnosis")
        }
    }

    private var phaseDetail: String {
        switch store.phase {
        case .running: t("正在检查 Coordinator、Relay、EXIT、WireGuard、MTU、DNS、IP、路由和视频连接。", "Checking Coordinator, Relay, EXIT, WireGuard, MTU, DNS, IP, routes, and video connectivity.")
        case .executing: t("请保持 RatelMesh 打开；每项更改都会验证并在需要时回滚。", "Keep RatelMesh open. Each change is verified and rolled back when needed.")
        case .finished: t("请查看每项修复的最终状态。", "Review the final status of every repair.")
        default: t("报告中的设备和网络标识已脱敏。", "Device and network identifiers in the report are redacted.")
        }
    }

    private var phaseAccessibilityLabel: String { "\(phaseTitle). \(phaseDetail)" }
    private var phaseIcon: String { store.phase == .failed ? "exclamationmark.triangle.fill" : "checkmark.circle.fill" }
    private var phaseColor: Color { store.phase == .failed ? .red : .green }

    private var errorMessage: String {
        switch store.error {
        case .responseTooLarge: t("诊断响应超出安全大小限制。", "The diagnostic response exceeded the safe size limit.")
        case .unsupportedSchema: t("后台服务返回了不受支持的诊断格式。", "The background service returned an unsupported diagnostic format.")
        case .invalidResponse: t("后台服务返回了无效的诊断响应。", "The background service returned an invalid diagnostic response.")
        case .noApplicableRepairs: t("当前没有可安全执行的修复。", "There are no repairs that can be run safely.")
        default: t("此版本的后台服务暂不支持 Network Doctor。", "This background-service version does not support Network Doctor yet.")
        }
    }

    private func resultTitle(_ status: String) -> String {
        switch status {
        case "applied": t("已修复并验证", "Applied and verified")
        case "rolled_back": t("修复失败，已回滚", "Repair failed; rolled back")
        case "postcondition_failed": t("验证失败，已回滚", "Verification failed; rolled back")
        case "snapshot_failed": t("无法备份状态，未更改", "Could not save state; unchanged")
        case "skipped": t("已安全跳过", "Safely skipped")
        case "rollback_failed": t("回滚失败，需要人工处理", "Rollback failed; manual action required")
        default: t("状态不确定，需要人工处理", "State uncertain; manual action required")
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

    private func t(_ chinese: String, _ english: String) -> String {
        language.localized(english, chineseFallback: chinese)
    }

    private func f(_ chinese: String, _ english: String, _ arguments: CVarArg...) -> String {
        String(format: t(chinese, english), arguments: arguments)
    }
}
