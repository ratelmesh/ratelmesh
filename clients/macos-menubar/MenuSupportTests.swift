import AppKit
import Foundation

@main
private enum MenuSupportTests {
    static func main() throws {
        let noPeers = Data(#"{"state":"Running","self":{"name":"test-device","meshIP":"100.64.0.1"},"peers":null,"activeExit":"","killSwitch":false,"internetFallback":false}"#.utf8)
        let status = try JSONDecoder().decode(MeshStatus.self, from: noPeers)
        precondition(status.state == "Running")
        precondition(status.peers.isEmpty)
        precondition(status.selfNode.name == "test-device")
        precondition(status.exitClients.isEmpty)
        precondition(status.exitTrafficVerified == false)
        precondition(status.enrollmentRequired == false)
        precondition(!shouldShowEnrollment(status: status, locallyEnrolled: false))

        let freshInstall = Data(#"{"state":"Starting","enrollmentRequired":true,"self":{"name":"","meshIP":""},"peers":[],"activeExit":"","killSwitch":false}"#.utf8)
        let freshStatus = try JSONDecoder().decode(MeshStatus.self, from: freshInstall)
        precondition(freshStatus.enrollmentRequired)
        precondition(shouldShowEnrollment(status: freshStatus, locallyEnrolled: false))
        precondition(shouldShowEnrollment(status: freshStatus, locallyEnrolled: true))
        precondition(shouldShowEnrollment(status: nil, locallyEnrolled: false))
        precondition(!shouldShowEnrollment(status: nil, locallyEnrolled: true))
        precondition(localConnectionPhase(status: freshStatus, reachable: true, locallyEnrolled: false) == .enrollment)
        precondition(localConnectionPhase(status: status, reachable: true, locallyEnrolled: true) == .connected)
        precondition(localConnectionPhase(status: nil, reachable: true, locallyEnrolled: true) == .connecting)
        precondition(localConnectionPhase(status: status, reachable: false, locallyEnrolled: true) == .disconnected)

        let doctorJSON = Data("""
        {
          "schema":"\(networkDoctorAPISchema)",
          "planID":"opaque-plan-7",
          "availableRepairs":["lower-mtu"],
          "report":{
            "schema":"\(networkDoctorReportSchema)",
            "generated_at":"2026-07-26T12:00:00Z",
            "summary":{"ok":false,"worst_severity":"warning","total_findings":1,"counts_by_severity":{"warning":1}},
            "findings":[{"code":"mtu.blackhole","severity":"warning","probe":"path-mtu","summary":"[redacted:host:abc123] is unreachable"}],
            "probes":[{"probe":"path-mtu","status":"completed","duration_ms":12,"findings":1}]
          },
          "plan":{
            "schema":"\(networkDoctorPlanSchema)",
            "dry_run":true,
            "repairs":[{"action":"lower-mtu","title":"Lower tunnel MTU","addresses":["mtu.blackhole"],"applicable":true,"apply":[{"op":"mtu.set"}]}]
          }
        }
        """.utf8)
        let doctor = try JSONDecoder().decode(NetworkDoctorDiagnosis.self, from: doctorJSON)
        precondition(doctor.planID == "opaque-plan-7")
        precondition(doctor.executableRepairs.map(\.action) == ["lower-mtu"])
        let doctorExport = try doctor.report.redactedJSON()
        let doctorExportText = try unwrap(String(data: doctorExport, encoding: .utf8))
        precondition(doctorExportText.contains("[redacted:host:abc123]"))
        precondition(!doctorExportText.contains("opaque-plan-7"))
        precondition(!doctorExportText.contains("lower-mtu"))
        let executionJSON = Data("""
        {"schema":"\(networkDoctorExecutionSchema)","repairs":[
          {"action":"lower-mtu","status":"rolled_back"},
          {"action":"flush-dns","status":"rollback_failed"}
        ]}
        """.utf8)
        let execution = try JSONDecoder().decode(NetworkDoctorExecutionReport.self, from: executionJSON)
        precondition(!execution.repairs[0].needsManualAttention)
        precondition(execution.repairs[1].needsManualAttention)

        let servingExit = Data(#"{"state":"Running","self":{"name":"exit-device","meshIP":"100.64.0.1","role":"exit"},"peers":[],"activeExit":"","selectedExit":"","killSwitch":false,"exitClients":[{"name":"client-device","meshIP":"100.64.0.2","state":"active","online":true,"lastSeen":"2026-07-19T12:00:00Z"}]}"#.utf8)
        let exitStatus = try JSONDecoder().decode(MeshStatus.self, from: servingExit)
        precondition(exitStatus.selfNode.role == "exit")
        precondition(exitStatus.exitClients.count == 1)
        precondition(exitStatus.exitClients[0].state == "active")

        let remote = Data(#"{"state":"Running","self":{"name":"phone","meshIP":"100.64.0.2"},"peers":[{"name":"office","meshIP":"100.64.0.8","role":"plain","online":true,"pathType":"direct","platform":"windows","remoteAccessAllowed":true,"remoteServices":[{"kind":"rdp","port":3389,"targetMeshIp":"100.64.0.8"}]}],"activeExit":"","killSwitch":false}"#.utf8)
        let remoteStatus = try JSONDecoder().decode(MeshStatus.self, from: remote)
        precondition(remoteStatus.peers[0].platform == "windows")
        precondition(remoteStatus.peers[0].remoteAccessAllowed == true)
        precondition(remoteStatus.peers[0].remoteServices == [RemoteService(kind: "rdp", port: 3389, targetMeshIp: "100.64.0.8")])
        let retargeted = Data(#"{"state":"Running","self":{"name":"phone","meshIP":"100.64.0.2"},"peers":[{"name":"office","meshIP":"100.64.0.8","role":"plain","online":true,"pathType":"direct","platform":"windows","remoteAccessAllowed":true,"remoteServices":[{"kind":"rdp","port":3389,"targetMeshIp":"100.64.0.99"}]}],"activeExit":"","killSwitch":false}"#.utf8)
        let retargetedStatus = try JSONDecoder().decode(MeshStatus.self, from: retargeted)
        precondition(retargetedStatus.peers[0].authorizedRemoteServices.isEmpty)
        precondition(
            RemoteAccessURL.make(
                RemoteService(kind: "ssh", port: 22, targetMeshIp: "100.64.0.8")
            )?.absoluteString == "ssh://100.64.0.8:22"
        )
        precondition(
            RemoteAccessURL.make(
                RemoteService(kind: "vnc", port: 5900, targetMeshIp: "fd00::8")
            )?.absoluteString == "vnc://[fd00::8]:5900"
        )
        for address in [
            "office.example", "100.64.0.8@evil.example", "100.64.0.8/path",
            "100.64.0.8?x=1", "[fd00::8]", "fd00::8%en0",
        ] {
            precondition(RemoteAccessURL.make(
                RemoteService(kind: "ssh", port: 22, targetMeshIp: address)
            ) == nil)
        }

        precondition(EnrollmentCode.valid("ratelmesh-ab12-cd34-ef56"))
        precondition(EnrollmentCode.valid("  RATELMESH-AB12-CD34-EF56\n"))
        precondition(!EnrollmentCode.valid("ratelmesh-ab12-cd34"))
        precondition(!EnrollmentCode.valid("ratelmesh-ab!2-cd34-ef56"))

        let sourceDirectory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        let appSource = try String(
            contentsOf: sourceDirectory.appendingPathComponent("RatelMeshMenuApp.swift"),
            encoding: .utf8
        )
        precondition(!appSource.localizedCaseInsensitiveContains("shi" + "eld"))
        precondition(appSource.contains("colorScheme == .dark ? cyan : accessibleCyan"))
        precondition(!appSource.contains(#"url(forResource: "RatelMesh", withExtension: "icns")"#))
        precondition(appSource.contains("RatelMeshBrandAssets.image(size: 18, template: true)"))
        precondition(appSource.contains(".accessibilityHidden(decorative)"))
        precondition(appSource.contains("NSStatusBar.system.statusItem"))
        precondition(appSource.contains("private let popover = NSPopover()"))
        precondition(appSource.contains("popover.behavior = .transient"))
        precondition(appSource.contains("popover.show("))
        precondition(appSource.contains("applicationShouldHandleReopen"))
        precondition(!appSource.contains("MenuBarExtra"))
        precondition(!appSource.contains(".menuBarExtraStyle"))
        precondition(appSource.contains(".accessibilityAddTraits(selected ? .isSelected : [])"))
        precondition(appSource.contains(".accessibilityLabel(Text(remoteAccessAccessibilityLabel"))
        precondition(
            appSource.components(separatedBy: "RatelMeshBrandMark(size: 20, template: true)").count == 3
        )
        precondition(!appSource.contains(".resizable()"))
        precondition(!appSource.contains(".scaledToFit()"))
        precondition(appSource.contains("copy.size = NSSize(width: size, height: size)"))
        precondition(appSource.contains(#"forResource: "BrandMarkDark", withExtension: "png""#))
        precondition(appSource.contains(#"forInfoDictionaryKey: "RatelMeshMenuTemplatePNG""#))
        precondition(appSource.contains("ScrollView {\n                operationalContent"))
        precondition(appSource.contains("ViewThatFits(in: .horizontal)"))
        precondition(appSource.contains("private final class PanelLayoutStore: ObservableObject"))
        precondition(appSource.contains("controller.sizingOptions = [.preferredContentSize]"))
        precondition(!appSource.contains("popover.contentSize = NSSize"))
        precondition(appSource.contains("visibleHeight - 48"))
        precondition(appSource.contains("Button(role: .destructive)"))
        precondition(appSource.contains("uninstallButton.hasDestructiveAction = true"))
        let cancelButtonIndex = try unwrap(
            appSource.range(of: #"alert.addButton(withTitle: Copy.text("Cancel", "取消"))"#)
        ).lowerBound
        let uninstallButtonIndex = try unwrap(
            appSource.range(of: #"let uninstallButton = alert.addButton(withTitle: Copy.text("Uninstall", "卸载"))"#)
        ).lowerBound
        precondition(cancelButtonIndex < uninstallButtonIndex)
        precondition(appSource.contains(".privacySensitive()"))
        precondition(appSource.contains("\"planID\": planID"))
        precondition(appSource.contains("\"confirm\": true"))
        precondition(appSource.contains("if store.phase == .idle"))
        precondition(appSource.contains("Task { await store.run() }"))
        precondition(!appSource.contains("if store.phase == .idle { Task { await store.run() } }"))
        precondition(appSource.contains("guard phase == .confirming"))
        precondition(!appSource.contains("error.localizedDescription"))
        precondition(appSource.contains("Export redacted report"))
        precondition(!appSource.contains("localizedDescription"))
        precondition(!appSource.contains("NSAppleScript.errorMessage"))
        precondition(!appSource.contains("locationReporter?.start()\n        Task { await refresh() }"))

        let enrollmentSource = try String(
            contentsOf: sourceDirectory.appendingPathComponent("EnrollmentSupport.swift"),
            encoding: .utf8
        )
        precondition(!enrollmentSource.contains("LocalizedError"))
        precondition(!enrollmentSource.contains("failed(String)"))
        precondition(enrollmentSource.contains("TrustedPrivilegedHelper.validate"))
        precondition(enrollmentSource.contains("maximumOutputBytes"))
        precondition(enrollmentSource.contains("writeAll"))
        precondition(!enrollmentSource.contains("private static func execute(code: String) throws -> String"))
        precondition(appSource.contains("try TrustedPrivilegedHelper.validate"))
        precondition(appSource.contains("ratelmesh-uninstall"))
        let updateSource = try String(
            contentsOf: sourceDirectory.appendingPathComponent("UpdateSupport.swift"),
            encoding: .utf8
        )
        precondition(!updateSource.contains("String(describing: error)"))
        precondition(!updateSource.contains("error.localizedDescription"))
        try TrustedPrivilegedHelper.validate("/bin/echo")
        let untrustedHelper = FileManager.default.temporaryDirectory
            .appendingPathComponent("ratelmesh-untrusted-helper-\(UUID().uuidString)")
        precondition(FileManager.default.createFile(
            atPath: untrustedHelper.path,
            contents: Data("#!/bin/sh\n".utf8),
            attributes: [.posixPermissions: 0o755]
        ))
        defer { try? FileManager.default.removeItem(at: untrustedHelper) }
        do {
            try TrustedPrivilegedHelper.validate(untrustedHelper.path)
            preconditionFailure("a user-owned privileged helper was trusted")
        } catch {
            // Expected: privileged helpers and every parent must be root-owned
            // and non-writable by group/other users.
        }

        let infoData = try Data(contentsOf: sourceDirectory.appendingPathComponent("Info.plist"))
        let info = try PropertyListSerialization.propertyList(from: infoData, format: nil) as? [String: Any]
        let menuImage = info?["RatelMeshMenuTemplatePNG"] as? Data
        precondition(menuImage?.isEmpty == false)
        let menuTemplate = try unwrap(NSImage(data: try unwrap(menuImage)))
        for size in [16, 24, 32] {
            let pixels = try renderedPixels(menuTemplate, size: size)
            let alpha = stride(from: 3, to: pixels.count, by: 4).map { pixels[$0] }
            let visible = alpha.filter { $0 > 0 }.count
            precondition(visible > size * size / 10, "menu mark disappears at \(size)px")
            precondition(visible < size * size * 9 / 10, "menu mark loses its transparent shape at \(size)px")
            var border: [UInt8] = []
            for index in 0..<size {
                border.append(alpha[index])
                border.append(alpha[(size - 1) * size + index])
                border.append(alpha[index * size])
                border.append(alpha[index * size + size - 1])
            }
            precondition(border.allSatisfy { $0 == 0 }, "menu mark clips at \(size)px")
        }
        precondition(info?["CFBundleShortVersionString"] as? String == "0.2.41")
        precondition(info?["CFBundleVersion"] as? String == "241")

        let repositoryRoot = sourceDirectory
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let brandPNG = repositoryRoot.appendingPathComponent("assets/brand/ratelmesh-brand-v3/png")
        let icnsImage = try unwrap(NSImage(
            contentsOf: sourceDirectory.appendingPathComponent("RatelMesh.icns")
        ))
        for (filename, size) in [("favicon-16.png", 16), ("favicon-32.png", 32)] {
            let micro = try unwrap(NSImage(
                contentsOf: brandPNG.appendingPathComponent(filename)
            ))
            let icnsPixels = try renderedPixels(icnsImage, size: size)
            let microPixels = try renderedPixels(micro, size: size)
            precondition(
                icnsPixels == microPixels,
                "ICNS \(size)px representation differs from canonical \(filename)"
            )
        }

        let localizationRoot = sourceDirectory.appendingPathComponent("Localizations")
        let menuReferenceData = try Data(
            contentsOf: localizationRoot
                .appendingPathComponent("zh-Hans.lproj/Localizable.strings")
        )
        let menuReference = try unwrap(
            PropertyListSerialization.propertyList(
                from: menuReferenceData,
                format: nil
            ) as? [String: String]
        )
        let doctorReferenceData = try Data(
            contentsOf: localizationRoot
                .appendingPathComponent("zh-Hans.lproj/NetworkDoctor.strings")
        )
        let doctorReference = try unwrap(
            PropertyListSerialization.propertyList(
                from: doctorReferenceData,
                format: nil
            ) as? [String: String]
        )
        let localizationDirectories = try FileManager.default.contentsOfDirectory(
            at: localizationRoot,
            includingPropertiesForKeys: nil
        ).filter { $0.pathExtension == "lproj" }
        precondition(localizationDirectories.count == 12)
        for directory in localizationDirectories {
            let menuData = try Data(
                contentsOf: directory.appendingPathComponent("Localizable.strings")
            )
            let menuStrings = try unwrap(
                PropertyListSerialization.propertyList(
                    from: menuData,
                    format: nil
                ) as? [String: String]
            )
            precondition(menuStrings.count == menuReference.count)
            precondition(Set(menuStrings.keys) == Set(menuReference.keys))
            for (key, value) in menuStrings {
                precondition(!value.isEmpty)
                for placeholder in ["%@", "%d"] {
                    precondition(
                        value.components(separatedBy: placeholder).count ==
                            key.components(separatedBy: placeholder).count
                    )
                }
            }
            let prompt = try String(
                contentsOf: directory.appendingPathComponent("InfoPlist.strings"),
                encoding: .utf8
            )
            precondition(prompt.contains(#""NSLocationUsageDescription" ="#))
            let doctorCopy = try String(
                contentsOf: directory.appendingPathComponent("NetworkDoctor.strings"),
                encoding: .utf8
            )
            precondition(doctorCopy.contains(#""Network Doctor" ="#))
            precondition(doctorCopy.contains(#""Rollback failed; manual action required" ="#))
            let doctorData = try Data(
                contentsOf: directory.appendingPathComponent("NetworkDoctor.strings")
            )
            let doctorStrings = try unwrap(
                PropertyListSerialization.propertyList(
                    from: doctorData,
                    format: nil
                ) as? [String: String]
            )
            precondition(doctorStrings.count == doctorReference.count)
            precondition(Set(doctorStrings.keys) == Set(doctorReference.keys))
            for (key, value) in doctorStrings {
                precondition(!value.isEmpty)
                precondition(
                    value.components(separatedBy: "%d").count ==
                        key.components(separatedBy: "%d").count
                )
            }
            let locale = directory.deletingPathExtension().lastPathComponent
            let unchangedEnglish = Set(
                doctorStrings.compactMap { $0.key == $0.value ? $0.key : nil }
            )
            precondition(
                unchangedEnglish == (locale == "sv" ? Set(["Support"]) : Set<String>())
            )
            let iosDoctorData = try Data(
                contentsOf: repositoryRoot
                    .appendingPathComponent("clients/ios/RatelMesh")
                    .appendingPathComponent(directory.lastPathComponent)
                    .appendingPathComponent("NetworkDoctor.strings")
            )
            precondition(doctorData == iosDoctorData)
        }

        print("macOS menu support tests passed")
    }

    private static func renderedPixels(_ image: NSImage, size: Int) throws -> Data {
        let representation = try unwrap(NSBitmapImageRep(
            bitmapDataPlanes: nil,
            pixelsWide: size,
            pixelsHigh: size,
            bitsPerSample: 8,
            samplesPerPixel: 4,
            hasAlpha: true,
            isPlanar: false,
            colorSpaceName: .deviceRGB,
            bytesPerRow: size * 4,
            bitsPerPixel: 32
        ))
        let context = try unwrap(NSGraphicsContext(bitmapImageRep: representation))
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = context
        image.draw(
            in: NSRect(x: 0, y: 0, width: size, height: size),
            from: .zero,
            operation: .copy,
            fraction: 1,
            respectFlipped: false,
            hints: [.interpolation: NSImageInterpolation.none]
        )
        context.flushGraphics()
        NSGraphicsContext.restoreGraphicsState()
        return Data(
            bytes: try unwrap(representation.bitmapData),
            count: representation.bytesPerRow * representation.pixelsHigh
        )
    }

    private static func unwrap<T>(_ value: T?) throws -> T {
        guard let value else { throw CocoaError(.fileReadCorruptFile) }
        return value
    }
}
