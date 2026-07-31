import XCTest
#if SWIFT_PACKAGE
@testable import RatelMeshShared
#else
#if canImport(UIKit)
import UIKit
#elseif canImport(AppKit)
import AppKit
#endif
@testable import RatelMesh
#endif

final class MobileConfigurationTests: XCTestCase {
    func testOfficialCoordinatorIsTheConfigurationDefault() throws {
        let configuration = ClientConfiguration(authKey: "test", hostname: "iphone")
        XCTAssertEqual(configuration.coordinatorURL, "https://control.ratelmesh.com")
        XCTAssertEqual(try configuration.validated().coordinatorURL, "https://control.ratelmesh.com")
    }

    func testSystemLanguageResolutionUsesEnglishForEnglishAndUnknownLocales() {
        XCTAssertEqual(ProductLanguage.systemLanguage(for: "en-US"), .english)
        XCTAssertEqual(ProductLanguage.systemLanguage(for: "es-MX"), .spanish)
        XCTAssertEqual(ProductLanguage.systemLanguage(for: "zh-Hans-CN"), .chinese)
        XCTAssertEqual(ProductLanguage.systemLanguage(for: "zh-TW"), .traditionalChinese)
        XCTAssertEqual(ProductLanguage.systemLanguage(for: "ar-SA"), .english)
    }

    func testPrivacyManifestDeclaresLocallyCoarsenedLocationCollection() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let data = try Data(
            contentsOf: iosRoot.appendingPathComponent("Shared/PrivacyInfo.xcprivacy")
        )
        let manifest = try XCTUnwrap(
            PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
        )
        let collected = try XCTUnwrap(
            manifest["NSPrivacyCollectedDataTypes"] as? [[String: Any]]
        )
        let coarseLocation = collected.first {
            $0["NSPrivacyCollectedDataType"] as? String ==
                "NSPrivacyCollectedDataTypeCoarseLocation"
        }
        XCTAssertNotNil(coarseLocation)
        XCTAssertEqual(coarseLocation?["NSPrivacyCollectedDataTypeLinked"] as? Bool, true)
        XCTAssertEqual(coarseLocation?["NSPrivacyCollectedDataTypeTracking"] as? Bool, false)
        XCTAssertEqual(
            coarseLocation?["NSPrivacyCollectedDataTypePurposes"] as? [String],
            ["NSPrivacyCollectedDataTypePurposeAppFunctionality"]
        )
    }

    func testFirstUsePrivacyDisclosureMatchesVPNReviewRequirements() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: iosRoot.appendingPathComponent("RatelMesh/ContentView.swift"),
            encoding: .utf8
        )
        let requiredCopy = [
            "Data RatelMesh uses",
            "device name and a device identifier",
            "only a coarse region",
            "No sale or third-party disclosure",
            "does not sell this data",
            "does not collect browsing content or plaintext tunnel traffic",
            "https://ratelmesh.com/privacy",
            ".interactiveDismissDisabled(!privacyAcknowledged)",
            "|| !privacyAcknowledged",
            "if privacyAcknowledged",
            "mainContent",
            "} else {\n                privacyGuide",
        ]
        for text in requiredCopy {
            XCTAssertTrue(source.contains(text), "missing first-use privacy disclosure: \(text)")
        }

        let locales = [
            "de", "es", "fr", "it", "ja", "ko", "nl", "pl",
            "pt-BR", "sv", "zh-Hans", "zh-Hant",
        ]
        for locale in locales {
            let strings = try String(
                contentsOf: iosRoot.appendingPathComponent(
                    "RatelMesh/\(locale).lproj/Localizable.strings"
                ),
                encoding: .utf8
            )
            for key in [
                "Data RatelMesh uses",
                "No sale or third-party disclosure",
                "Read the privacy policy",
            ] {
                XCTAssertTrue(strings.contains("\"\(key)\" = "), "\(locale) is missing \(key)")
            }
        }
    }

    func testAppReviewVPNResponseMatchesImplementedDataFlow() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let metadata = try String(
            contentsOf: iosRoot.appendingPathComponent("AppStore/metadata.en-US.md"),
            encoding: .utf8
        )
        let response = try String(
            contentsOf: iosRoot.appendingPathComponent(
                "AppStore/review-response-vpn.en-US.md"
            ),
            encoding: .utf8
        )
        let normalizedMetadata = metadata
            .components(separatedBy: .whitespacesAndNewlines)
            .filter { !$0.isEmpty }
            .joined(separator: " ")
        let normalizedResponse = response
            .components(separatedBy: .whitespacesAndNewlines)
            .filter { !$0.isEmpty }
            .joined(separator: " ")
        let requiredCopy = [
            "RatelMesh contains VPN functionality",
            "does not collect or store browsing history",
            "plaintext packet payloads",
            "WireGuard private key and session credential remain in the device Keychain",
            "exact coordinates remain on the device",
            "not used for advertising, cross-app tracking, marketing profiles, or sale",
            "does not sell this information or share it with third parties for their own purposes",
            "Tokyo, Japan",
            "relay transports encrypted WireGuard packets",
            "selected exit necessarily sees destination IP addresses, timing, and traffic volume",
            "does not persist tunnel contents or DNS browsing history",
            "Network Doctor is optional",
            "does not persist that observed public IP",
        ]
        for text in requiredCopy {
            XCTAssertTrue(
                normalizedMetadata.contains(text),
                "App Review notes are missing: \(text)"
            )
            XCTAssertTrue(
                normalizedResponse.contains(text),
                "App Review reply is missing: \(text)"
            )
        }
        XCTAssertFalse(response.contains("ENROLLMENT_CODE"))
        XCTAssertFalse(response.contains("PASSWORD"))
    }

    func testDeviceIdentityStateIsExcludedFromBackup() throws {
        let container = FileManager.default.temporaryDirectory
            .appendingPathComponent("ratelmesh-state-backup-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: container) }

        let state = try DeviceStateDirectory.prepare(in: container)
        XCTAssertEqual(state.lastPathComponent, "State")
        XCTAssertEqual(
            try state.resourceValues(forKeys: [.isExcludedFromBackupKey]).isExcludedFromBackup,
            true
        )

        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let provider = try String(
            contentsOf: iosRoot.appendingPathComponent("PacketTunnel/PacketTunnelProvider.swift"),
            encoding: .utf8
        )
        let app = try String(
            contentsOf: iosRoot.appendingPathComponent("RatelMesh/AppViewModel.swift"),
            encoding: .utf8
        )
        XCTAssertTrue(provider.contains("try DeviceStateDirectory.prepare(in: container)"))
        XCTAssertTrue(app.contains("try DeviceStateDirectory.excludeExistingFromBackup(in: container)"))
    }

    func testBrandPresentationUsesAcceptedAssetsWithoutLegacySecurityGlyphs() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: iosRoot.appendingPathComponent("RatelMesh/ContentView.swift"),
            encoding: .utf8
        )
        XCTAssertFalse(source.localizedCaseInsensitiveContains("shi" + "eld"))
        XCTAssertTrue(source.contains("colorScheme == .dark ? cyan : accessibleCyan"))
        XCTAssertTrue(source.contains(#"Image("BrandMarkDark")"#))
        XCTAssertTrue(source.contains(".accessibilityAddTraits(selected ? .isSelected : [])"))
        XCTAssertTrue(source.contains(".accessibilityLabel(Text(remoteAccessAccessibilityLabel"))
        XCTAssertTrue(FileManager.default.fileExists(
            atPath: iosRoot.appendingPathComponent(
                "RatelMesh/Assets.xcassets/BrandMarkDark.imageset/BrandMarkDark-1024.png"
            ).path
        ))
        #if !SWIFT_PACKAGE
        #if canImport(UIKit)
        XCTAssertNotNil(UIImage(named: "BrandMarkDark"))
        #elseif canImport(AppKit)
        XCTAssertNotNil(NSImage(named: "BrandMarkDark"))
        #endif
        #endif
    }

    func testNativeMacStoreTargetIsSandboxedAndDisclosesVPNDataUse() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let macRoot = iosRoot
            .deletingLastPathComponent()
            .appendingPathComponent("macos-appstore")
        let project = try String(
            contentsOf: iosRoot.appendingPathComponent("project.yml"),
            encoding: .utf8
        )
        let view = try String(
            contentsOf: macRoot.appendingPathComponent("App/MacContentView.swift"),
            encoding: .utf8
        )
        let app = try String(
            contentsOf: macRoot.appendingPathComponent("App/RatelMeshMacApp.swift"),
            encoding: .utf8
        )
        let appEntitlementsData = try Data(
            contentsOf: macRoot.appendingPathComponent("RatelMeshMac.entitlements")
        )
        let tunnelEntitlementsData = try Data(
            contentsOf: macRoot.appendingPathComponent("PacketTunnelMac.entitlements")
        )
        for data in [appEntitlementsData, tunnelEntitlementsData] {
            let entitlements = try XCTUnwrap(
                PropertyListSerialization.propertyList(from: data, format: nil)
                    as? [String: Any]
            )
            XCTAssertEqual(entitlements["com.apple.security.app-sandbox"] as? Bool, true)
            XCTAssertTrue(
                (entitlements["com.apple.developer.networking.networkextension"]
                    as? [String])?.contains("packet-tunnel-provider") == true
            )
            XCTAssertEqual(entitlements["com.apple.security.network.client"] as? Bool, true)
        }
        XCTAssertTrue(project.contains("RatelMeshMac:"))
        XCTAssertTrue(project.contains("PacketTunnelMac:"))
        XCTAssertTrue(project.contains("platform: macOS"))
        XCTAssertTrue(project.contains("- path: PacketTunnel"))
        XCTAssertTrue(project.contains("- Info.plist"))
        XCTAssertTrue(view.contains("Data RatelMesh uses"))
        XCTAssertTrue(view.contains("No sale or third-party disclosure"))
        XCTAssertTrue(view.contains("does not collect browsing content or plaintext tunnel traffic"))
        XCTAssertTrue(view.contains("https://ratelmesh.com/privacy"))
        XCTAssertTrue(view.contains("NSImage(contentsOf: url)"))
        XCTAssertFalse(view.contains("Image(\"BrandMarkDark\")"))
        XCTAssertTrue(app.contains("XCTestConfigurationFilePath"))
        XCTAssertTrue(app.contains("#if DEBUG"))
        XCTAssertTrue(app.contains("RATELMESH_APP_STORE_SCREENSHOT_PATH"))
        XCTAssertTrue(app.contains("MacAppStoreScreenshotCapture"))
        XCTAssertTrue(view.contains("RATELMESH_APP_STORE_SCREEN"))
        XCTAssertTrue(view.contains(".interactiveDismissDisabled(!privacyAcknowledged)"))
        XCTAssertTrue(view.contains("!privacyAcknowledged"))
        XCTAssertFalse(view.contains("ratelmeshd"))
        XCTAssertFalse(view.contains("pfctl"))
        XCTAssertFalse(view.contains("Sparkle"))
    }

    func testNativeMacLocalizationTableCoversVisibleCopy() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let requiredKeys = [
            "Apply safe repair",
            "Applying safe repair",
            "Connect to reach your devices and private services.",
            "Connected through your private mesh",
            "Coordinator",
            "Diagnosis could not complete. No repair was run.",
            "Each change is verified and rolled back when needed.",
            "Internet traffic uses your selected exit device",
            "Leak protection on",
            "No other devices",
            "No remote access service is authorized",
            "Overview",
            "Privacy before connecting",
            "Review privacy disclosure",
            "Save the new enrollment code, then connect again.",
            "State",
            "System boundary",
            "The Mac App Store edition uses Apple Network Extension. macOS gives selected traffic to RatelMesh only after you start the VPN.",
            "Your enrollment expired or was revoked. Enter a new one-use enrollment code.",
            "Your mesh devices appear after connecting.",
            "Your network remains yours.",
            "checks",
        ]
        let locales = [
            "de", "es", "fr", "it", "ja", "ko", "nl", "pl",
            "pt-BR", "sv", "zh-Hans", "zh-Hant",
        ]
        for locale in locales {
            let table = try String(
                contentsOf: iosRoot.appendingPathComponent(
                    "RatelMesh/\(locale).lproj/MacApp.strings"
                ),
                encoding: .utf8
            )
            for key in requiredKeys {
                XCTAssertTrue(
                    table.contains("\"\(key)\" = "),
                    "\(locale) is missing native Mac copy: \(key)"
                )
            }
        }
    }

    func testDecodesVerifiedExitAndItsClients() throws {
        let json = #"{"state":"Running","peers":[],"activeExit":"home-exit","selectedExit":"home-exit","exitTrafficVerified":true,"exitClients":[{"name":"phone","meshIP":"100.64.0.3","state":"active","online":true}]}"#
        let status = try JSONDecoder().decode(MobileStatus.self, from: Data(json.utf8))
        XCTAssertTrue(status.exitTrafficVerified == true)
        XCTAssertEqual(status.exitClients?.first?.name, "phone")
        XCTAssertEqual(status.exitClients?.first?.state, "active")
    }

    func testPeerOnlyChangesDoNotReplaceIOSNetworkSettings() throws {
        func configuration(endpoint: String, allowedIPs: [String]) -> MobileTunnelConfiguration {
            MobileTunnelConfiguration(
                version: 1,
                active: true,
                privateKey: "test-private-key",
                listenPort: 51820,
                addresses: ["100.64.0.7/32"],
                dnsServers: ["1.1.1.1"],
                peers: [
                    MobilePeerConfiguration(
                        publicKey: "test-public-key",
                        endpoint: endpoint,
                        allowedIPs: allowedIPs,
                        persistentKeepalive: 5
                    )
                ],
                directRoutes: ["203.0.113.1/32"],
                blockRoutes: []
            )
        }

        let first = configuration(endpoint: "192.0.2.1:51820", allowedIPs: ["0.0.0.0/0"])
        let movedEndpoint = configuration(endpoint: "192.0.2.2:51820", allowedIPs: ["0.0.0.0/0"])
        let changedRoutes = configuration(endpoint: "192.0.2.2:51820", allowedIPs: ["100.64.0.0/10"])
        XCTAssertEqual(
            try first.networkSettingsFingerprint(),
            try movedEndpoint.networkSettingsFingerprint()
        )
        XCTAssertNotEqual(
            try first.networkSettingsFingerprint(),
            try changedRoutes.networkSettingsFingerprint()
        )
    }

    func testConfigurationDropsRoutesForMissingInterfaceAddressFamily() throws {
        let config = MobileTunnelConfiguration(
            version: 1,
            active: true,
            privateKey: "test-private-key",
            listenPort: 51820,
            addresses: ["100.64.0.7/32"],
            dnsServers: [],
            peers: [
                MobilePeerConfiguration(
                    publicKey: "test-public-key",
                    endpoint: "192.0.2.1:51820",
                    allowedIPs: ["0.0.0.0/0", "::/0"],
                    persistentKeepalive: 5
                )
            ],
            directRoutes: [],
            blockRoutes: []
        )
        XCTAssertEqual(
            try XCTUnwrap(config.effectivePeers().first).allowedIPs,
            ["0.0.0.0/0"]
        )
        XCTAssertEqual(try config.effectiveDNSServers(), ["1.1.1.1"])
    }

    func testDirectPreservesSystemDNSAndExplicitExitDNSWins() throws {
        func configuration(dnsServers: [String], allowedIPs: [String]) -> MobileTunnelConfiguration {
            MobileTunnelConfiguration(
                version: 1,
                active: true,
                privateKey: "test-private-key",
                listenPort: 51820,
                addresses: ["100.64.0.7/32"],
                dnsServers: dnsServers,
                peers: [
                    MobilePeerConfiguration(
                        publicKey: "test-public-key",
                        endpoint: "192.0.2.1:51820",
                        allowedIPs: allowedIPs,
                        persistentKeepalive: 5
                    )
                ],
                directRoutes: [],
                blockRoutes: []
            )
        }

        XCTAssertEqual(
            try configuration(dnsServers: [], allowedIPs: ["100.64.0.0/10"])
                .effectiveDNSServers(),
            []
        )
        XCTAssertEqual(
            try configuration(dnsServers: ["9.9.9.9"], allowedIPs: ["0.0.0.0/0"])
                .effectiveDNSServers(),
            ["9.9.9.9"]
        )
    }

    func testExitSelectionPreservesPhysicalEndpointBypassRoutes() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let controller = try String(
            contentsOf: iosRoot.appendingPathComponent("RatelMesh/TunnelController.swift"),
            encoding: .utf8
        )
        let model = try String(
            contentsOf: iosRoot.appendingPathComponent("RatelMesh/AppViewModel.swift"),
            encoding: .utf8
        )
        XCTAssertFalse(controller.contains("includeAllNetworks"))
        XCTAssertFalse(model.contains("includeAllNetworks"))
        XCTAssertTrue(controller.contains("sendProviderMessage"))
        XCTAssertTrue(model.contains("try await tunnel.installIfNeeded()"))
    }

    func testDecodesEnrollmentRequiredAndExposesSafeRecovery() throws {
        let json = #"{"state":"Starting","enrollmentRequired":true,"peers":[],"activeExit":""}"#
        let status = try JSONDecoder().decode(MobileStatus.self, from: Data(json.utf8))
        XCTAssertTrue(status.enrollmentRequired == true)

        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let app = try String(
            contentsOf: iosRoot.appendingPathComponent("RatelMesh/AppViewModel.swift"),
            encoding: .utf8
        )
        let view = try String(
            contentsOf: iosRoot.appendingPathComponent("RatelMesh/ContentView.swift"),
            encoding: .utf8
        )
        XCTAssertTrue(app.contains("var requiresReEnrollment: Bool"))
        XCTAssertTrue(app.contains("func beginReEnrollment()"))
        XCTAssertTrue(app.contains("authKey = \"\""))
        XCTAssertTrue(view.contains("if model.requiresReEnrollment"))
        XCTAssertTrue(view.contains("guard model.isConnected else"))
        XCTAssertTrue(view.contains("localizedCoreState(status.state)"))
        XCTAssertTrue(view.contains(".accessibilityHidden(true)"))
    }

    func testReEnrollmentCannotReusePreviousIdentityOrCredential() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let app = try String(
            contentsOf: iosRoot.appendingPathComponent("RatelMesh/AppViewModel.swift"),
            encoding: .utf8
        )
        XCTAssertTrue(app.contains("try store.delete()"))
        XCTAssertTrue(app.contains("await tunnel.waitUntilStopped()"))
        XCTAssertTrue(app.contains("appendingPathComponent(\"State\", isDirectory: true)"))
        XCTAssertTrue(app.contains("removeObject(forKey: AppConstants.lastStatusKey)"))
        XCTAssertTrue(app.contains("removeObject(forKey: AppConstants.selectedExitKey)"))
        XCTAssertTrue(app.contains("markEnrollmentResetPending()"))
        XCTAssertTrue(app.contains("enrollmentResetPending"))
    }

    func testReinstallBindingPreventsPersistentKeychainCredentialReuse() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let store = try String(
            contentsOf: iosRoot.appendingPathComponent("Shared/SecureConfigurationStore.swift"),
            encoding: .utf8
        )
        let app = try String(
            contentsOf: iosRoot.appendingPathComponent("RatelMesh/AppViewModel.swift"),
            encoding: .utf8
        )
        let constants = try String(
            contentsOf: iosRoot.appendingPathComponent("Shared/AppConstants.swift"),
            encoding: .utf8
        )
        XCTAssertTrue(store.contains("prepareForCurrentInstallation"))
        XCTAssertTrue(store.contains("kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly"))
        XCTAssertTrue(constants.contains("installation-binding-v1"))
        XCTAssertTrue(app.contains("prepareForCurrentInstallation"))
        XCTAssertTrue(app.contains("allowLegacyMigration: tunnel.manager != nil"))
        XCTAssertTrue(app.contains("resetEnrollmentState"))
    }

    func testProviderMessagesFailClosedAfterLifecycleInvalidation() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: iosRoot.appendingPathComponent("PacketTunnel/PacketTunnelProvider.swift"),
            encoding: .utf8
        )
        let message = try XCTUnwrap(source.range(of: "override func handleAppMessage"))
        let polling = try XCTUnwrap(source.range(
            of: "private func startPolling",
            range: message.upperBound..<source.endIndex
        ))
        let body = String(source[message.lowerBound..<polling.lowerBound])
        XCTAssertTrue(body.contains("self.lifecycle.accepts(self.lifecycle.value)"))
        XCTAssertTrue(body.contains("let core = self.core else"))
        XCTAssertFalse(body.contains("try self.core?.useExit"))
        XCTAssertFalse(body.contains("completion?.call(self.core?.statusJSON"))
    }

    func testEnrollmentResetBlocksProviderRestartAndLocationIsConnectionScoped() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let provider = try String(
            contentsOf: iosRoot.appendingPathComponent("PacketTunnel/PacketTunnelProvider.swift"),
            encoding: .utf8
        )
        let app = try String(
            contentsOf: iosRoot.appendingPathComponent("RatelMesh/AppViewModel.swift"),
            encoding: .utf8
        )
        let prepareStart = try XCTUnwrap(app.range(of: "func prepare() async"))
        let connectStart = try XCTUnwrap(app.range(
            of: "func connect() async",
            range: prepareStart.upperBound..<app.endIndex
        ))
        let prepareBody = String(app[prepareStart.lowerBound..<connectStart.lowerBound])
        XCTAssertTrue(provider.contains("AppConstants.enrollmentResetIsPending"))
        XCTAssertTrue(prepareBody.contains("if vpnStatus == .connected"))
        XCTAssertFalse(prepareBody.contains("try await tunnel.prepare()\n            systemLocation.start()"))
        XCTAssertTrue(app.contains("if nextStatus == .connected && self.vpnStatus != .connected"))
    }

    func testRemoteAccessURLsAcceptOnlyNumericMeshAddresses() {
        XCTAssertEqual(
            RemoteAccessURL.make(scheme: "ssh", address: "100.64.0.8", port: 22)?.absoluteString,
            "ssh://100.64.0.8:22"
        )
        XCTAssertEqual(
            RemoteAccessURL.make(scheme: "vnc", address: "fd00::8", port: 5900)?.absoluteString,
            "vnc://[fd00::8]:5900"
        )
        for address in [
            "office.example", "100.64.0.8@evil.example", "100.64.0.8/path",
            "100.64.0.8?x=1", "[fd00::8]", "fd00::8%en0",
        ] {
            XCTAssertNil(RemoteAccessURL.make(scheme: "ssh", address: address, port: 22))
        }
        XCTAssertNil(RemoteAccessURL.make(scheme: "https", address: "100.64.0.8", port: 22))
        XCTAssertNil(RemoteAccessURL.make(scheme: "ssh", address: "100.64.0.8", port: 0))
    }

    func testDecodesTenantRemoteAccessGrant() throws {
        let json = #"{"state":"Running","peers":[{"name":"office","meshIP":"100.64.0.8","role":"plain","online":true,"pathType":"direct","platform":"windows","remoteAccessAllowed":true,"remoteServices":[{"kind":"rdp","port":3389,"targetMeshIp":"100.64.0.8"}]}],"activeExit":""}"#
        let status = try JSONDecoder().decode(MobileStatus.self, from: Data(json.utf8))
        XCTAssertEqual(status.peers.first?.platform, "windows")
        XCTAssertTrue(status.peers.first?.remoteAccessAllowed == true)
        XCTAssertEqual(status.peers.first?.remoteServices, [MobileRemoteService(kind: "rdp", port: 3389, targetMeshIp: "100.64.0.8")])
    }

    func testRemoteAccessServiceCannotRetargetAnotherAddress() throws {
        let json = #"{"state":"Running","peers":[{"name":"office","meshIP":"100.64.0.8","role":"plain","online":true,"pathType":"direct","platform":"windows","remoteAccessAllowed":true,"remoteServices":[{"kind":"rdp","port":3389,"targetMeshIp":"100.64.0.99"}]}],"activeExit":""}"#
        let status = try JSONDecoder().decode(MobileStatus.self, from: Data(json.utf8))

        XCTAssertTrue(status.peers.first?.authorizedRemoteServices.isEmpty == true)
    }

    func testDecodesContractAndBuildsWgQuick() throws {
        let json = #"{"version":7,"active":true,"privateKey":"private=","listenPort":51820,"addresses":["100.64.0.2/32"],"dnsServers":["100.100.100.100"],"peers":[{"publicKey":"public=","presharedKey":"pq-secret=","endpoint":"203.0.113.8:51820","allowedIPs":["100.64.0.3/32"],"persistentKeepalive":25}],"directRoutes":[],"blockRoutes":[]}"#
        let config = try JSONDecoder().decode(MobileTunnelConfiguration.self, from: Data(json.utf8))
        XCTAssertEqual(config.version, 7)
        let rendered = try config.wgQuickConfiguration()
        XCTAssertTrue(rendered.contains("Address = 100.64.0.2/32"))
        XCTAssertTrue(rendered.contains("Endpoint = 203.0.113.8:51820"))
        XCTAssertTrue(rendered.contains("PersistentKeepalive = 25"))
        XCTAssertTrue(rendered.contains("PresharedKey = pq-secret="))
    }

    func testBlockRouteGetsEndpointlessDropPeer() throws {
        let config = MobileTunnelConfiguration(
            version: 1, active: true, privateKey: "private=", listenPort: 0,
            addresses: ["100.64.0.2/32"], dnsServers: [],
            peers: [MobilePeerConfiguration(
                publicKey: "real=", endpoint: "203.0.113.8:51820",
                allowedIPs: ["0.0.0.0/0"], persistentKeepalive: 25
            )],
            directRoutes: [], blockRoutes: ["198.51.100.0/24"]
        )
        let rendered = try config.wgQuickConfiguration()
        XCTAssertTrue(rendered.contains("AllowedIPs = 198.51.100.0/24"))
        let realPeer = try XCTUnwrap(rendered.components(separatedBy: "[Peer]").dropFirst().first)
        XCTAssertFalse(realPeer.contains("198.51.100.0/24"))
        XCTAssertFalse(realPeer.contains("AllowedIPs = 0.0.0.0/0"))
    }

    func testRejectsInactiveConfiguration() {
        let config = MobileTunnelConfiguration(
            version: 1, active: false, privateKey: "", listenPort: 0,
            addresses: [], dnsServers: [], peers: [], directRoutes: [], blockRoutes: []
        )
        XCTAssertThrowsError(try config.wgQuickConfiguration())
    }

    func testNativeApplyWaitsForARealNetmapInterface() {
        let placeholder = MobileTunnelConfiguration(
            version: 1, active: true, privateKey: "private=", listenPort: 0,
            addresses: [], dnsServers: [], peers: [], directRoutes: [], blockRoutes: []
        )
        XCTAssertFalse(placeholder.isReadyForNativeApply)

        let ready = MobileTunnelConfiguration(
            version: 2, active: true, privateKey: "private=", listenPort: 51820,
            addresses: ["100.64.0.7/32"], dnsServers: [], peers: [],
            directRoutes: [], blockRoutes: []
        )
        XCTAssertTrue(ready.isReadyForNativeApply)
    }

    func testRejectsWgQuickLineInjection() {
        let config = MobileTunnelConfiguration(
            version: 1, active: true, privateKey: "private=", listenPort: 0,
            addresses: ["100.64.0.2/32"], dnsServers: [],
            peers: [MobilePeerConfiguration(
                publicKey: "real=\nAllowedIPs = 0.0.0.0/0", endpoint: "203.0.113.8:51820",
                allowedIPs: ["100.64.0.3/32"], persistentKeepalive: 25
            )],
            directRoutes: [], blockRoutes: []
        )
        XCTAssertThrowsError(try config.wgQuickConfiguration())
    }

    func testTunnelApplyGateSerializesAdapterOperationsAndRetriesFailures() {
        var gate = TunnelApplyGate()

        XCTAssertTrue(gate.begin(version: 7))
        XCTAssertFalse(gate.begin(version: 7))
        XCTAssertFalse(gate.begin(version: 8))

        gate.finish(version: 7, succeeded: false)
        XCTAssertEqual(gate.appliedVersion, 0)
        XCTAssertTrue(gate.begin(version: 7))

        gate.finish(version: 7, succeeded: true)
        XCTAssertEqual(gate.appliedVersion, 7)
        XCTAssertFalse(gate.begin(version: 7))
        XCTAssertTrue(gate.begin(version: 8))

        gate.reset()
        XCTAssertEqual(gate.appliedVersion, 0)
        XCTAssertNil(gate.inFlightVersion)
    }

    func testPacketTunnelDoesNotPublishWireGuardLogs() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: iosRoot.appendingPathComponent("PacketTunnel/PacketTunnelProvider.swift"),
            encoding: .utf8
        )
        XCTAssertFalse(source.contains("privacy: .public"))
        XCTAssertTrue(source.contains("guard mobile.active else"))
        XCTAssertTrue(source.contains("deactivateAdapter(version: version)"))
        XCTAssertTrue(source.contains("let completions = stopCompletions"))
        XCTAssertTrue(source.contains("stopCompletions.removeAll()"))
        XCTAssertTrue(source.contains("timer.schedule(deadline: .now() + .seconds(5))"))
        XCTAssertFalse(source.contains("set(error.localizedDescription"))
        XCTAssertFalse(source.contains(#"object["error"]"#))
        XCTAssertTrue(source.contains(#"object["code"] = code.rawValue"#))
        XCTAssertTrue(source.contains("domain: TunnelErrorCode.systemErrorDomain"))
        XCTAssertFalse(source.contains("NSLocalizedDescriptionKey"))
        XCTAssertTrue(source.contains("userInfo: nil"))
    }

    #if !SWIFT_PACKAGE
    func testEveryTunnelErrorHasCopyForEveryManualProductLanguage() throws {
        let manualLanguages = ProductLanguage.allCases.filter { $0 != .system }
        XCTAssertEqual(manualLanguages.count, 13)
        for code in TunnelErrorCode.allCases {
            for language in manualLanguages {
                XCTAssertFalse(
                    TunnelErrorCopy.message(for: code, language: language).isEmpty,
                    "missing \(language.rawValue) copy for \(code.rawValue)"
                )
            }
        }

        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let localeDirectories = [
            "de", "es", "fr", "it", "ja", "ko", "nl", "pl",
            "pt-BR", "sv", "zh-Hans", "zh-Hant",
        ]
        let expectedKeys = Set(TunnelErrorCode.allCases.map { TunnelErrorCopy.source(for: $0).english })
        for locale in localeDirectories {
            let contents = try String(
                contentsOf: iosRoot.appendingPathComponent("RatelMesh/\(locale).lproj/Localizable.strings"),
                encoding: .utf8
            )
            let keys = Set(contents.split(separator: "\n").compactMap { line -> String? in
                guard line.first == "\"", let end = line.dropFirst().firstIndex(of: "\"") else { return nil }
                return String(line[line.index(after: line.startIndex)..<end])
            })
            XCTAssertTrue(expectedKeys.isSubset(of: keys), "\(locale) is missing tunnel error copy")
        }
    }
    #endif

    func testProviderRejectsDoubleStartAndStartWhileRunningWithoutOverwritingState() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: iosRoot.appendingPathComponent("PacketTunnel/PacketTunnelProvider.swift"),
            encoding: .utf8
        )
        for guardClause in [
            "self.core == nil",
            "self.startCompletion == nil",
            "!self.adapterStarted",
            "self.adapterOperation == nil",
            "self.stopCompletions.isEmpty",
            "self.lifecycle.canBegin",
        ] {
            XCTAssertTrue(source.contains(guardClause), "missing start guard: \(guardClause)")
        }
        XCTAssertTrue(source.contains("completion.call(self.systemError(for: ProviderError.alreadyActive))"))
    }

    func testClosingWatchdogAndRepeatedStopPreserveEveryCompletion() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: iosRoot.appendingPathComponent("PacketTunnel/PacketTunnelProvider.swift"),
            encoding: .utf8
        )
        XCTAssertTrue(source.contains("stopCompletions.append(completion)"))
        XCTAssertTrue(source.contains("guard !lifecycle.isTerminal, closingWatchdog == nil else { return }"))
        XCTAssertTrue(source.contains("completions.forEach { $0.call(()) }"))
        XCTAssertTrue(source.contains("adapterOperation = nil"))
        XCTAssertTrue(source.contains("self.adapterStopInFlight = false"))
    }

    func testLostStartUpdateDeactivateAndStopCallbacksUseBoundedClose() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: iosRoot.appendingPathComponent("PacketTunnel/PacketTunnelProvider.swift"),
            encoding: .utf8
        )
        for operation in ["case start", "case update", "case deactivate"] {
            XCTAssertTrue(source.contains(operation))
        }
        XCTAssertTrue(source.contains("startClosingWatchdogIfNeeded()"))
        XCTAssertTrue(source.contains("timer.schedule(deadline: .now() + .seconds(5))"))
        XCTAssertTrue(source.contains("cancelTunnelWithError(systemError(for: ProviderError.forcedTeardown))"))
        XCTAssertTrue(source.contains("adapter.stop"))
        XCTAssertTrue(source.contains("timer.schedule(deadline: .now() + .seconds(2))"))
        XCTAssertTrue(source.contains("self.adapterStopInFlight = false"))
    }

    func testSuccessfulStaleDeactivateDoesNotIssueSecondStop() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: iosRoot.appendingPathComponent("PacketTunnel/PacketTunnelProvider.swift"),
            encoding: .utf8
        )
        XCTAssertTrue(source.contains("if kind == .deactivate, error == nil"))
        XCTAssertTrue(source.contains("kind == .deactivate || error == nil"))
        XCTAssertTrue(source.contains("stopAdapterForClosing(force: forceStop)"))
    }

    func testClosingStopFailureEscalatesToTerminalForcedTeardown() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: iosRoot.appendingPathComponent("PacketTunnel/PacketTunnelProvider.swift"),
            encoding: .utf8
        )
        let closingStop = try XCTUnwrap(source.range(of: "private func stopAdapterForClosing"))
        let completeStop = try XCTUnwrap(source.range(
            of: "private func completeStopIfNeeded",
            range: closingStop.upperBound..<source.endIndex
        ))
        let body = String(source[closingStop.lowerBound..<completeStop.lowerBound])
        XCTAssertTrue(body.contains("if let error"))
        XCTAssertTrue(body.contains("self.forceProviderTeardown()"))
        XCTAssertTrue(body.contains("return"))
        XCTAssertTrue(source.contains("recordProviderError(ProviderError.forcedTeardown)"))
    }

    func testGoControlCoreIsIsolatedFromWireGuardGoRuntime() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let project = try String(
            contentsOf: iosRoot.appendingPathComponent("project.yml"),
            encoding: .utf8
        )
        XCTAssertTrue(project.contains("RatelMeshControl:"))
        XCTAssertTrue(project.contains("- target: RatelMeshControl"))
        let appTarget = try XCTUnwrap(project.range(of: "  RatelMesh:\n"))
        let tunnelTarget = try XCTUnwrap(
            project.range(of: "  PacketTunnel:\n", range: appTarget.upperBound..<project.endIndex)
        )
        let testsTarget = try XCTUnwrap(
            project.range(of: "  RatelMeshTests:\n", range: tunnelTarget.upperBound..<project.endIndex)
        )
        let appTargetBody = project[appTarget.lowerBound..<tunnelTarget.lowerBound]
        let tunnelTargetBody = project[tunnelTarget.lowerBound..<testsTarget.lowerBound]
        XCTAssertTrue(appTargetBody.contains(
            """
            - target: RatelMeshControl
                    embed: true
            """
        ))
        XCTAssertTrue(tunnelTargetBody.contains(
            """
            - target: RatelMeshControl
                    embed: false
            """
        ))
        let archiveVerification = try String(
            contentsOf: iosRoot.appendingPathComponent("Scripts/verify-archive.sh"),
            encoding: .utf8
        )
        XCTAssertTrue(archiveVerification.contains(
            #"CONTROL_FRAMEWORK="$APP_BUNDLE/Frameworks/RatelMeshControl.framework""#
        ))
        XCTAssertTrue(archiveVerification.contains(
            #"if [ -e "$EXTENSION_BUNDLE/Frameworks" ]"#
        ))
        let source = try String(
            contentsOf: iosRoot.appendingPathComponent("RatelMeshControl/RatelMeshMobileClient.swift"),
            encoding: .utf8
        )
        XCTAssertTrue(source.contains("app.doctorDisclosureVersion()"))
        XCTAssertTrue(source.contains("app.runNetworkDoctor"))
        XCTAssertTrue(source.contains("app.applyNetworkDoctorRepair"))
        let provider = try String(
            contentsOf: iosRoot.appendingPathComponent("PacketTunnel/PacketTunnelProvider.swift"),
            encoding: .utf8
        )
        XCTAssertTrue(provider.contains("import RatelMeshControl"))
        XCTAssertTrue(provider.contains("throw ProviderError.controlCoreStartFailed"))
        XCTAssertTrue(provider.contains("throw ProviderError.exitSelectionFailed"))
        XCTAssertTrue(provider.contains("applyNetworkSettings: routesChanged"))
        XCTAssertTrue(provider.contains("networkSettingsFingerprint"))
        let preparation = try String(
            contentsOf: iosRoot.appendingPathComponent("Scripts/prepare-wireguard.sh"),
            encoding: .utf8
        )
        XCTAssertTrue(preparation.contains("wireguard-apple-selective-network-settings.patch"))
        let adapterPatch = try String(
            contentsOf: iosRoot.appendingPathComponent(
                "Patches/wireguard-apple-selective-network-settings.patch"
            ),
            encoding: .utf8
        )
        XCTAssertTrue(adapterPatch.contains("applyNetworkSettings: Bool = true"))
        XCTAssertTrue(adapterPatch.contains("if applyNetworkSettings"))
        XCTAssertFalse(FileManager.default.fileExists(
            atPath: iosRoot.appendingPathComponent("PacketTunnel/RatelMeshMobileClient.swift").path
        ))
    }

    func testAppStoreExportDeclarationMatchesCurrentDistributionScope() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let project = try String(
            contentsOf: iosRoot.appendingPathComponent("project.yml"),
            encoding: .utf8
        )
        let info = try String(
            contentsOf: iosRoot.appendingPathComponent("RatelMesh/Info.plist"),
            encoding: .utf8
        )
        XCTAssertTrue(project.contains("ITSAppUsesNonExemptEncryption: false"))
        XCTAssertFalse(project.contains("ITSEncryptionExportComplianceCode"))
        XCTAssertTrue(info.contains(
            "<key>ITSAppUsesNonExemptEncryption</key>\n\t<false/>"
        ))
        XCTAssertFalse(info.contains("ITSEncryptionExportComplianceCode"))

        for scriptName in ["verify-archive.sh", "verify-ipa.sh"] {
            let script = try String(
                contentsOf: iosRoot.appendingPathComponent("Scripts/\(scriptName)"),
                encoding: .utf8
            )
            XCTAssertTrue(script.contains(
                "ITSEncryptionExportComplianceCode raw"
            ))
        }
    }

    func testAppStoreScreenshotFixtureCannotShipInRelease() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: iosRoot.appendingPathComponent("RatelMesh/AppViewModel.swift"),
            encoding: .utf8
        )
        let fixtureStart = try XCTUnwrap(
            source.range(of: "#if DEBUG\n    private func prepareAppStoreScreenshotFixture()")
        )
        let fixtureEnd = try XCTUnwrap(
            source.range(
                of: "\n#endif\n\n    func connect()",
                range: fixtureStart.lowerBound..<source.endIndex
            )
        )
        XCTAssertLessThan(fixtureStart.lowerBound, fixtureEnd.lowerBound)
        XCTAssertTrue(source.contains(
            "#if DEBUG\n        if ProcessInfo.processInfo.environment[\"RATELMESH_APP_STORE_SCREENSHOTS\"] == \"1\""
        ))
        XCTAssertTrue(source.contains(
            "ProcessInfo.processInfo.environment[\"RATELMESH_APP_STORE_SCREEN\"] == \"settings\""
        ))
    }

    func testDeviceConnectHookCannotShipInReleaseBuilds() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let app = try String(
            contentsOf: iosRoot.appendingPathComponent("RatelMesh/RatelMeshApp.swift"),
            encoding: .utf8
        )
        let connect = try XCTUnwrap(app.range(of: "await model.connect()"))
        let debugStart = try XCTUnwrap(
            app.range(of: "#if DEBUG", options: .backwards, range: app.startIndex..<connect.lowerBound)
        )
        let debugEnd = try XCTUnwrap(
            app.range(of: "#endif", range: connect.upperBound..<app.endIndex)
        )
        let debugBlock = app[debugStart.lowerBound..<debugEnd.upperBound]
        XCTAssertTrue(debugBlock.contains("await model.connect()"))
        XCTAssertTrue(app.contains("RATELMESH_DEVICE_TEST_CONNECT"))
        XCTAssertTrue(app.contains("--ratelmesh-device-test-connect"))
        XCTAssertTrue(app.contains("--ratelmesh-device-test-disconnect"))
        XCTAssertTrue(app.contains("--ratelmesh-device-test-exit="))
        XCTAssertTrue(app.contains("--ratelmesh-device-test-direct"))
        XCTAssertTrue(app.contains("--ratelmesh-device-test-network"))
        XCTAssertTrue(debugBlock.contains("runDeviceNetworkTests"))
    }

    func testLowLevelErrorsDoNotCarryUserVisibleHardcodedCopy() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        for relativePath in [
            "Shared/ClientConfiguration.swift",
            "Shared/SecureConfigurationStore.swift",
            "Shared/MobileModels.swift",
        ] {
            let source = try String(
                contentsOf: iosRoot.appendingPathComponent(relativePath),
                encoding: .utf8
            )
            XCTAssertFalse(source.contains("errorDescription"), relativePath)
            XCTAssertFalse(source.contains("LocalizedError"), relativePath)
        }
    }

    func testEveryTranslationLocalizesTheSystemLocationPrompt() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        for locale in ["de", "es", "fr", "it", "ja", "ko", "nl", "pl", "pt-BR", "sv", "zh-Hans", "zh-Hant"] {
            let source = try String(
                contentsOf: iosRoot.appendingPathComponent(
                    "RatelMesh/\(locale).lproj/InfoPlist.strings"
                ),
                encoding: .utf8
            )
            XCTAssertTrue(source.contains(#""NSLocationWhenInUseUsageDescription" ="#), locale)
        }
    }

    func testPrepareObservesProviderErrorBeforeFailableSetup() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: iosRoot.appendingPathComponent("RatelMesh/AppViewModel.swift"),
            encoding: .utf8
        )
        let prepare = try XCTUnwrap(source.range(of: "func prepare() async"))
        let observe = try XCTUnwrap(source.range(
            of: "observeProviderError()",
            range: prepare.upperBound..<source.endIndex
        ))
        let setup = try XCTUnwrap(source.range(
            of: "if let saved = try store.load()",
            range: prepare.upperBound..<source.endIndex
        ))
        XCTAssertLessThan(observe.lowerBound, setup.lowerBound)
    }

    func testAppGroupFailureIsExplicitInAppAndProvider() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let constants = try String(
            contentsOf: iosRoot.appendingPathComponent("Shared/AppConstants.swift"),
            encoding: .utf8
        )
        let app = try String(
            contentsOf: iosRoot.appendingPathComponent("RatelMesh/AppViewModel.swift"),
            encoding: .utf8
        )
        let provider = try String(
            contentsOf: iosRoot.appendingPathComponent("PacketTunnel/PacketTunnelProvider.swift"),
            encoding: .utf8
        )
        XCTAssertFalse(constants.contains("?? .standard"))
        XCTAssertTrue(app.contains("throw AppGroupAccessError.unavailable"))
        XCTAssertTrue(provider.contains("throw ProviderError.missingAppGroup"))
        XCTAssertTrue(app.contains("let container = AppConstants.sharedContainerURL"))
        XCTAssertTrue(provider.contains("let container = AppConstants.sharedContainerURL"))
        XCTAssertTrue(app.contains("try store.validateAccessGroup()"))
        XCTAssertTrue(provider.contains("try SecureConfigurationStore().validateAccessGroup()"))
        XCTAssertTrue(provider.contains("throw ProviderError.missingKeychainGroup"))
        XCTAssertTrue(app.contains("@Published private(set) var appGroupReady = false"))
        XCTAssertTrue(app.contains("guard appGroupReady, sharedDefaults != nil else"))
        XCTAssertTrue(app.contains("guard appGroupReady, let sharedDefaults else"))
    }

    func testRuntimeStatsGateRejectsStaleGenerationWithoutClearingNewRead() throws {
        var gate = RuntimeStatsReadGate()
        let stale = try XCTUnwrap(gate.begin(generation: 1))

        gate.invalidate()
        let current = try XCTUnwrap(gate.begin(generation: 3))
        XCTAssertFalse(gate.finish(stale, currentGeneration: 3))
        XCTAssertNil(gate.begin(generation: 3), "stale callback cleared the current read")
        XCTAssertTrue(gate.finish(current, currentGeneration: 3))
        XCTAssertNotNil(gate.begin(generation: 3))
    }

    func testRuntimeStatsCallbackRequiresGenerationAndCoreIdentity() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: iosRoot.appendingPathComponent("PacketTunnel/PacketTunnelProvider.swift"),
            encoding: .utf8
        )
        XCTAssertTrue(source.contains("self.statsReadGate.finish(token, currentGeneration: self.lifecycle.value)"))
        XCTAssertTrue(source.contains("self.lifecycle.accepts(generation)"))
        XCTAssertTrue(source.contains("self.core === core"))
        XCTAssertTrue(source.contains("self.adapterStarted"))
        XCTAssertTrue(source.contains("self.adapterOperation?.kind != .deactivate"))
        XCTAssertTrue(source.contains("statsReadGate.invalidate()"))
    }

    func testNormalDeactivationInvalidatesStatsBeforeStoppingAdapter() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: iosRoot.appendingPathComponent("PacketTunnel/PacketTunnelProvider.swift"),
            encoding: .utf8
        )
        let deactivate = try XCTUnwrap(source.range(of: "private func deactivateAdapter"))
        let invalidate = try XCTUnwrap(source.range(
            of: "statsReadGate.invalidate()",
            range: deactivate.upperBound..<source.endIndex
        ))
        let stop = try XCTUnwrap(source.range(
            of: "adapter.stop",
            range: invalidate.upperBound..<source.endIndex
        ))
        XCTAssertLessThan(invalidate.lowerBound, stop.lowerBound)
    }

    func testInitialPollFailureRecordsOnlyThroughFailInitialStart() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: iosRoot.appendingPathComponent("PacketTunnel/PacketTunnelProvider.swift"),
            encoding: .utf8
        )
        let poll = try XCTUnwrap(source.range(of: "private func pollOnce()"))
        let stats = try XCTUnwrap(source.range(
            of: "private func reportRuntimeStats",
            range: poll.upperBound..<source.endIndex
        ))
        let body = String(source[poll.lowerBound..<stats.lowerBound])
        XCTAssertTrue(body.contains("if !adapterStarted, startCompletion != nil"))
        XCTAssertTrue(body.contains("failInitialStart(error)"))
        XCTAssertTrue(body.contains("else {\n                recordProviderError(error)\n            }"))
        XCTAssertFalse(body.contains("recordProviderError(error)\n            if !adapterStarted"))
    }

    func testProviderErrorAcknowledgementAndAlertQueueAreExplicit() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let app = try String(
            contentsOf: iosRoot.appendingPathComponent("RatelMesh/AppViewModel.swift"),
            encoding: .utf8
        )
        let view = try String(
            contentsOf: iosRoot.appendingPathComponent("RatelMesh/ContentView.swift"),
            encoding: .utf8
        )
        let observe = try XCTUnwrap(app.range(of: "private func observeProviderError()"))
        let acknowledge = try XCTUnwrap(app.range(of: "func acknowledgeError()"))
        let refresh = try XCTUnwrap(app.range(
            of: "private func beginRefreshing()",
            range: acknowledge.upperBound..<app.endIndex
        ))
        let observeBody = String(app[observe.lowerBound..<app.endIndex])
        let acknowledgeBody = String(app[acknowledge.lowerBound..<refresh.lowerBound])
        XCTAssertFalse(observeBody.contains("sharedDefaults.set(event.id"))
        XCTAssertTrue(observeBody.contains("TunnelErrorStore.pendingEvents"))
        XCTAssertTrue(acknowledgeBody.contains("TunnelErrorStore.acknowledge"))
        XCTAssertFalse(acknowledgeBody.contains("lastSeenProviderErrorEventKey"))
        XCTAssertTrue(app.contains("errorQueue.enqueueProvider(event)"))
        XCTAssertTrue(app.contains("errorQueue.enqueueLocal"))
        XCTAssertTrue(view.contains("set: { if !$0 { model.acknowledgeError() } }"))
        XCTAssertTrue(view.contains("Button(t(\"好\", \"OK\")) {}"))
        XCTAssertTrue(
            view.contains("!model.appGroupReady || model.isBusy || model.isTransitioning")
        )
        XCTAssertTrue(view.contains(".disabled(!model.appGroupReady)"))
    }

    #if os(macOS)
    func testArchiveRequiresExactExternalVersionAndBuild() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let project = try String(
            contentsOf: iosRoot.appendingPathComponent("project.yml"),
            encoding: .utf8
        )
        let version = try XCTUnwrap(
            project.firstMatch(capturing: #"MARKETING_VERSION:\s*([^\s]+)"#)
        )
        let build = try XCTUnwrap(
            project.firstMatch(capturing: #"CURRENT_PROJECT_VERSION:\s*([^\s]+)"#)
        )

        let valid = try runArchiveValidation(
            iosRoot: iosRoot,
            arguments: [version, build]
        )
        XCTAssertEqual(valid.status, 0, valid.output)

        let mismatch = try runArchiveValidation(
            iosRoot: iosRoot,
            arguments: ["999.999.999", build]
        )
        XCTAssertNotEqual(mismatch.status, 0)
        XCTAssertTrue(mismatch.output.contains("release version mismatch"))

        let malformed = try runArchiveValidation(
            iosRoot: iosRoot,
            arguments: ["\(version)-dirty", build]
        )
        XCTAssertNotEqual(malformed.status, 0)
        XCTAssertTrue(malformed.output.contains("invalid release version"))
    }
    #endif

    func testWatchdogForcesSystemAndAdapterTeardownBeforeCompletingStops() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: iosRoot.appendingPathComponent("PacketTunnel/PacketTunnelProvider.swift"),
            encoding: .utf8
        )
        let cancel = try XCTUnwrap(source.range(of: "cancelTunnelWithError(systemError(for: ProviderError.forcedTeardown))"))
        let forcedStop = try XCTUnwrap(source.range(of: "adapter.stop", range: cancel.lowerBound..<source.endIndex))
        let finalBound = try XCTUnwrap(source.range(of: "deadline: .now() + .seconds(2)", range: forcedStop.lowerBound..<source.endIndex))
        let completion = try XCTUnwrap(source.range(of: "self.completeStopWaiters()", range: finalBound.lowerBound..<source.endIndex))
        XCTAssertLessThan(cancel.lowerBound, forcedStop.lowerBound)
        XCTAssertLessThan(forcedStop.lowerBound, finalBound.lowerBound)
        XCTAssertLessThan(finalBound.lowerBound, completion.lowerBound)
        XCTAssertFalse(source.contains("closingTimedOut"))
    }

    func testForcedTimeoutQuarantinesProviderUntilSystemReplacesIt() throws {
        var lifecycle = TunnelLifecycleGeneration()
        _ = lifecycle.begin()
        lifecycle.markTerminal()
        XCTAssertTrue(lifecycle.isClosing)
        XCTAssertTrue(lifecycle.isTerminal)
        XCTAssertFalse(lifecycle.canBegin)

        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: iosRoot.appendingPathComponent("PacketTunnel/PacketTunnelProvider.swift"),
            encoding: .utf8
        )
        let timeout = try XCTUnwrap(source.range(of: "timer.schedule(deadline: .now() + .seconds(2))"))
        let assignment = try XCTUnwrap(source.range(
            of: "forcedTeardownWatchdog = timer",
            range: timeout.upperBound..<source.endIndex
        ))
        let handler = String(source[timeout.lowerBound..<assignment.upperBound])
        XCTAssertTrue(handler.contains("self.cancelTeardownWatchdogs()"))
        XCTAssertTrue(handler.contains("self.completeStopWaiters()"))
        XCTAssertFalse(handler.contains("self.adapterOperation = nil"))
        XCTAssertFalse(handler.contains("self.adapterStopInFlight = false"))
        XCTAssertFalse(handler.contains("self.adapterStarted = false"))
        XCTAssertTrue(source.contains("guard lifecycle.isClosing, !lifecycle.isTerminal else { return }"))
    }

    func testRepeatedStopDuringForcedTeardownCannotCreateAnotherWatchdog() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let source = try String(
            contentsOf: iosRoot.appendingPathComponent("PacketTunnel/PacketTunnelProvider.swift"),
            encoding: .utf8
        )
        let terminalBranch = try XCTUnwrap(source.range(of: "if self.lifecycle.isTerminal {"))
        let nextBranch = try XCTUnwrap(source.range(
            of: "if self.adapterOperation == nil",
            range: terminalBranch.upperBound..<source.endIndex
        ))
        let body = String(source[terminalBranch.lowerBound..<nextBranch.lowerBound])
        XCTAssertTrue(body.contains("self.forcedTeardownWatchdog != nil"))
        XCTAssertTrue(body.contains("self.stopCompletions.append(completion)"))
        XCTAssertFalse(body.contains("startClosingWatchdogIfNeeded"))
        XCTAssertTrue(source.contains("guard !lifecycle.isTerminal, closingWatchdog == nil else { return }"))
        XCTAssertTrue(source.contains("private func cancelTeardownWatchdogs()"))
    }

    func testStartInFlightCallbackIsRejectedAfterStop() {
        var lifecycle = TunnelLifecycleGeneration()
        let startGeneration = lifecycle.begin()
        XCTAssertTrue(lifecycle.accepts(startGeneration))

        lifecycle.invalidate()

        XCTAssertTrue(lifecycle.isClosing)
        XCTAssertFalse(lifecycle.accepts(startGeneration))
    }

    func testStartInFlightCallbackIsRejectedAfterTimeoutAndNextStart() {
        var lifecycle = TunnelLifecycleGeneration()
        let timedOutGeneration = lifecycle.begin()
        lifecycle.invalidate()
        XCTAssertFalse(lifecycle.accepts(timedOutGeneration))

        let nextGeneration = lifecycle.begin()
        XCTAssertFalse(lifecycle.accepts(timedOutGeneration))
        XCTAssertTrue(lifecycle.accepts(nextGeneration))
    }

    func testUpdateAndDeactivateCallbacksAreRejectedAfterStop() {
        for operation in ["update", "deactivate"] {
            var lifecycle = TunnelLifecycleGeneration()
            let operationGeneration = lifecycle.begin()
            lifecycle.invalidate()
            XCTAssertFalse(
                lifecycle.accepts(operationGeneration),
                "\(operation) callback must not mutate a closed lifecycle"
            )
        }
    }

    #if os(macOS)
    private func runArchiveValidation(
        iosRoot: URL,
        arguments: [String]
    ) throws -> (status: Int32, output: String) {
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = [iosRoot.appendingPathComponent("Scripts/archive.sh").path] + arguments
        process.environment = ["RATELMESH_ARCHIVE_VALIDATE_ONLY": "1"]
        process.standardOutput = output
        process.standardError = output
        try process.run()
        process.waitUntilExit()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        return (process.terminationStatus, String(decoding: data, as: UTF8.self))
    }
    #endif

    func testMakeReleaseIOSPassesIndependentVersionAndBuild() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let makefile = try String(
            contentsOf: iosRoot
                .deletingLastPathComponent()
                .deletingLastPathComponent()
                .appendingPathComponent("Makefile"),
            encoding: .utf8
        )
        XCTAssertTrue(makefile.contains("archive.sh \"$(VERSION)\" \"$(BUILD)\""))
        XCTAssertTrue(makefile.contains("make release-ios VERSION=X.Y.Z BUILD=N"))
    }

    func testVerifyAcceptsCurrentSimctlAvailableRuntimeFormat() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let script = try String(
            contentsOf: iosRoot.appendingPathComponent("Scripts/verify.sh"),
            encoding: .utf8
        )
        XCTAssertTrue(script.contains("simctl list runtimes available"))
        XCTAssertTrue(script.contains("grep -Eq '^iOS[[:space:]]'"))
        XCTAssertFalse(script.contains("iOS .*available"))
    }
}

private extension String {
    func firstMatch(capturing pattern: String) -> String? {
        guard let expression = try? NSRegularExpression(pattern: pattern),
              let match = expression.firstMatch(
                  in: self,
                  range: NSRange(startIndex..<endIndex, in: self)
              ),
              let range = Range(match.range(at: 1), in: self) else {
            return nil
        }
        return String(self[range])
    }
}
