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
        precondition(appSource.contains("RatelMeshBrandMark(size: 18, template: true)"))
        precondition(appSource.contains(#"forResource: "BrandMarkDark", withExtension: "png""#))
        precondition(appSource.contains(#"forInfoDictionaryKey: "RatelMeshMenuTemplatePNG""#))

        let infoData = try Data(contentsOf: sourceDirectory.appendingPathComponent("Info.plist"))
        let info = try PropertyListSerialization.propertyList(from: infoData, format: nil) as? [String: Any]
        let menuImage = info?["RatelMeshMenuTemplatePNG"] as? Data
        precondition(menuImage?.isEmpty == false)

        print("macOS menu support tests passed")
    }
}
