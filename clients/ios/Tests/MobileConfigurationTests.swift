import XCTest
#if SWIFT_PACKAGE
@testable import RatelMeshShared
#else
@testable import RatelMesh
#endif

final class MobileConfigurationTests: XCTestCase {
    func testDecodesVerifiedExitAndItsClients() throws {
        let json = #"{"state":"Running","peers":[],"activeExit":"home-exit","selectedExit":"home-exit","exitTrafficVerified":true,"exitClients":[{"name":"phone","meshIP":"100.64.0.3","state":"active","online":true}]}"#
        let status = try JSONDecoder().decode(MobileStatus.self, from: Data(json.utf8))
        XCTAssertTrue(status.exitTrafficVerified == true)
        XCTAssertEqual(status.exitClients?.first?.name, "phone")
        XCTAssertEqual(status.exitClients?.first?.state, "active")
    }

    func testDecodesTenantRemoteAccessGrant() throws {
        let json = #"{"state":"Running","peers":[{"name":"office","meshIP":"100.64.0.8","role":"plain","online":true,"pathType":"direct","platform":"windows","remoteAccessAllowed":true}],"activeExit":""}"#
        let status = try JSONDecoder().decode(MobileStatus.self, from: Data(json.utf8))
        XCTAssertEqual(status.peers.first?.platform, "windows")
        XCTAssertTrue(status.peers.first?.remoteAccessAllowed == true)
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
}
