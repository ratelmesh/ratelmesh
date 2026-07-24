import XCTest
#if SWIFT_PACKAGE
@testable import RatelMeshShared
#else
@testable import RatelMesh
#endif

final class IPPrefixTests: XCTestCase {
    func testSubtractsIPv4PrefixWithoutExpandingHosts() throws {
        let routes = try IPPrefix("0.0.0.0/0").subtracting([IPPrefix("10.0.0.0/8")])
        XCTAssertEqual(routes.count, 8)
        XCTAssertFalse(routes.map(\.description).contains("10.0.0.0/8"))
        XCTAssertTrue(routes.map(\.description).contains("128.0.0.0/1"))
    }

    func testSubtractsIPv6Prefix() throws {
        let routes = try IPPrefix("::/0").subtracting([IPPrefix("fd00::/8")])
        XCTAssertEqual(routes.count, 8)
        XCTAssertFalse(routes.map(\.description).contains("fd00::/8"))
    }

    func testUnrelatedFamilyDoesNotChangeRoute() throws {
        let routes = try IPPrefix("0.0.0.0/0").subtracting([IPPrefix("fd00::/8")])
        XCTAssertEqual(routes.map(\.description), ["0.0.0.0/0"])
    }
}
