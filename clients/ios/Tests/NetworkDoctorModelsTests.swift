import XCTest
#if SWIFT_PACKAGE
@testable import RatelMeshShared
#else
@testable import RatelMesh
#endif

final class NetworkDoctorModelsTests: XCTestCase {
    func testDecodesOpaquePlanAndExportsOnlyTypedRedactedReport() throws {
        let diagnosis = try JSONDecoder().decode(
            NetworkDoctorDiagnosis.self,
            from: Data(Self.diagnosisJSON.utf8)
        )
        XCTAssertEqual(diagnosis.planID, "opaque-plan-7")
        XCTAssertEqual(diagnosis.report.schema, networkDoctorReportSchema)
        XCTAssertEqual(diagnosis.plan.schema, networkDoctorPlanSchema)
        XCTAssertEqual(diagnosis.executableRepairs.map(\.action), ["lower-mtu"])

        let exported = try diagnosis.report.redactedJSON()
        let text = try XCTUnwrap(String(data: exported, encoding: .utf8))
        XCTAssertTrue(text.contains("[redacted:ip-public:abc123]"))
        XCTAssertFalse(text.contains("opaque-plan-7"))
        XCTAssertFalse(text.contains("lower-mtu"))
    }

    func testExecutionDistinguishesRestoredAndUncertainState() throws {
        let data = Data("""
        {
          "schema": "\(networkDoctorExecutionSchema)",
          "repairs": [
            {"action":"lower-mtu","status":"postcondition_failed","rolled_back":[{"op":"mtu.set","ok":true}]},
            {"action":"flush-dns","status":"uncertain"}
          ]
        }
        """.utf8)
        let report = try JSONDecoder().decode(NetworkDoctorExecutionReport.self, from: data)
        XCTAssertFalse(report.repairs[0].needsManualAttention)
        XCTAssertTrue(report.repairs[1].needsManualAttention)
    }

    func testDiagnosisWithoutRepairsDecodesAsReadOnlyReport() throws {
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(Self.diagnosisJSON.utf8)) as? [String: Any]
        )
        object.removeValue(forKey: "availableRepairs")
        object.removeValue(forKey: "planID")
        var plan = try XCTUnwrap(object["plan"] as? [String: Any])
        plan["repairs"] = NSNull()
        object["plan"] = plan
        let data = try JSONSerialization.data(withJSONObject: object)

        let diagnosis = try JSONDecoder().decode(NetworkDoctorDiagnosis.self, from: data)

        XCTAssertEqual(diagnosis.availableRepairs, [])
        XCTAssertEqual(diagnosis.planID, "")
        XCTAssertEqual(diagnosis.plan.repairs, [])
        XCTAssertEqual(diagnosis.executableRepairs, [])
        XCTAssertEqual(diagnosis.report.schema, networkDoctorReportSchema)
    }

    func testRejectsUnsupportedReportForExport() throws {
        var object = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(Self.diagnosisJSON.utf8)) as? [String: Any]
        )
        var report = try XCTUnwrap(object["report"] as? [String: Any])
        report["schema"] = "future/v9"
        object["report"] = report
        let data = try JSONSerialization.data(withJSONObject: object)
        let diagnosis = try JSONDecoder().decode(NetworkDoctorDiagnosis.self, from: data)
        XCTAssertThrowsError(try diagnosis.report.redactedJSON())
    }

    func testEverySupportedLocaleContainsNetworkDoctorCopy() throws {
        let iosRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let locales = ["de", "es", "fr", "it", "ja", "ko", "nl", "pl", "pt-BR", "sv", "zh-Hans", "zh-Hant"]
        let reference = try reference
        for locale in locales {
            let iosURL = iosRoot.appendingPathComponent(
                "RatelMesh/\(locale).lproj/NetworkDoctor.strings"
            )
            let data = try Data(contentsOf: iosURL)
            let text = try XCTUnwrap(String(data: data, encoding: .utf8))
            XCTAssertTrue(text.contains(#""Network Doctor" ="#), locale)
            XCTAssertTrue(text.contains(#""Rollback failed; manual action required" ="#), locale)
            XCTAssertTrue(text.contains(#""Exports only the redacted JSON report shown here" ="#), locale)

            let strings = try XCTUnwrap(
                PropertyListSerialization.propertyList(from: data, format: nil) as? [String: String]
            )
            XCTAssertEqual(strings.count, 54, locale)
            XCTAssertEqual(Set(strings.keys), Set(reference.keys), locale)
            for (key, value) in strings {
                XCTAssertFalse(value.isEmpty, "\(locale): \(key)")
                XCTAssertEqual(value.components(separatedBy: "%d").count, key.components(separatedBy: "%d").count, "\(locale): \(key)")
            }
            let unchangedEnglish = Set(
                strings.compactMap { $0.key == $0.value ? $0.key : nil }
            )
            XCTAssertEqual(
                unchangedEnglish,
                locale == "sv" ? Set(["Support"]) : Set<String>(),
                "\(locale) contains an English fallback"
            )

            let macURL = iosRoot
                .deletingLastPathComponent()
                .appendingPathComponent(
                    "macos-menubar/Localizations/\(locale).lproj/NetworkDoctor.strings"
                )
            XCTAssertEqual(data, try Data(contentsOf: macURL), "\(locale) differs between iOS and macOS")
        }

        for locale in ["zh-Hans", "zh-Hant"] {
            let data = try Data(contentsOf: iosRoot.appendingPathComponent(
                "RatelMesh/\(locale).lproj/NetworkDoctor.strings"
            ))
            let strings = try XCTUnwrap(
                PropertyListSerialization.propertyList(from: data, format: nil) as? [String: String]
            )
            XCTAssertTrue(strings.allSatisfy { $0.key != $0.value }, "\(locale) contains an English fallback")
        }
    }

    private var reference: [String: String] {
        get throws {
            let iosRoot = URL(fileURLWithPath: #filePath)
                .deletingLastPathComponent()
                .deletingLastPathComponent()
            let data = try Data(contentsOf: iosRoot.appendingPathComponent(
                "RatelMesh/zh-Hans.lproj/NetworkDoctor.strings"
            ))
            return try XCTUnwrap(
                PropertyListSerialization.propertyList(from: data, format: nil) as? [String: String]
            )
        }
    }

    fileprivate static let diagnosisJSON = """
    {
      "schema": "\(networkDoctorAPISchema)",
      "planID": "opaque-plan-7",
      "availableRepairs": ["lower-mtu"],
      "report": {
        "schema": "\(networkDoctorReportSchema)",
        "generated_at": "2026-07-26T12:00:00Z",
        "summary": {
          "ok": false,
          "worst_severity": "warning",
          "total_findings": 1,
          "counts_by_severity": {"warning": 1}
        },
        "findings": [{
          "code": "mtu.blackhole",
          "severity": "warning",
          "probe": "path-mtu",
          "summary": "Path to [redacted:ip-public:abc123] drops large packets"
        }],
        "probes": [{"probe":"path-mtu","status":"completed","duration_ms":12,"findings":1}]
      },
      "plan": {
        "schema": "\(networkDoctorPlanSchema)",
        "dry_run": true,
        "repairs": [{
          "action": "lower-mtu",
          "title": "Lower tunnel MTU",
          "addresses": ["mtu.blackhole"],
          "applicable": true,
          "apply": [{"op":"mtu.set","params":{"mtu":"1280"}}],
          "rollback": [{"op":"mtu.set","params":{"from_snapshot":"mtu"}}]
        }]
      }
    }
    """
}

#if !SWIFT_PACKAGE
@MainActor
private final class FakeNetworkDoctorService: NetworkDoctorServicing {
    var executeCalls = 0
    let diagnosis: NetworkDoctorDiagnosis
    let execution: NetworkDoctorExecutionReport

    init() throws {
        diagnosis = try JSONDecoder().decode(
            NetworkDoctorDiagnosis.self,
            from: Data(NetworkDoctorModelsTests.diagnosisJSON.utf8)
        )
        execution = try JSONDecoder().decode(
            NetworkDoctorExecutionReport.self,
            from: Data("""
            {"schema":"\(networkDoctorExecutionSchema)","repairs":[{"action":"lower-mtu","status":"applied"}]}
            """.utf8)
        )
    }

    func diagnose() async throws -> NetworkDoctorDiagnosis { diagnosis }

    func execute(planID: String, action: String, confirmed: Bool) async throws -> NetworkDoctorExecutionReport {
        XCTAssertEqual(planID, "opaque-plan-7")
        XCTAssertEqual(action, "lower-mtu")
        XCTAssertTrue(confirmed)
        executeCalls += 1
        return execution
    }
}

@MainActor
final class NetworkDoctorStoreTests: XCTestCase {
    func testRepairCannotExecuteBeforeExplicitConfirmation() async throws {
        let service = try FakeNetworkDoctorService()
        let store = NetworkDoctorStore(service: service)

        await store.run()
        XCTAssertEqual(store.phase, .review)
        XCTAssertEqual(service.executeCalls, 0)

        await store.confirmAndRepair()
        XCTAssertEqual(service.executeCalls, 0)
        XCTAssertEqual(store.phase, .failed)
    }

    func testConfirmedRepairUsesOnlyOpaquePlanID() async throws {
        let service = try FakeNetworkDoctorService()
        let store = NetworkDoctorStore(service: service)

        await store.run()
        store.requestConfirmation()
        XCTAssertEqual(store.phase, .confirming)
        await store.confirmAndRepair()

        XCTAssertEqual(service.executeCalls, 1)
        XCTAssertEqual(store.phase, .finished)
        XCTAssertEqual(store.execution?.repairs.first?.status, "applied")
    }
}
#endif
