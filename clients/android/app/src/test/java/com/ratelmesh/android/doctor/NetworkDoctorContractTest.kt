package com.ratelmesh.android.doctor

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.json.JSONObject

class NetworkDoctorContractTest {
    @Test
    fun `daemon diagnostic identifiers accept dotted codes but reject injection`() {
        assertEquals(
            "routes.exit_default_absent",
            boundedDiagnosticID("routes.exit_default_absent", 128),
        )
        assertEquals("dns.ok", boundedDiagnosticID("dns.ok", 128))
        assertThrows(IllegalArgumentException::class.java) {
            boundedDiagnosticID("dns.ok\nforged", 128)
        }
        assertThrows(IllegalArgumentException::class.java) {
            boundedDiagnosticID("../secret", 128)
        }
    }

    @Test
    fun `report parser accepts only explicitly redacted bounded schema`() {
        val report = parseDoctorReportJSON(
            """
            {
              "schema": 1,
              "redacted": true,
              "id": "report-1",
              "summary": "One route needs attention.",
              "shareText": "RatelMesh report\\nroutes.exit_default_absent",
              "findings": [{
                "code": "routes.exit_default_absent",
                "severity": "CRITICAL",
                "title": "EXIT route missing",
                "detail": "The expected tunnel route is not active."
              }]
            }
            """.trimIndent(),
        )

        assertEquals("report-1", report.id)
        assertEquals(DoctorSeverity.CRITICAL, report.findings.single().severity)
        assertTrue(report.redacted)

        assertThrows(IllegalArgumentException::class.java) {
            parseDoctorReportJSON(
                """{"schema":1,"redacted":false,"id":"raw","findings":[]}""",
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            parseDoctorReportJSON(
                """{"schema":1,"redacted":true,"id":"raw","findings":[],"rawSnapshot":"secret"}""",
            )
        }
    }

    @Test
    fun `repair plan is bound to the report being reviewed`() {
        val raw =
            """
            {
              "schema": 1,
              "id": "plan-1",
              "reportID": "report-1",
              "actions": [{
                "id": "repair-route",
                "title": "Restore tunnel routes",
                "detail": "Reapply the active tunnel configuration.",
                "reversible": true
              }]
            }
            """.trimIndent()

        assertEquals("plan-1", parseDoctorRepairPlanJSON(raw, "report-1").id)
        assertThrows(IllegalArgumentException::class.java) {
            parseDoctorRepairPlanJSON(raw, "other-report")
        }
        assertThrows(IllegalArgumentException::class.java) {
            parseDoctorRepairPlanJSON(
                """{"schema":1,"id":"plan-1","reportID":"report-1","actions":[]}""",
                "report-1",
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            parseDoctorRepairPlanJSON(
                """
                {
                  "schema": 1,
                  "id": "plan-1",
                  "reportID": "report-1",
                  "actions": [
                    {"id":"one","title":"One","detail":"","reversible":false},
                    {"id":"two","title":"Two","detail":"","reversible":false}
                  ]
                }
                """.trimIndent(),
                "report-1",
            )
        }
    }

    @Test
    fun `daemon plan id is optional only when no repair is exposed`() {
        assertEquals("", doctorPlanID(JSONObject("""{"schema":"doctor"}"""), 0))
        assertEquals(
            "opaque_plan-1",
            doctorPlanID(JSONObject("""{"planID":"opaque_plan-1"}"""), 1),
        )
        assertThrows(IllegalArgumentException::class.java) {
            doctorPlanID(JSONObject("""{"schema":"doctor"}"""), 1)
        }
        assertThrows(IllegalArgumentException::class.java) {
            doctorPlanID(JSONObject("""{"planID":"not allowed"}"""), 0)
        }
    }

    @Test
    fun `process restore fails interrupted mutations closed`() {
        listOf(
            DoctorPhase.RUNNING,
            DoctorPhase.LOADING_PLAN,
            DoctorPhase.REPAIRING,
            DoctorPhase.ROLLING_BACK,
        ).forEach { phase ->
            val restored = NetworkDoctorStateCodec.decode(
                NetworkDoctorStateCodec.encode(NetworkDoctorUiState(phase = phase)),
            )
            assertEquals(DoctorPhase.ERROR, restored.phase)
            assertEquals("interrupted", restored.errorCode)
        }
    }

    @Test
    fun `stable report and rollback receipt survive process restore without stale plan`() {
        val original = NetworkDoctorUiState(
            phase = DoctorPhase.REPAIRED,
            report = DoctorReport(
                id = "report-1",
                summary = "Ready",
                findings = listOf(DoctorFinding("dns.ok", DoctorSeverity.OK, "DNS", "Healthy")),
                shareText = "redacted report",
                redacted = true,
                repairsAvailable = true,
            ),
            plan = DoctorRepairPlan(
                id = "plan-1",
                reportID = "report-1",
                actions = listOf(DoctorRepairAction("dns", "Refresh DNS", "Refresh", true)),
            ),
            receipt = DoctorRepairReceipt("Applied", "opaque-rollback-token"),
        )

        val restored = NetworkDoctorStateCodec.decode(NetworkDoctorStateCodec.encode(original))
        assertEquals(DoctorPhase.REPAIRED, restored.phase)
        assertFalse(requireNotNull(restored.report).repairsAvailable)
        assertEquals(null, restored.plan)
        assertEquals(original.receipt, restored.receipt)
    }

    @Test
    fun `confirmation restore returns to report and clears the ephemeral plan`() {
        val report = DoctorReport(
            id = "report-1",
            summary = "Ready",
            findings = emptyList(),
            shareText = "redacted report",
            redacted = true,
            repairsAvailable = true,
        )
        val plan = DoctorRepairPlan(
            id = "plan-1",
            reportID = report.id,
            actions = listOf(DoctorRepairAction("dns", "Refresh DNS", "Refresh", true)),
        )

        val encoded = NetworkDoctorStateCodec.encode(
            NetworkDoctorUiState(
                phase = DoctorPhase.CONFIRM_REPAIR,
                report = report,
                plan = plan,
            ),
        )
        assertFalse(encoded.contains("plan-1"))
        val restored = NetworkDoctorStateCodec.decode(encoded)

        assertEquals(DoctorPhase.REPORT, restored.phase)
        assertFalse(requireNotNull(restored.report).repairsAvailable)
        assertEquals(null, restored.plan)
    }

    @Test
    fun `restore rejects unknown finding severity instead of downgrading it`() {
        val encoded = NetworkDoctorStateCodec.encode(
            NetworkDoctorUiState(
                phase = DoctorPhase.REPORT,
                report = DoctorReport(
                    id = "report-1",
                    summary = "Ready",
                    findings = listOf(
                        DoctorFinding("future", DoctorSeverity.INFO, "Future", "Unknown"),
                    ),
                    shareText = "redacted",
                    redacted = true,
                ),
            ),
        ).replace("\"severity\":\"INFO\"", "\"severity\":\"FUTURE_CRITICAL\"")

        val restored = NetworkDoctorStateCodec.decode(encoded)
        assertEquals(DoctorPhase.ERROR, restored.phase)
        assertEquals("restore_failed", restored.errorCode)
    }

    @Test
    fun `screen exposes progress announcements confirmation and safe sharing`() {
        val source = File(appDir, "src/main/java/com/ratelmesh/android/doctor/NetworkDoctorScreen.kt").readText()
        val gateway = File(appDir, "src/main/java/com/ratelmesh/android/doctor/NetworkDoctorGateway.kt").readText()

        assertTrue(source.contains("progressBarRangeInfo"))
        assertTrue(source.contains("LiveRegionMode.Polite"))
        assertTrue(source.contains("RepairConfirmationDialog"))
        assertTrue(source.contains("Intent.createChooser"))
        assertTrue(source.contains("report.redacted"))
        assertFalse(gateway.contains("error.message"))
        assertFalse(gateway.contains("printStackTrace"))
    }

    @Test
    fun `android 13 advertised locales include the doctor decision flow`() {
        val localeDirectories = listOf(
            "values-es",
            "values-de",
            "values-fr",
            "values-ja",
            "values-ko",
            "values-it",
            "values-nl",
            "values-pl",
            "values-sv",
            "values-pt-rBR",
            "values-zh-rCN",
            "values-zh-rTW",
        )
        val required = listOf(
            "doctor_entry",
            "doctor_privacy_note",
            "doctor_start",
            "doctor_report_title",
            "doctor_share_report",
            "doctor_confirm_title",
            "doctor_confirm_apply",
            "doctor_cancel",
            "doctor_repair_complete",
            "doctor_rollback",
            "doctor_error_generic",
            "doctor_retry",
        )
        localeDirectories.forEach { directory ->
            val resource = File(appDir, "src/main/res/$directory/doctor.xml")
            assertTrue("$directory doctor resources missing", resource.isFile)
            val xml = resource.readText()
            required.forEach { name ->
                assertTrue("$directory missing $name", xml.contains("""name="$name""""))
            }
        }
        val config = File(appDir, "src/main/res/xml/locales_config.xml").readText()
        assertEquals(13, """<locale android:name=""".toRegex().findAll(config).count())
    }

    private val appDir: File by lazy {
        val working = File(requireNotNull(System.getProperty("user.dir")))
        sequenceOf(
            File(working, "app"),
            working,
            File(working, "clients/android/app"),
        ).first { File(it, "src/main/AndroidManifest.xml").isFile }
    }
}
