package com.ratelmesh.android.doctor

import org.json.JSONArray
import org.json.JSONObject

enum class DoctorPhase {
    INTRO,
    RUNNING,
    REPORT,
    LOADING_PLAN,
    CONFIRM_REPAIR,
    REPAIRING,
    REPAIRED,
    ROLLING_BACK,
    ROLLED_BACK,
    ERROR,
}

enum class DoctorSeverity { OK, INFO, WARNING, CRITICAL }

data class DoctorFinding(
    val code: String,
    val severity: DoctorSeverity,
    val title: String,
    val detail: String,
)

data class DoctorReport(
    val id: String,
    val summary: String,
    val findings: List<DoctorFinding>,
    val shareText: String,
    val redacted: Boolean,
    val repairsAvailable: Boolean = false,
)

data class DoctorRepairAction(
    val id: String,
    val title: String,
    val detail: String,
    val reversible: Boolean,
)

data class DoctorRepairPlan(
    val id: String,
    val reportID: String,
    val actions: List<DoctorRepairAction>,
)

data class DoctorRepairReceipt(
    val summary: String,
    val rollbackToken: String,
)

data class NetworkDoctorUiState(
    val phase: DoctorPhase = DoctorPhase.INTRO,
    val progressStep: Int = 0,
    val progressTotal: Int = NetworkDoctorChecks.size,
    val progressLabel: String = "",
    val report: DoctorReport? = null,
    val plan: DoctorRepairPlan? = null,
    val receipt: DoctorRepairReceipt? = null,
    val errorCode: String = "",
)

val NetworkDoctorChecks = listOf(
    "coordinator",
    "relay",
    "exit",
    "wireguard",
    "mtu",
    "dns",
    "ip_routes",
    "media",
)

internal object NetworkDoctorStateCodec {
    private const val schema = 1

    fun encode(state: NetworkDoctorUiState): String = JSONObject().apply {
        put("schema", schema)
        put("phase", state.phase.name)
        put("progressStep", state.progressStep)
        put("progressTotal", state.progressTotal)
        put("progressLabel", state.progressLabel)
        put("errorCode", state.errorCode)
        state.report?.let { put("report", reportJSON(it)) }
        state.receipt?.let {
            put(
                "receipt",
                JSONObject()
                    .put("summary", it.summary)
                    .put("rollbackToken", it.rollbackToken),
            )
        }
    }.toString()

    fun decode(raw: String?): NetworkDoctorUiState {
        if (raw.isNullOrBlank()) return NetworkDoctorUiState()
        return runCatching {
            val root = JSONObject(raw)
            require(root.optInt("schema") == schema)
            val restoredPhase = DoctorPhase.valueOf(root.getString("phase"))
            val stablePhase = when (restoredPhase) {
                DoctorPhase.CONFIRM_REPAIR -> DoctorPhase.REPORT
                DoctorPhase.RUNNING,
                DoctorPhase.LOADING_PLAN,
                DoctorPhase.REPAIRING,
                DoctorPhase.ROLLING_BACK,
                -> DoctorPhase.ERROR
                else -> restoredPhase
            }
            NetworkDoctorUiState(
                phase = stablePhase,
                progressStep = root.optInt("progressStep").coerceAtLeast(0),
                progressTotal = root.optInt("progressTotal", NetworkDoctorChecks.size).coerceAtLeast(1),
                progressLabel = root.optString("progressLabel").take(64),
                // Backend plans are one-use and held only in the live service.
                // Process restoration must not surface a stale repair action.
                report = root.optJSONObject("report")?.let(::parseReport)
                    ?.copy(repairsAvailable = false),
                plan = null,
                receipt = root.optJSONObject("receipt")?.let {
                    DoctorRepairReceipt(
                        summary = it.optString("summary").take(500),
                        rollbackToken = it.optString("rollbackToken").take(512),
                    )
                },
                errorCode = if (stablePhase == DoctorPhase.ERROR && restoredPhase != DoctorPhase.ERROR) {
                    "interrupted"
                } else {
                    root.optString("errorCode").take(64)
                },
            )
        }.getOrElse { NetworkDoctorUiState(phase = DoctorPhase.ERROR, errorCode = "restore_failed") }
    }

    private fun reportJSON(report: DoctorReport) = JSONObject()
        .put("id", report.id)
        .put("summary", report.summary)
        .put("shareText", report.shareText)
        .put("redacted", report.redacted)
        .put("repairsAvailable", report.repairsAvailable)
        .put(
            "findings",
            JSONArray().apply {
                report.findings.forEach {
                    put(
                        JSONObject()
                            .put("code", it.code)
                            .put("severity", it.severity.name)
                            .put("title", it.title)
                            .put("detail", it.detail),
                    )
                }
            },
        )

    private fun parseReport(root: JSONObject): DoctorReport {
        require(root.optBoolean("redacted"))
        val findings = root.optJSONArray("findings") ?: JSONArray()
        return DoctorReport(
            id = root.getString("id").take(128),
            summary = root.optString("summary").take(1_000),
            findings = buildList {
                for (index in 0 until findings.length().coerceAtMost(64)) {
                    val item = findings.optJSONObject(index) ?: continue
                    add(
                        DoctorFinding(
                            code = item.optString("code").take(128),
                            severity = DoctorSeverity.valueOf(item.optString("severity")),
                            title = item.optString("title").take(200),
                            detail = item.optString("detail").take(1_000),
                        ),
                    )
                }
            },
            shareText = root.optString("shareText").take(64 * 1024),
            redacted = true,
            repairsAvailable = root.optBoolean("repairsAvailable"),
        )
    }

}
