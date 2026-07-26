package com.ratelmesh.android.doctor

import org.json.JSONArray
import org.json.JSONObject

/**
 * Android-side boundary for the gomobile Network Doctor API.
 *
 * JSON schema v1:
 * - diagnose -> {"schema":1,"redacted":true,"id","summary","shareText",
 *   "repairsAvailable","findings":[{"code","severity","title","detail"}]}
 * - prepareRepair -> {"schema":1,"id","reportID","actions":
 *   [{"id","title","detail","reversible"}]}
 * - applyRepair -> {"schema":1,"summary","rollbackToken"}
 * - rollback -> {"schema":1,"status":"rolled_back"}
 *
 * Raw snapshots, endpoint addresses, auth material and executor errors must
 * never cross this interface. IDs and rollbackToken are opaque. Implementations
 * map every backend failure to NetworkDoctorUnavailableException; raw error
 * text is neither returned nor logged by this UI layer.
 */
interface NetworkDoctorGateway {
    suspend fun diagnoseJSON(onProgress: (step: Int, total: Int, check: String) -> Unit): String
    suspend fun prepareRepairJSON(reportID: String): String
    suspend fun applyRepairJSON(planID: String): String
    suspend fun rollbackJSON(rollbackToken: String): String
}

class NetworkDoctorUnavailableException : Exception()

object NetworkDoctorGatewayProvider {
    @Volatile
    var factory: () -> NetworkDoctorGateway = {
        object : NetworkDoctorGateway {
            override suspend fun diagnoseJSON(
                onProgress: (step: Int, total: Int, check: String) -> Unit,
            ): String = throw NetworkDoctorUnavailableException()

            override suspend fun prepareRepairJSON(reportID: String): String =
                throw NetworkDoctorUnavailableException()

            override suspend fun applyRepairJSON(planID: String): String =
                throw NetworkDoctorUnavailableException()

            override suspend fun rollbackJSON(rollbackToken: String): String =
                throw NetworkDoctorUnavailableException()
        }
    }
}

internal fun parseDoctorReportJSON(raw: String): DoctorReport {
    require(raw.length <= 128 * 1024)
    val root = JSONObject(raw)
    requireOnlyKeys(root, setOf("schema", "redacted", "id", "summary", "shareText", "findings", "repairsAvailable"))
    require(root.optInt("schema") == 1 && root.optBoolean("redacted"))
    val findings = root.optJSONArray("findings") ?: JSONArray()
    require(findings.length() <= 64)
    return DoctorReport(
        id = boundedRequired(root, "id", 128),
        summary = bounded(root, "summary", 1_000),
        findings = buildList {
            for (index in 0 until findings.length()) {
                val item = findings.getJSONObject(index)
                requireOnlyKeys(item, setOf("code", "severity", "title", "detail"))
                add(
                    DoctorFinding(
                        code = boundedRequired(item, "code", 128),
                        severity = DoctorSeverity.valueOf(boundedRequired(item, "severity", 16)),
                        title = bounded(item, "title", 200),
                        detail = bounded(item, "detail", 1_000),
                    ),
                )
            }
        },
        shareText = bounded(root, "shareText", 64 * 1024),
        redacted = true,
        repairsAvailable = root.optBoolean("repairsAvailable"),
    )
}

internal fun parseDoctorRepairPlanJSON(raw: String, expectedReportID: String): DoctorRepairPlan {
    require(raw.length <= 64 * 1024)
    val root = JSONObject(raw)
    requireOnlyKeys(root, setOf("schema", "id", "reportID", "actions"))
    require(root.optInt("schema") == 1)
    val actions = root.getJSONArray("actions")
    require(actions.length() == 1)
    val reportID = boundedRequired(root, "reportID", 128)
    require(reportID == expectedReportID)
    return DoctorRepairPlan(
        id = boundedRequired(root, "id", 128),
        reportID = reportID,
        actions = buildList {
            for (index in 0 until actions.length()) {
                val item = actions.getJSONObject(index)
                requireOnlyKeys(item, setOf("id", "title", "detail", "reversible"))
                add(
                    DoctorRepairAction(
                        id = boundedRequired(item, "id", 128),
                        title = bounded(item, "title", 200),
                        detail = bounded(item, "detail", 1_000),
                        reversible = item.optBoolean("reversible"),
                    ),
                )
            }
        },
    )
}

internal fun parseDoctorRepairReceiptJSON(raw: String): DoctorRepairReceipt {
    require(raw.length <= 4 * 1024)
    val root = JSONObject(raw)
    requireOnlyKeys(root, setOf("schema", "summary", "rollbackToken"))
    require(root.optInt("schema") == 1)
    return DoctorRepairReceipt(
        summary = bounded(root, "summary", 500),
        rollbackToken = bounded(root, "rollbackToken", 512),
    )
}

internal fun requireDoctorRollbackJSON(raw: String) {
    require(raw.length <= 1_024)
    val root = JSONObject(raw)
    requireOnlyKeys(root, setOf("schema", "status"))
    require(root.optInt("schema") == 1 && root.optString("status") == "rolled_back")
}

private fun bounded(root: JSONObject, key: String, max: Int): String =
    root.optString(key).also { require(it.length <= max) }

private fun boundedRequired(root: JSONObject, key: String, max: Int): String =
    bounded(root, key, max).also { require(it.isNotBlank()) }

private fun requireOnlyKeys(root: JSONObject, allowed: Set<String>) {
    val keys = root.keys()
    while (keys.hasNext()) {
        require(keys.next() in allowed)
    }
}
