package com.ratelmesh.android.doctor

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import com.ratelmesh.android.service.IMeshCoreService
import com.ratelmesh.android.service.MeshCoreService
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

internal fun boundedDiagnosticID(value: String, maximum: Int): String {
    require(value.isNotBlank() && value.length <= maximum)
    require(value.all { it.isLetterOrDigit() || it == '-' || it == '_' || it == '.' })
    return value
}

/**
 * Adapts the private-process gomobile API to the deliberately smaller Android
 * presentation contract. The Go API remains authoritative for plan IDs,
 * executable actions, expiry, confirmation, execution and rollback status.
 */
class MobileNetworkDoctorGateway(context: Context) : NetworkDoctorGateway {
    private val application = context.applicationContext
    private val lock = Any()
    private var cachedReportID = ""
    private var cachedPlanID = ""
    private var cachedActions = emptyList<String>()
    private var cachedPlanJSON = ""

    override suspend fun diagnoseJSON(
        onProgress: (step: Int, total: Int, check: String) -> Unit,
    ): String = guarded {
        onProgress(0, NetworkDoctorChecks.size, "preparing")
        val raw = withCore { core ->
            val disclosure = core.doctorDisclosureVersion()
            require(disclosure == "v1")
            core.runNetworkDoctor(disclosure, true)
        }
        require(raw.isNotBlank() && raw.length <= 1_048_576)
        val envelope = JSONObject(raw)
        require(envelope.optString("schema") == "ratelmesh.doctor.api/v1")
        val report = envelope.getJSONObject("report")
        val plan = envelope.getJSONObject("plan")
        require(report.optString("schema") == "ratelmesh.diagnose.report/v2")
        require(plan.optString("schema") == "ratelmesh.diagnose.repair-plan/v1")
        require(plan.optBoolean("dry_run"))

        val allowed = stringSet(envelope.optJSONArray("availableRepairs"), 32)
        val reportID = UUID.randomUUID().toString()
        val actions = transformActions(plan.optJSONArray("repairs"), allowed)
        val planID = doctorPlanID(envelope, actions.length())
        val planJSON = if (actions.length() == 1) {
            JSONObject()
                .put("schema", 1)
                .put("id", planID)
                .put("reportID", reportID)
                .put("actions", actions)
                .toString()
        } else {
            ""
        }

        val findings = transformFindings(report.optJSONArray("findings"))
        val summary = report.optJSONObject("summary") ?: JSONObject()
        val total = summary.optInt("total_findings").coerceIn(0, 10_000)
        val worst = boundedText(summary.optString("worst_severity"), 32)
        val share = JSONObject()
            .put("schema", "ratelmesh.diagnose.report/v2")
            .put("summary", summary)
            .put("findings", findings)
            .toString(2)
        require(share.length <= 64 * 1024)
        val presentation = JSONObject()
            .put("schema", 1)
            .put("redacted", true)
            .put("id", reportID)
            .put("summary", "$total · ${worst.uppercase()}")
            .put("shareText", share)
            .put("findings", findings)
            .put("repairsAvailable", actions.length() > 0)
            .toString()

        synchronized(lock) {
            cachedReportID = reportID
            cachedPlanID = planID
            cachedActions = buildList {
                for (index in 0 until actions.length()) {
                    add(actions.getJSONObject(index).getString("id"))
                }
            }
            cachedPlanJSON = planJSON
        }
        onProgress(NetworkDoctorChecks.size, NetworkDoctorChecks.size, "complete")
        presentation
    }

    override suspend fun prepareRepairJSON(reportID: String): String = guarded {
        synchronized(lock) {
            require(reportID == cachedReportID && cachedPlanJSON.isNotBlank())
            cachedPlanJSON
        }
    }

    override suspend fun applyRepairJSON(planID: String): String = guarded {
        val action = synchronized(lock) {
            require(planID == cachedPlanID)
            cachedActions.single()
        }
        val raw = withCore { core ->
            val disclosure = core.doctorDisclosureVersion()
            require(disclosure == "v1")
            core.applyNetworkDoctorRepair(planID, action, disclosure, true)
        }
        require(raw.isNotBlank() && raw.length <= 1_048_576)
        val envelope = JSONObject(raw)
        require(envelope.optString("schema") == "ratelmesh.doctor.execution/v1")
        val execution = envelope.getJSONObject("execution")
        require(execution.optString("schema") == "ratelmesh.diagnose.repair-execution/v1")
        val repairs = execution.optJSONArray("repairs") ?: JSONArray()
        require(repairs.length() == 1)
        val status = boundedID(repairs.getJSONObject(0).getString("status"), 64)
        synchronized(lock) {
            cachedReportID = ""
            cachedPlanID = ""
            cachedActions = emptyList()
            cachedPlanJSON = ""
        }
        JSONObject()
            .put("schema", 1)
            .put("summary", status)
            .put("rollbackToken", "")
            .toString()
    }

    override suspend fun rollbackJSON(rollbackToken: String): String =
        throw NetworkDoctorUnavailableException()

    private fun transformFindings(source: JSONArray?): JSONArray {
        val out = JSONArray()
        val input = source ?: return out
        require(input.length() <= 256)
        for (index in 0 until minOf(input.length(), 64)) {
            val finding = input.getJSONObject(index)
            val severity = when (finding.optString("severity").lowercase()) {
                "critical", "error" -> "CRITICAL"
                "warning", "warn" -> "WARNING"
                "info" -> "INFO"
                "ok", "pass" -> "OK"
                else -> throw NetworkDoctorUnavailableException()
            }
            out.put(
                JSONObject()
                    .put("code", boundedDiagnosticID(finding.getString("code"), 128))
                    .put("severity", severity)
                    .put("title", boundedText(finding.optString("summary"), 200))
                    .put("detail", boundedDiagnosticID(finding.optString("probe"), 128)),
            )
        }
        return out
    }

    private fun transformActions(source: JSONArray?, allowed: Set<String>): JSONArray {
        val out = JSONArray()
        val input = source ?: return out
        require(input.length() <= 64)
        for (index in 0 until input.length()) {
            val repair = input.getJSONObject(index)
            val action = boundedID(repair.getString("action"), 64)
            if (!repair.optBoolean("applicable") || action !in allowed) continue
            out.put(
                JSONObject()
                    .put("id", action)
                    .put("title", boundedText(repair.optString("title"), 200))
                    .put("detail", action)
                    .put("reversible", (repair.optJSONArray("rollback")?.length() ?: 0) > 0),
            )
            // A daemon repair plan is one-use. Expose only the first safe action
            // so the UI never implies it can apply several actions with one ID.
            break
        }
        require(out.length() in 0..1)
        return out
    }

    private suspend fun <T> withCore(block: (IMeshCoreService) -> T): T =
        withContext(Dispatchers.IO) {
            val bound = bindCore()
            try {
                block(bound.core)
            } finally {
                bound.release()
            }
        }

    private suspend fun bindCore(): BoundCore = suspendCancellableCoroutine { continuation ->
        val completed = AtomicBoolean(false)
        lateinit var connection: ServiceConnection
        lateinit var lease: ServiceBindingLease
        connection = object : ServiceConnection {
            private fun failBinding() {
                if (completed.compareAndSet(false, true) && continuation.isActive) {
                    continuation.resumeWithException(NetworkDoctorUnavailableException())
                }
                lease.release()
            }

            override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
                val core = IMeshCoreService.Stub.asInterface(binder)
                if (core == null) {
                    failBinding()
                    return
                }
                val bound = BoundCore(core, lease)
                if (completed.compareAndSet(false, true) && continuation.isActive) {
                    continuation.resume(bound)
                } else {
                    lease.release()
                }
            }

            override fun onServiceDisconnected(name: ComponentName?) {
                failBinding()
            }

            override fun onNullBinding(name: ComponentName?) = failBinding()

            override fun onBindingDied(name: ComponentName?) = failBinding()
        }
        lease = ServiceBindingLease(application, connection)
        continuation.invokeOnCancellation {
            completed.set(true)
            lease.release()
        }
        val accepted = try {
            application.bindService(
                Intent(application, MeshCoreService::class.java),
                connection,
                Context.BIND_AUTO_CREATE,
            )
        } catch (_: RuntimeException) {
            false
        }
        lease.recordBindResult(accepted)
        if (!accepted &&
            completed.compareAndSet(false, true) &&
            continuation.isActive
        ) {
            continuation.resumeWithException(NetworkDoctorUnavailableException())
        }
    }

    private fun stringSet(array: JSONArray?, maximum: Int): Set<String> {
        val input = array ?: return emptySet()
        require(input.length() <= maximum)
        return buildSet {
            for (index in 0 until input.length()) {
                add(boundedID(input.getString(index), 64))
            }
        }
    }

    private fun boundedID(value: String, maximum: Int): String {
        require(value.isNotBlank() && value.length <= maximum)
        require(value.all { it.isLetterOrDigit() || it == '-' || it == '_' })
        return value
    }

    private fun boundedText(value: String, maximum: Int): String {
        require(value.length <= maximum)
        return value
    }

    private suspend fun <T> guarded(block: suspend () -> T): T = try {
        block()
    } catch (cancelled: CancellationException) {
        throw cancelled
    } catch (_: NetworkDoctorUnavailableException) {
        throw NetworkDoctorUnavailableException()
    } catch (_: Throwable) {
        throw NetworkDoctorUnavailableException()
    }

    private data class BoundCore(
        val core: IMeshCoreService,
        private val lease: ServiceBindingLease,
    ) {
        fun release() = lease.release()
    }

    /**
     * Tracks the awkward bindService race where a callback or cancellation can
     * arrive before bindService itself returns. release() is idempotent and a
     * deferred release is honored as soon as a successful bind is known.
     */
    private class ServiceBindingLease(
        private val context: Context,
        private val connection: ServiceConnection,
    ) {
        private val lock = Any()
        private var bindResultKnown = false
        private var bound = false
        private var releaseRequested = false
        private var unbound = false

        fun recordBindResult(accepted: Boolean) {
            val shouldUnbind = synchronized(lock) {
                bindResultKnown = true
                bound = accepted
                takeUnbindLocked()
            }
            if (shouldUnbind) unbind()
        }

        fun release() {
            val shouldUnbind = synchronized(lock) {
                releaseRequested = true
                takeUnbindLocked()
            }
            if (shouldUnbind) unbind()
        }

        private fun takeUnbindLocked(): Boolean {
            if (!bindResultKnown || !bound || !releaseRequested || unbound) return false
            unbound = true
            return true
        }

        private fun unbind() {
            runCatching { context.unbindService(connection) }
        }
    }
}

internal fun doctorPlanID(envelope: JSONObject, actionCount: Int): String {
    require(actionCount in 0..1)
    val value = envelope.optString("planID")
    if (actionCount == 0 && value.isBlank()) return ""
    require(value.isNotBlank() && value.length <= 256)
    require(value.all { it.isLetterOrDigit() || it == '-' || it == '_' })
    return value
}
