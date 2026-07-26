package com.ratelmesh.android.doctor

import android.content.Context
import android.content.Intent
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.progressBarRangeInfo
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.ratelmesh.android.R

@Composable
fun NetworkDoctorRoute(onClose: () -> Unit) {
    val doctor: NetworkDoctorViewModel = viewModel(
        factory = NetworkDoctorViewModel.factory(NetworkDoctorGatewayProvider.factory()),
    )
    val state by doctor.state.collectAsState()
    NetworkDoctorScreen(
        state = state,
        onClose = onClose,
        onStart = doctor::startDiagnosis,
        onPlan = doctor::requestRepairPlan,
        onCancelRepair = doctor::cancelRepair,
        onConfirmRepair = doctor::confirmRepair,
        onRollback = doctor::rollback,
        onRetry = doctor::retry,
        onReset = doctor::reset,
    )
}

@Composable
private fun NetworkDoctorScreen(
    state: NetworkDoctorUiState,
    onClose: () -> Unit,
    onStart: () -> Unit,
    onPlan: () -> Unit,
    onCancelRepair: () -> Unit,
    onConfirmRepair: () -> Unit,
    onRollback: () -> Unit,
    onRetry: () -> Unit,
    onReset: () -> Unit,
) {
    BackHandler(
        enabled = state.phase !in setOf(
            DoctorPhase.RUNNING,
            DoctorPhase.LOADING_PLAN,
            DoctorPhase.REPAIRING,
            DoctorPhase.ROLLING_BACK,
        ),
        onBack = onClose,
    )
    val context = LocalContext.current
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(
                stringResource(R.string.doctor_title),
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Black,
                modifier = Modifier.semantics { heading() },
            )
            TextButton(onClick = onClose) { Text(stringResource(R.string.doctor_close)) }
        }
        Text(
            stringResource(R.string.doctor_privacy_note),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        when (state.phase) {
            DoctorPhase.INTRO -> DoctorIntro(onStart)
            DoctorPhase.RUNNING -> DoctorProgress(state)
            DoctorPhase.REPORT -> DoctorReportView(state, onPlan, onReset, context)
            DoctorPhase.LOADING_PLAN -> BusyMessage(R.string.doctor_preparing_plan)
            DoctorPhase.CONFIRM_REPAIR -> {
                DoctorReportView(state, onPlan = {}, onReset = onReset, context = context, showActions = false)
                state.plan?.let { plan ->
                    RepairConfirmationDialog(plan, onCancelRepair, onConfirmRepair)
                }
            }
            DoctorPhase.REPAIRING -> BusyMessage(R.string.doctor_applying)
            DoctorPhase.REPAIRED -> RepairResult(
                state = state,
                title = R.string.doctor_repair_complete,
                onRollback = onRollback,
                onReset = onReset,
            )
            DoctorPhase.ROLLING_BACK -> BusyMessage(R.string.doctor_rolling_back)
            DoctorPhase.ROLLED_BACK -> RepairResult(
                state = state,
                title = R.string.doctor_rollback_complete,
                onRollback = null,
                onReset = onReset,
            )
            DoctorPhase.ERROR -> DoctorError(state.errorCode, onRetry, onReset)
        }
    }
}

@Composable
private fun DoctorIntro(onStart: () -> Unit) {
    DoctorCard {
        Text(stringResource(R.string.doctor_intro), style = MaterialTheme.typography.bodyLarge)
        Text(stringResource(R.string.doctor_checks), color = MaterialTheme.colorScheme.onSurfaceVariant)
        Button(onClick = onStart, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.doctor_start), fontWeight = FontWeight.Bold)
        }
    }
}

@Composable
private fun DoctorProgress(state: NetworkDoctorUiState) {
    val total = state.progressTotal.coerceAtLeast(1)
    val step = state.progressStep.coerceIn(0, total)
    val description = stringResource(R.string.doctor_progress_accessibility, step, total)
    DoctorCard(
        modifier = Modifier.semantics {
            liveRegion = LiveRegionMode.Polite
            progressBarRangeInfo = ProgressBarRangeInfo(
                step.toFloat(),
                0f..total.toFloat(),
                (total - 1).coerceAtLeast(0),
            )
        },
    ) {
        Text(stringResource(R.string.doctor_running), fontWeight = FontWeight.Bold)
        LinearProgressIndicator(
            progress = { step.toFloat() / total },
            modifier = Modifier.fillMaxWidth(),
        )
        Text(description)
        Text(
            doctorCheckLabel(state.progressLabel),
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(stringResource(R.string.doctor_do_not_close), style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun DoctorReportView(
    state: NetworkDoctorUiState,
    onPlan: () -> Unit,
    onReset: () -> Unit,
    context: Context,
    showActions: Boolean = true,
) {
    val report = state.report ?: return
    Text(
        stringResource(R.string.doctor_report_title),
        style = MaterialTheme.typography.titleLarge,
        fontWeight = FontWeight.Bold,
        modifier = Modifier.semantics { heading() },
    )
    DoctorCard {
        Text(report.summary)
        HorizontalDivider()
        report.findings.forEach { finding ->
            Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Text(
                    "${severityLabel(finding.severity)} · ${finding.title}",
                    fontWeight = FontWeight.SemiBold,
                )
                if (finding.detail.isNotBlank()) {
                    Text(
                        finding.detail,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
    Text(
        stringResource(R.string.doctor_report_redacted),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    if (showActions) {
        if (report.repairsAvailable) {
            Button(onClick = onPlan, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.doctor_review_repairs))
            }
        }
        OutlinedButton(
            onClick = { shareDoctorReport(context, report.shareText) },
            enabled = report.redacted && report.shareText.isNotBlank(),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(stringResource(R.string.doctor_share_report))
        }
        TextButton(onClick = onReset, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.doctor_run_again))
        }
    }
}

@Composable
private fun RepairConfirmationDialog(
    plan: DoctorRepairPlan,
    onCancel: () -> Unit,
    onConfirm: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text(stringResource(R.string.doctor_confirm_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(stringResource(R.string.doctor_confirm_body))
                plan.actions.forEach { action ->
                    Column {
                        Text(action.title, fontWeight = FontWeight.SemiBold)
                        Text(action.detail, style = MaterialTheme.typography.bodySmall)
                        Text(
                            stringResource(
                                if (action.reversible) {
                                    R.string.doctor_action_reversible
                                } else {
                                    R.string.doctor_action_not_reversible
                                },
                            ),
                            style = MaterialTheme.typography.labelSmall,
                        )
                    }
                }
            }
        },
        confirmButton = {
            Button(onClick = onConfirm) { Text(stringResource(R.string.doctor_confirm_apply)) }
        },
        dismissButton = {
            TextButton(onClick = onCancel) { Text(stringResource(R.string.doctor_cancel)) }
        },
    )
}

@Composable
private fun RepairResult(
    state: NetworkDoctorUiState,
    title: Int,
    onRollback: (() -> Unit)?,
    onReset: () -> Unit,
) {
    DoctorCard(
        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
    ) {
        Text(stringResource(title), style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
        state.receipt?.summary?.takeIf { it.isNotBlank() }?.let { Text(it) }
        if (onRollback != null && !state.receipt?.rollbackToken.isNullOrBlank()) {
            OutlinedButton(onClick = onRollback, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.doctor_rollback))
            }
        }
        Button(onClick = onReset, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.doctor_done))
        }
    }
}

@Composable
private fun DoctorError(errorCode: String, onRetry: () -> Unit, onReset: () -> Unit) {
    val message = when (errorCode) {
        "unavailable" -> R.string.doctor_error_unavailable
        "interrupted", "restore_failed" -> R.string.doctor_error_interrupted
        "rollback_failed" -> R.string.doctor_error_rollback
        else -> R.string.doctor_error_generic
    }
    DoctorCard(modifier = Modifier.semantics { liveRegion = LiveRegionMode.Assertive }) {
        Text(stringResource(R.string.doctor_error_title), fontWeight = FontWeight.Bold)
        Text(stringResource(message))
        Button(onClick = onRetry, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.doctor_retry))
        }
        TextButton(onClick = onReset, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.doctor_back_to_start))
        }
    }
}

@Composable
private fun BusyMessage(label: Int) {
    DoctorCard(
        modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
    ) {
        LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
        Text(stringResource(label), fontWeight = FontWeight.Bold)
    }
}

@Composable
private fun DoctorCard(
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            content()
        }
    }
}

@Composable
private fun doctorCheckLabel(check: String): String = stringResource(
    when (check) {
        "coordinator" -> R.string.doctor_check_coordinator
        "relay" -> R.string.doctor_check_relay
        "exit" -> R.string.doctor_check_exit
        "wireguard" -> R.string.doctor_check_wireguard
        "mtu" -> R.string.doctor_check_mtu
        "dns" -> R.string.doctor_check_dns
        "ip_routes" -> R.string.doctor_check_ip_routes
        "media" -> R.string.doctor_check_media
        else -> R.string.doctor_check_preparing
    },
)

@Composable
private fun severityLabel(severity: DoctorSeverity): String = stringResource(
    when (severity) {
        DoctorSeverity.OK -> R.string.doctor_severity_ok
        DoctorSeverity.INFO -> R.string.doctor_severity_info
        DoctorSeverity.WARNING -> R.string.doctor_severity_warning
        DoctorSeverity.CRITICAL -> R.string.doctor_severity_critical
    },
)

private fun shareDoctorReport(context: Context, report: String) {
    val safe = report
        .take(64 * 1024)
        .filter { it == '\n' || it == '\t' || it.code >= 0x20 }
    if (safe.isBlank()) return
    val send = Intent(Intent.ACTION_SEND)
        .setType("text/plain")
        .putExtra(Intent.EXTRA_SUBJECT, context.getString(R.string.doctor_share_subject))
        .putExtra(Intent.EXTRA_TEXT, safe)
    context.startActivity(
        Intent.createChooser(send, context.getString(R.string.doctor_share_chooser)),
    )
}
