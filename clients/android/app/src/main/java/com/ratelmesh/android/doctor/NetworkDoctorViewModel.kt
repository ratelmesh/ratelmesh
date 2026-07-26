package com.ratelmesh.android.doctor

import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.createSavedStateHandle
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class NetworkDoctorViewModel(
    private val savedStateHandle: SavedStateHandle,
    private val gateway: NetworkDoctorGateway,
) : ViewModel() {
    private val mutableState = MutableStateFlow(
        NetworkDoctorStateCodec.decode(savedStateHandle[STATE_KEY]),
    )
    val state = mutableState.asStateFlow()

    fun startDiagnosis() = runExclusive(DoctorPhase.RUNNING) {
        update(
            NetworkDoctorUiState(
                phase = DoctorPhase.RUNNING,
                progressTotal = NetworkDoctorChecks.size,
            ),
        )
        val report = parseDoctorReportJSON(
            gateway.diagnoseJSON { step, total, check ->
                update(
                    mutableState.value.copy(
                        progressStep = step.coerceIn(0, total.coerceAtLeast(1)),
                        progressTotal = total.coerceAtLeast(1),
                        progressLabel = check.take(64),
                    ),
                )
            },
        )
        update(NetworkDoctorUiState(phase = DoctorPhase.REPORT, report = report))
    }

    fun requestRepairPlan() {
        val report = mutableState.value.report ?: return
        if (!report.repairsAvailable) return
        runExclusive(DoctorPhase.LOADING_PLAN) {
            update(mutableState.value.copy(phase = DoctorPhase.LOADING_PLAN, errorCode = ""))
            val plan = parseDoctorRepairPlanJSON(gateway.prepareRepairJSON(report.id), report.id)
            update(mutableState.value.copy(phase = DoctorPhase.CONFIRM_REPAIR, plan = plan))
        }
    }

    fun cancelRepair() {
        if (mutableState.value.phase == DoctorPhase.CONFIRM_REPAIR) {
            update(mutableState.value.copy(phase = DoctorPhase.REPORT, plan = null))
        }
    }

    fun confirmRepair() {
        val plan = mutableState.value.plan ?: return
        if (mutableState.value.phase != DoctorPhase.CONFIRM_REPAIR) return
        runExclusive(DoctorPhase.REPAIRING) {
            update(mutableState.value.copy(phase = DoctorPhase.REPAIRING, errorCode = ""))
            val receipt = parseDoctorRepairReceiptJSON(gateway.applyRepairJSON(plan.id))
            update(mutableState.value.copy(phase = DoctorPhase.REPAIRED, receipt = receipt))
        }
    }

    fun rollback() {
        val token = mutableState.value.receipt?.rollbackToken.orEmpty()
        if (token.isBlank() || mutableState.value.phase != DoctorPhase.REPAIRED) return
        runExclusive(DoctorPhase.ROLLING_BACK) {
            update(mutableState.value.copy(phase = DoctorPhase.ROLLING_BACK, errorCode = ""))
            requireDoctorRollbackJSON(gateway.rollbackJSON(token))
            update(mutableState.value.copy(phase = DoctorPhase.ROLLED_BACK))
        }
    }

    fun retry() {
        update(NetworkDoctorUiState())
        startDiagnosis()
    }

    fun reset() = update(NetworkDoctorUiState())

    private fun runExclusive(transitionalPhase: DoctorPhase, block: suspend () -> Unit) {
        if (mutableState.value.phase in setOf(
                DoctorPhase.RUNNING,
                DoctorPhase.LOADING_PLAN,
                DoctorPhase.REPAIRING,
                DoctorPhase.ROLLING_BACK,
            )
        ) {
            return
        }
        // Move into the transitional state before scheduling the coroutine.
        // Two taps in the same UI frame must never queue two diagnoses, repairs
        // or rollbacks before the first coroutine gets CPU time.
        update(mutableState.value.copy(phase = transitionalPhase, errorCode = ""))
        viewModelScope.launch {
            try {
                block()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: NetworkDoctorUnavailableException) {
                update(mutableState.value.copy(phase = DoctorPhase.ERROR, errorCode = "unavailable"))
            } catch (_: Throwable) {
                val code = when (transitionalPhase) {
                    DoctorPhase.RUNNING -> "diagnosis_failed"
                    DoctorPhase.LOADING_PLAN -> "plan_failed"
                    DoctorPhase.REPAIRING -> "repair_failed"
                    DoctorPhase.ROLLING_BACK -> "rollback_failed"
                    else -> "unknown"
                }
                update(mutableState.value.copy(phase = DoctorPhase.ERROR, errorCode = code))
            }
        }
    }

    private fun update(next: NetworkDoctorUiState) {
        mutableState.value = next
        savedStateHandle[STATE_KEY] = NetworkDoctorStateCodec.encode(next)
    }

    companion object {
        private const val STATE_KEY = "network_doctor_state_v1"

        fun factory(gateway: NetworkDoctorGateway): ViewModelProvider.Factory = viewModelFactory {
            initializer {
                NetworkDoctorViewModel(createSavedStateHandle(), gateway)
            }
        }
    }
}
