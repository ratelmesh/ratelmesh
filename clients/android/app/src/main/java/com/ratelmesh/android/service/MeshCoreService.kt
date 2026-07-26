package com.ratelmesh.android.service

import android.app.Service
import android.content.Intent
import android.os.IBinder
import mobile.App as MobileApp
import mobile.Mobile

/**
 * Owns RatelMeshMobile in a private process.
 *
 * WireGuard's Android backend is also implemented in Go. Loading its runtime
 * together with gomobile's runtime in one process corrupts runtime state and
 * crashes shortly after the tunnel comes up. The manifest therefore runs this
 * service as :meshcore, while MeshVpnService and GoBackend stay in the main
 * process.
 */
class MeshCoreService : Service() {
    private val lock = Any()
    private var app: MobileApp? = null
    @Volatile private var errorMessage = ""

    private val binder = object : IMeshCoreService.Stub() {
        override fun startApp(
            coordinatorUrl: String,
            authKey: String,
            stateDirectory: String,
            hostname: String,
            listenPort: Int,
            endpointCandidatesJson: String,
        ): String = synchronized(lock) {
            stopLocked()
            try {
                val next = Mobile.newAppWithOptions(
                    meshCoreOptions(
                        coordinatorUrl,
                        authKey,
                        stateDirectory,
                        hostname,
                        listenPort,
                        endpointCandidatesJson,
                    ),
                )
                app = next
                next.start()
                errorMessage = ""
                ""
            } catch (error: Throwable) {
                stopLocked()
                message(error).also { errorMessage = it }
            }
        }

        override fun stopApp() = synchronized(lock) { stopLocked() }

        override fun tunnelConfigVersion(): Long = withApp(-1L) { it.tunnelConfigVersion() }

        override fun tunnelConfigJSON(): String = withApp("") { it.tunnelConfigJSON() }

        override fun statusJSON(): String = withApp("") { it.statusJSON() }

        override fun publicKey(): String = withApp("") { it.publicKey() }

        override fun lastError(): String = errorMessage

        override fun updatePeerStatsJSON(payload: String) {
            withApp(Unit) { it.updatePeerStatsJSON(payload) }
        }

        override fun useExit(name: String): String = command { it.useExit(name) }

        override fun clearExit(): String = command { it.clearExit() }

		override fun setSystemLocation(latitude: Double, longitude: Double): String =
			command { it.setSystemLocation(latitude, longitude) }

        override fun doctorDisclosureVersion(): String =
            withApp("") { it.doctorDisclosureVersion() }

        override fun runNetworkDoctor(disclosureVersion: String, confirmed: Boolean): String =
            withApp("") { it.runNetworkDoctor(disclosureVersion, confirmed) }

        override fun applyNetworkDoctorRepair(
            planID: String,
            action: String,
            disclosureVersion: String,
            confirmed: Boolean,
        ): String = withApp("") {
            it.applyNetworkDoctorRepair(planID, action, disclosureVersion, confirmed)
        }
    }

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onDestroy() {
        synchronized(lock) { stopLocked() }
        super.onDestroy()
    }

    private fun stopLocked() {
        runCatching { app?.stop() }
        app = null
    }

    private fun command(block: (MobileApp) -> Unit): String = synchronized(lock) {
        val current = app ?: return@synchronized "mesh is not connected"
        try {
            block(current)
            errorMessage = ""
            ""
        } catch (error: Throwable) {
            message(error).also { errorMessage = it }
        }
    }

    private fun <T> withApp(fallback: T, block: (MobileApp) -> T): T = synchronized(lock) {
        val current = app ?: return@synchronized fallback
        try {
            block(current)
        } catch (error: Throwable) {
            errorMessage = message(error)
            fallback
        }
    }

    private fun message(error: Throwable): String = error.message ?: error.javaClass.simpleName
}
