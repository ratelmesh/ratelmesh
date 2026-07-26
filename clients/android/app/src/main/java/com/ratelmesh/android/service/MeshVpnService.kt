package com.ratelmesh.android.service

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.location.LocationManager
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.ratelmesh.android.AppLanguagePreferences
import com.ratelmesh.android.MainActivity
import com.ratelmesh.android.R
import com.ratelmesh.android.data.SecureSettings
import com.ratelmesh.android.data.VpnDisclosureConsent
import com.ratelmesh.android.model.ConnectionPhase
import com.ratelmesh.android.model.MeshState
import com.ratelmesh.android.model.parseStatus
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import java.io.BufferedReader
import java.io.File
import java.io.StringReader
import org.json.JSONArray
import org.json.JSONObject
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

class MeshVpnService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val lifecycleMutex = Mutex()
    private lateinit var backend: GoBackend
    private var coreService: IMeshCoreService? = null
    private var coreConnection: ServiceConnection? = null
    private var pollJob: Job? = null
    private var appliedVersion = -1L
    private var appliedConfigJson: String? = null
    @Volatile private var tunnelUp = false
    @Volatile private var backendMutation = false
    private val systemTeardownScheduled = AtomicBoolean()

    private val tunnel = object : Tunnel {
        override fun getName(): String = TUNNEL_NAME

        override fun onStateChange(newState: Tunnel.State) {
            tunnelUp = newState == Tunnel.State.UP
            if (newState == Tunnel.State.DOWN && coreService != null && !backendMutation) {
                MeshRuntime.update { current ->
                    if (current.phase == ConnectionPhase.DISCONNECTING) current
                    else current.copy(
                        phase = ConnectionPhase.ERROR,
                        error = getString(R.string.error_android_closed_vpn),
                    )
                }
                if (systemTeardownScheduled.compareAndSet(false, true)) {
                    scope.launch { stopAfterSystemTunnelDown() }
                }
            }
        }
    }

    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(AppLanguagePreferences.localizedContext(newBase))
    }

    override fun onCreate() {
        super.onCreate()
        backend = GoBackend(applicationContext)
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action != ACTION_STOP && !VpnDisclosureConsent.isAccepted(this)) {
            stopSelf(startId)
            return START_NOT_STICKY
        }
        when (intent?.action) {
            ACTION_STOP -> scope.launch { stopSession() }
            ACTION_USE_EXIT -> scope.launch { selectExit(intent.getStringExtra(EXTRA_EXIT).orEmpty()) }
            ACTION_CLEAR_EXIT -> scope.launch { clearExit() }
            ACTION_REFRESH_LANGUAGE -> {
                createNotificationChannel()
                updateNotification()
            }
            else -> {
                startForeground(NOTIFICATION_ID, notification(connecting = true))
                scope.launch { startSession() }
            }
        }
        return START_NOT_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        // Normal disconnect calls stopSession first. This also covers process/service
        // teardown so GoBackend's separate VpnService is not left carrying traffic.
        val job = pollJob
        pollJob = null
        job?.cancel()
        runBlocking {
            withTimeoutOrNull(ON_DESTROY_JOIN_TIMEOUT_MS) { job?.join() }
        }
        if (::backend.isInitialized) runCatching { setBackendState(Tunnel.State.DOWN, null) }
        runCatching { coreService?.stopApp() }
        releaseCoreService()
        MeshRuntime.update { current ->
            withoutLiveSession(
                current,
                phase = if (current.phase == ConnectionPhase.ERROR) current.phase else ConnectionPhase.DISCONNECTED,
                error = if (current.phase == ConnectionPhase.ERROR) current.error else null,
            )
        }
        scope.cancel()
        super.onDestroy()
    }

    private suspend fun startSession() = lifecycleMutex.withLock {
        if (coreService != null) return
        MeshRuntime.update { it.copy(phase = ConnectionPhase.CONNECTING, error = null) }

        try {
            resetIdentityIfPending()
            val settings = SecureSettings(applicationContext).load()
            require(settings.coordinatorUrl.isNotBlank()) { getString(R.string.error_coordinator_required) }
            require(settings.hostname.isNotBlank()) { getString(R.string.error_device_required) }
            val stateDirectory = File(noBackupFilesDir, "mesh-state").apply {
                check(mkdirs() || isDirectory) { getString(R.string.error_state_directory) }
            }
            val core = bindCoreService()
            val listenPort = MeshListenPort.getOrCreate(applicationContext)
            val endpointCandidates = JSONArray().apply {
                StunEndpointDiscovery.discover(applicationContext, listenPort)?.let(::put)
            }.toString()
            val startError = core.startApp(
                settings.coordinatorUrl,
                settings.authKey,
                stateDirectory.absolutePath,
                settings.hostname,
                listenPort,
                endpointCandidates,
            )
            check(startError.isBlank()) { startError }
			reportAuthorizedSystemLocation(core)
            MeshRuntime.update { it.copy(publicKey = core.publicKey()) }
            pollJob = scope.launch { poll(core) }
        } catch (_: Throwable) {
            fail()
        }
    }

	private fun reportAuthorizedSystemLocation(core: IMeshCoreService) {
		if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_COARSE_LOCATION) != PackageManager.PERMISSION_GRANTED) return
		val manager = getSystemService(LocationManager::class.java) ?: return
		val location = manager.getProviders(true)
			.mapNotNull { provider -> runCatching { manager.getLastKnownLocation(provider) }.getOrNull() }
			.maxByOrNull { it.time }
			?: return
		core.setSystemLocation(location.latitude, location.longitude)
	}

    private suspend fun poll(core: IMeshCoreService) {
        try {
            while (true) {
                val nextState = try {
                    parseStatus(core.statusJSON(), MeshRuntime.state.value)
                } catch (_: Exception) {
                    MeshRuntime.state.value
                }
                val version = core.tunnelConfigVersion()
                if (version > 0 && version != appliedVersion) {
                    val configJson = core.tunnelConfigJSON()
                    if (TunnelConfigParser.isReady(configJson)) {
                        if (TunnelConfigParser.shouldApplyRefresh(
                                appliedConfigJson,
                                configJson,
                                nextState.selectedExit,
                                nextState.exitTrafficVerified,
                            )
                        ) {
                            val quickConfig = TunnelConfigParser.toWgQuick(configJson, packageName)
                            val config = Config.parse(BufferedReader(StringReader(quickConfig)))
                            setBackendState(Tunnel.State.UP, config)
                            appliedVersion = version
                            appliedConfigJson = configJson
                            updateNotification()
                        }
                    } else if (!TunnelConfigParser.isActive(configJson) && appliedVersion >= 0) {
                        setBackendState(Tunnel.State.DOWN, null)
                        appliedVersion = version
                        appliedConfigJson = null
                    }
                }
                MeshRuntime.update { current ->
                    nextState.copy(
                        phase = if (tunnelUp) ConnectionPhase.CONNECTED else current.phase,
                        error = if (tunnelUp) null else current.error,
                    )
                }
                // Statistics are advisory. A transient backend read must not tear down the VPN.
                runCatching { updatePeerHealth(core) }
                delay(POLL_INTERVAL_MS)
            }
        } catch (cancelled: kotlinx.coroutines.CancellationException) {
            throw cancelled
        } catch (_: Throwable) {
            lifecycleMutex.withLock { fail() }
        }
    }

    private fun updatePeerHealth(core: IMeshCoreService) {
        if (!tunnelUp) return
        val statistics = backend.getStatistics(tunnel)
        val peers = JSONArray()
        for (key in statistics.peers()) {
            val peer = statistics.peer(key) ?: continue
            peers.put(
                JSONObject()
                    .put("publicKey", key.toBase64())
                    .put("latestHandshakeUnix", peer.latestHandshakeEpochMillis() / 1_000L)
                    .put("rxBytes", peer.rxBytes()),
            )
        }
        core.updatePeerStatsJSON(peers.toString())
    }

    private fun resetIdentityIfPending() {
        val settings = SecureSettings(applicationContext)
        val reset = settings.resetIdentityIfPending {
            runCatching { setBackendState(Tunnel.State.DOWN, null) }.getOrThrow()
            val stateDirectory = File(noBackupFilesDir, "mesh-state")
            check(!stateDirectory.exists() || stateDirectory.deleteRecursively()) {
                getString(R.string.error_state_directory)
            }
        }
        if (!reset) return
        MeshRuntime.update { current ->
            current.copy(enrollmentRequired = false)
        }
    }

    private fun setBackendState(state: Tunnel.State, config: Config?) {
        backendMutation = true
        try {
            backend.setState(tunnel, state, config)
            tunnelUp = state == Tunnel.State.UP
        } finally {
            backendMutation = false
        }
    }

    private suspend fun stopSession() {
        val job = lifecycleMutex.withLock {
            MeshRuntime.update { it.copy(phase = ConnectionPhase.DISCONNECTING, error = null) }
            pollJob.also {
                pollJob = null
                it?.cancel()
            }
        }
        job?.join()
        lifecycleMutex.withLock {
            runCatching { setBackendState(Tunnel.State.DOWN, null) }
            runCatching { coreService?.stopApp() }
            releaseCoreService()
            appliedVersion = -1
            appliedConfigJson = null
            tunnelUp = false
            MeshRuntime.update {
                withoutLiveSession(it, phase = ConnectionPhase.DISCONNECTED, error = null)
            }
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private suspend fun stopAfterSystemTunnelDown() {
        val job = lifecycleMutex.withLock {
            pollJob.also {
                pollJob = null
                it?.cancel()
            }
        }
        job?.join()
        lifecycleMutex.withLock {
            runCatching { coreService?.stopApp() }
            releaseCoreService()
            appliedVersion = -1
            appliedConfigJson = null
            tunnelUp = false
            MeshRuntime.update {
                withoutLiveSession(
                    it,
                    phase = ConnectionPhase.ERROR,
                    error = getString(R.string.error_android_closed_vpn),
                )
            }
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private suspend fun selectExit(name: String) = lifecycleMutex.withLock {
        if (name.isBlank()) return
        try {
            val error = checkNotNull(coreService) {
                getString(R.string.error_mesh_not_connected)
            }.useExit(name)
            check(error.isBlank()) { error }
            MeshRuntime.update { it.copy(error = null) }
        } catch (_: Throwable) {
            MeshRuntime.update { it.copy(error = getString(R.string.error_select_exit)) }
        }
    }

    private suspend fun clearExit() = lifecycleMutex.withLock {
        try {
            val error = checkNotNull(coreService) {
                getString(R.string.error_mesh_not_connected)
            }.clearExit()
            check(error.isBlank()) { error }
            MeshRuntime.update { it.copy(error = null) }
        } catch (_: Throwable) {
            MeshRuntime.update { it.copy(error = getString(R.string.error_clear_exit)) }
        }
    }

    private fun fail() {
        pollJob?.cancel()
        pollJob = null
        runCatching { setBackendState(Tunnel.State.DOWN, null) }
        runCatching { coreService?.stopApp() }
        releaseCoreService()
        appliedVersion = -1
        appliedConfigJson = null
        tunnelUp = false
        MeshRuntime.update {
            withoutLiveSession(
                it,
                phase = ConnectionPhase.ERROR,
                error = getString(R.string.error_connection_failed),
            )
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private suspend fun bindCoreService(): IMeshCoreService {
        coreService?.let { return it }
        return suspendCancellableCoroutine { continuation ->
            val connection = object : ServiceConnection {
                override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
                    val service = IMeshCoreService.Stub.asInterface(binder)
                    coreService = service
                    if (continuation.isActive) continuation.resume(service)
                }

                override fun onServiceDisconnected(name: ComponentName?) {
                    coreService = null
                }

                override fun onBindingDied(name: ComponentName?) {
                    coreService = null
                }

                override fun onNullBinding(name: ComponentName?) {
                    if (continuation.isActive) {
                        continuation.resumeWithException(
                            IllegalStateException("mesh core service returned no binder"),
                        )
                    }
                }
            }
            coreConnection = connection
            val bound = bindService(
                Intent(this, MeshCoreService::class.java),
                connection,
                Context.BIND_AUTO_CREATE,
            )
            if (!bound && continuation.isActive) {
                coreConnection = null
                continuation.resumeWithException(IllegalStateException("cannot start mesh core service"))
            }
            continuation.invokeOnCancellation {
                if (coreConnection === connection) releaseCoreService()
            }
        }
    }

    private fun withoutLiveSession(
        current: MeshState,
        phase: ConnectionPhase,
        error: String?,
    ): MeshState = current.copy(
        phase = phase,
        publicKey = "",
        meshIp = "",
        activeExit = "",
        selectedExit = "",
        exitTrafficVerified = false,
        exitClients = emptyList(),
        peers = emptyList(),
        error = error,
        backendState = "",
        enrollmentRequired = current.enrollmentRequired,
    )

    private fun releaseCoreService() {
        val connection = coreConnection ?: return
        coreConnection = null
        coreService = null
        runCatching { unbindService(connection) }
    }

    private fun notification(connecting: Boolean): android.app.Notification {
        val localized = AppLanguagePreferences.localizedContext(this)
        return NotificationCompat.Builder(localized, CHANNEL_ID)
        .setSmallIcon(R.drawable.ic_notification)
        .setContentTitle(
            if (connecting) localized.getString(R.string.vpn_notification_connecting)
            else localized.getString(R.string.vpn_notification_title),
        )
        .setContentIntent(
            PendingIntent.getActivity(
                this,
                0,
                Intent(this, MainActivity::class.java),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            ),
        )
        .addAction(
            0,
            localized.getString(R.string.vpn_notification_stop),
            PendingIntent.getService(
                this,
                1,
                Intent(this, MeshVpnService::class.java).setAction(ACTION_STOP),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            ),
        )
        .setOngoing(true)
        .setOnlyAlertOnce(true)
        .setCategory(NotificationCompat.CATEGORY_SERVICE)
        .build()
    }

    private fun updateNotification() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) return
        NotificationManagerCompat.from(this).notify(NOTIFICATION_ID, notification(connecting = !tunnelUp))
    }

    private fun createNotificationChannel() {
        val localized = AppLanguagePreferences.localizedContext(this)
        val channel = NotificationChannel(
            CHANNEL_ID,
            localized.getString(R.string.vpn_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ).apply { description = localized.getString(R.string.vpn_channel_description) }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    companion object {
        private const val ACTION_START = "com.ratelmesh.android.START"
        private const val ACTION_STOP = "com.ratelmesh.android.STOP"
        private const val ACTION_USE_EXIT = "com.ratelmesh.android.USE_EXIT"
        private const val ACTION_CLEAR_EXIT = "com.ratelmesh.android.CLEAR_EXIT"
        private const val ACTION_REFRESH_LANGUAGE = "com.ratelmesh.android.REFRESH_LANGUAGE"
        private const val EXTRA_EXIT = "exit"
        private const val CHANNEL_ID = "mesh-vpn"
        private const val NOTIFICATION_ID = 4401
        private const val TUNNEL_NAME = "ratelmesh"
        private const val POLL_INTERVAL_MS = 1_000L
        private const val ON_DESTROY_JOIN_TIMEOUT_MS = 1_000L

        fun start(context: Context) {
            if (!VpnDisclosureConsent.isAccepted(context)) return
            context.startForegroundService(
                Intent(context, MeshVpnService::class.java).setAction(ACTION_START),
            )
        }

        fun stop(context: Context) {
            context.startService(Intent(context, MeshVpnService::class.java).setAction(ACTION_STOP))
        }

        fun useExit(context: Context, name: String) {
            context.startService(
                Intent(context, MeshVpnService::class.java)
                    .setAction(ACTION_USE_EXIT)
                    .putExtra(EXTRA_EXIT, name),
            )
        }

        fun clearExit(context: Context) {
            context.startService(Intent(context, MeshVpnService::class.java).setAction(ACTION_CLEAR_EXIT))
        }

        fun refreshLanguage(context: Context) {
            if (MeshRuntime.state.value.phase == ConnectionPhase.DISCONNECTED) return
            context.startService(
                Intent(context, MeshVpnService::class.java).setAction(ACTION_REFRESH_LANGUAGE),
            )
        }
    }
}
