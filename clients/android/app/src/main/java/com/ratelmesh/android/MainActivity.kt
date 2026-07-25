package com.ratelmesh.android

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
	import androidx.core.content.ContextCompat
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.ratelmesh.android.data.ClientSettings
import com.ratelmesh.android.data.SecureSettings
import com.ratelmesh.android.data.VpnDisclosureConsent
import com.ratelmesh.android.model.ConnectionPhase
import com.ratelmesh.android.model.MeshState
import com.ratelmesh.android.service.MeshRuntime
import com.ratelmesh.android.service.MeshVpnService

class MainActivity : ComponentActivity() {
	private var afterLocationPermission: (() -> Unit)? = null
    private val vpnPermission = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            requestNotificationPermission()
            MeshVpnService.start(this)
        }
    }
    private val notificationPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { /* A denied notification permission does not revoke VPN permission. */ }
	private val locationPermission = registerForActivityResult(
		ActivityResultContracts.RequestPermission(),
	) {
		// Denial is expected: the coordinator falls back to public-IP location.
		afterLocationPermission?.invoke()
		afterLocationPermission = null
	}

    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(AppLanguagePreferences.localizedContext(newBase))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val secureSettings = SecureSettings(this)
        val privacyPreferences = getSharedPreferences("privacy", MODE_PRIVATE)
        val initial = secureSettings.load().let {
            if (it.hostname.isBlank()) {
                val generated = "android-${Build.MANUFACTURER}-${Build.MODEL}".lowercase()
                    .replace(Regex("[^a-z0-9-]"), "-")
                    .replace(Regex("-+"), "-")
                    .trim('-')
                    .take(63)
                    .trimEnd('-')
                    .ifBlank { "android-device" }
                it.copy(hostname = generated)
            } else it
        }

        setContent {
            var pendingConnection by remember { mutableStateOf<ClientSettings?>(null) }
            var showPrivacy by remember {
                mutableStateOf(!privacyPreferences.getBoolean("geographic_privacy_v1", false))
            }
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = Sand) {
                    MeshScreen(
                        initialSettings = initial,
                        selectedLanguage = AppLanguagePreferences.load(this),
                        onLanguage = { language ->
                            if (language != AppLanguagePreferences.load(this)) {
                                AppLanguagePreferences.save(this, language)
                                recreate()
                            }
                        },
                        onConnect = { settings ->
                            if (VpnDisclosureConsent.isAccepted(this)) connect(secureSettings, settings)
                            else pendingConnection = settings
                        },
                        onDisconnect = { MeshVpnService.stop(this) },
                        onUseExit = { MeshVpnService.useExit(this, it) },
                        onClearExit = { MeshVpnService.clearExit(this) },
                        onPrivacy = { showPrivacy = true },
                    )
                    pendingConnection?.let { settings ->
                        VpnDisclosureDialog(
                            onAccept = {
                                VpnDisclosureConsent.accept(this)
                                pendingConnection = null
                                connect(secureSettings, settings)
                            },
                            onDecline = { pendingConnection = null },
                        )
                    }
                    if (showPrivacy) {
                        GeographicPrivacyDialog(
                            onOpenLocation = { openSystemSettings(Settings.ACTION_LOCATION_SOURCE_SETTINGS) },
                            onOpenPrivacy = { openSystemSettings(Settings.ACTION_PRIVACY_SETTINGS) },
                            onDone = {
                                privacyPreferences.edit().putBoolean("geographic_privacy_v1", true).apply()
                                showPrivacy = false
                            },
                            onRemind = { showPrivacy = false },
                        )
                    }
                }
            }
        }
    }

    private fun connect(secureSettings: SecureSettings, settings: ClientSettings) {
        secureSettings.save(settings.copy(coordinatorUrl = settings.coordinatorUrl.trimEnd('/')))
		if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_COARSE_LOCATION) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
			afterLocationPermission = { beginVpnConnection() }
			locationPermission.launch(Manifest.permission.ACCESS_COARSE_LOCATION)
			return
		}
		beginVpnConnection()
	}

	private fun beginVpnConnection() {
        val permissionIntent: Intent? = VpnService.prepare(this)
        if (permissionIntent == null) {
            requestNotificationPermission()
            MeshVpnService.start(this)
        } else {
            // Activity Result launchers cannot safely show the VPN and
            // notification dialogs at the same time. Ask for notifications only
            // after Android has finished the VPN consent flow.
            vpnPermission.launch(permissionIntent)
        }
	}

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    private fun openSystemSettings(action: String) {
        runCatching { startActivity(Intent(action)) }
            .onFailure { startActivity(Intent(Settings.ACTION_SETTINGS)) }
    }

}

@Composable
private fun GeographicPrivacyDialog(
    onOpenLocation: () -> Unit,
    onOpenPrivacy: () -> Unit,
    onDone: () -> Unit,
    onRemind: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onRemind,
        title = { Text(stringResource(R.string.geo_privacy_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(stringResource(R.string.geo_privacy_body))
                TextButton(onClick = onOpenLocation) { Text(stringResource(R.string.geo_privacy_location_settings)) }
                TextButton(onClick = onOpenPrivacy) { Text(stringResource(R.string.geo_privacy_tracking_settings)) }
                Text(stringResource(R.string.geo_privacy_browser_steps), style = MaterialTheme.typography.bodySmall)
                Text(stringResource(R.string.geo_privacy_radio_steps), style = MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton = { Button(onClick = onDone) { Text(stringResource(R.string.geo_privacy_done)) } },
        dismissButton = { TextButton(onClick = onRemind) { Text(stringResource(R.string.geo_privacy_remind)) } },
    )
}

private val Sand = Color(0xFFF6F3EC)
private val Ink = Color(0xFF1E1E1E)
private val Orange = Color(0xFFFF9F1C)
private val Green = Color(0xFF16825D)

@Composable
private fun VpnDisclosureDialog(onAccept: () -> Unit, onDecline: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDecline,
        title = { Text(stringResource(R.string.vpn_disclosure_title)) },
        text = { Text(stringResource(R.string.vpn_disclosure_body)) },
        confirmButton = {
            Button(onClick = onAccept) { Text(stringResource(R.string.vpn_disclosure_accept)) }
        },
        dismissButton = {
            TextButton(onClick = onDecline) { Text(stringResource(R.string.vpn_disclosure_decline)) }
        },
    )
}

@Composable
private fun MeshScreen(
    initialSettings: ClientSettings,
    selectedLanguage: AppLanguage,
    onLanguage: (AppLanguage) -> Unit,
    onConnect: (ClientSettings) -> Unit,
    onDisconnect: () -> Unit,
    onUseExit: (String) -> Unit,
    onClearExit: () -> Unit,
    onPrivacy: () -> Unit,
) {
    val context = LocalContext.current
    val state by MeshRuntime.state.collectAsState()
    var coordinator by remember { mutableStateOf(normalizedCoordinator(initialSettings.coordinatorUrl)) }
    var authKey by remember { mutableStateOf(initialSettings.authKey) }
    var hostname by remember { mutableStateOf(initialSettings.hostname) }
    var showAdvanced by remember {
        mutableStateOf(
            initialSettings.coordinatorUrl.isNotBlank() &&
                normalizedCoordinator(initialSettings.coordinatorUrl) != OFFICIAL_COORDINATOR_URL,
        )
    }
    var inputError by remember { mutableStateOf<Int?>(null) }
    val active = state.phase == ConnectionPhase.CONNECTING ||
        state.phase == ConnectionPhase.CONNECTED || state.phase == ConnectionPhase.DISCONNECTING

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 22.dp, vertical = 30.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(stringResource(R.string.brand_name), color = Orange, fontWeight = FontWeight.Black)
            LanguageSelector(selectedLanguage, onLanguage)
        }
        Text(stringResource(R.string.tagline), style = MaterialTheme.typography.headlineMedium, color = Ink)

        StatusCard(state)

        if (!active) {
            Text(stringResource(R.string.first_connection), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Text(stringResource(R.string.enrollment_hint), style = MaterialTheme.typography.bodyMedium, color = Color.DarkGray)
            OutlinedTextField(
                value = authKey,
                onValueChange = { authKey = it.lowercase().replace(" ", ""); inputError = null },
                modifier = Modifier.fillMaxWidth(),
                label = { Text(stringResource(R.string.enrollment_code)) },
                placeholder = { Text(stringResource(R.string.enrollment_code_placeholder)) },
                visualTransformation = PasswordVisualTransformation(),
                singleLine = true,
            )
            OutlinedTextField(
                value = hostname,
                onValueChange = { hostname = it.replace(Regex("[^A-Za-z0-9-]"), "-").take(63); inputError = null },
                modifier = Modifier.fillMaxWidth(),
                label = { Text(stringResource(R.string.device_name)) },
                supportingText = { Text(stringResource(R.string.device_name_hint)) },
                singleLine = true,
            )
            TextButton(onClick = { showAdvanced = !showAdvanced }) {
                Text(stringResource(if (showAdvanced) R.string.hide_advanced else R.string.show_advanced))
            }
            if (showAdvanced) {
                OutlinedTextField(
                    value = coordinator,
                    onValueChange = { coordinator = it; inputError = null },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text(stringResource(R.string.coordinator_url)) },
                    placeholder = { Text(OFFICIAL_COORDINATOR_URL) },
                    supportingText = { Text(stringResource(R.string.coordinator_advanced_hint)) },
                    singleLine = true,
                )
            }
        }

        (inputError?.let { stringResource(it) } ?: state.error)?.let {
            Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
        }

        if (active) {
            Button(
                onClick = onDisconnect,
                enabled = state.phase != ConnectionPhase.DISCONNECTING,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = Ink),
            ) {
                Text(
                    stringResource(
                        if (state.phase == ConnectionPhase.DISCONNECTING) R.string.status_disconnecting
                        else R.string.disconnect,
                    ),
                )
            }
        } else {
            Button(
                onClick = {
                    val error = validateSettings(coordinator, authKey, hostname)
                    inputError = error
                    if (error == null) {
                        onConnect(ClientSettings(normalizedCoordinator(coordinator), authKey.trim(), hostname.trim()))
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = Orange, contentColor = Ink),
            ) { Text(stringResource(R.string.connect), fontWeight = FontWeight.Bold) }
        }

        if (state.phase == ConnectionPhase.CONNECTED) ExitSelector(state, onUseExit, onClearExit)

        if (state.exitClients.isNotEmpty()) {
            Text(stringResource(R.string.exit_clients), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            state.exitClients.forEach { client ->
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Column {
                        Text(client.name.ifBlank { client.meshIp }, fontWeight = FontWeight.SemiBold)
                        if (client.meshIp.isNotBlank()) Text(client.meshIp, style = MaterialTheme.typography.bodySmall)
                    }
                    Text(
                        stringResource(
                            when (client.state) {
                                "active" -> R.string.exit_client_active
                                "offline" -> R.string.exit_client_offline
                                else -> R.string.exit_client_connecting
                            },
                        ),
                        color = if (client.state == "active") Green else Color.Gray,
                    )
                }
            }
        }

        if (state.peers.isNotEmpty()) {
            Text(stringResource(R.string.peers), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            state.peers.forEach { peer ->
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Column {
                        Text(peer.name.ifBlank { peer.meshIp }, fontWeight = FontWeight.SemiBold)
                        Text("${peer.meshIp} · ${localizedPath(peer.pathType)}", style = MaterialTheme.typography.bodySmall)
                    }
                    Text(
                        stringResource(if (peer.online) R.string.online else R.string.offline),
                        color = if (peer.online) Green else Color.Gray,
                    )
                }
            }
        }
        val remotePeers = state.peers.filter { it.remoteAccessAllowed && it.meshIp.isNotBlank() }
        if (remotePeers.isNotEmpty()) {
            Text(stringResource(R.string.remote_access), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            remotePeers.forEach { peer ->
                Column(modifier = Modifier.fillMaxWidth()) {
                    Text(peer.name.ifBlank { peer.meshIp }, fontWeight = FontWeight.SemiBold)
                    Text("${peer.meshIp} · ${peer.platform}", style = MaterialTheme.typography.bodySmall)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        peer.remoteServices.forEach { service ->
                            OutlinedButton(onClick = {
                                openRemoteAccess(context, service.kind, service.targetMeshIp, service.port)
                            }) {
                                Text(if (service.kind == "vnc") stringResource(R.string.remote_screen) else service.kind.uppercase())
                            }
                        }
                    }
                }
            }
            Text(stringResource(R.string.remote_access_note), style = MaterialTheme.typography.bodySmall, color = Color.Gray)
        }
        OutlinedButton(onClick = onPrivacy, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.geo_privacy_open))
        }
        Spacer(Modifier.height(16.dp))
    }
}

private fun openRemoteAccess(context: Context, scheme: String, meshIp: String, port: Int) {
    if (scheme !in setOf("ssh", "rdp", "vnc") || meshIp.isBlank() || port !in 1..65535) return
    val host = if (':' in meshIp) "[$meshIp]" else meshIp
    val intent = Intent(Intent.ACTION_VIEW, Uri.parse("$scheme://$host:$port"))
    try {
        context.startActivity(intent)
    } catch (_: Exception) {
        Toast.makeText(context, context.getString(R.string.remote_access_no_app), Toast.LENGTH_LONG).show()
    }
}

@Composable
private fun LanguageSelector(selected: AppLanguage, onSelect: (AppLanguage) -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    Box {
        TextButton(onClick = { expanded = true }) {
            Text(stringResource(R.string.language_button, languageLabel(selected)))
        }
        DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            AppLanguage.entries.forEach { language ->
                DropdownMenuItem(
                    text = {
                        Text(
                            if (language == selected) "✓ ${languageLabel(language)}"
                            else languageLabel(language),
                        )
                    },
                    onClick = {
                        expanded = false
                        onSelect(language)
                    },
                )
            }
        }
    }
}

@Composable
private fun languageLabel(language: AppLanguage): String = when (language) {
    AppLanguage.SYSTEM -> stringResource(R.string.language_system)
    AppLanguage.SIMPLIFIED_CHINESE -> "简体中文"
    AppLanguage.TRADITIONAL_CHINESE -> "繁體中文"
    AppLanguage.ENGLISH -> "English"
}

@Composable
private fun StatusCard(state: MeshState) {
    val (label, color) = when (state.phase) {
        ConnectionPhase.DISCONNECTED -> stringResource(R.string.status_disconnected) to Color.Gray
        ConnectionPhase.CONNECTING -> stringResource(R.string.status_connecting) to Orange
        ConnectionPhase.CONNECTED -> stringResource(R.string.status_connected) to Green
        ConnectionPhase.DISCONNECTING -> stringResource(R.string.status_disconnecting) to Orange
        ConnectionPhase.ERROR -> stringResource(R.string.status_failed) to MaterialTheme.colorScheme.error
    }
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(16.dp),
    ) {
        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(label, color = color, fontWeight = FontWeight.Bold)
            // Explain a stuck connection instead of showing "Connecting…" forever:
            // a revoked/expired device needs re-enrollment; otherwise, while still
            // connecting with no mesh IP yet, say we are reaching the coordinator.
            if (state.enrollmentRequired) {
                Text(
                    stringResource(R.string.enrollment_required),
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                )
            } else if (state.phase == ConnectionPhase.CONNECTING && state.meshIp.isBlank()) {
                Text(
                    stringResource(R.string.status_reaching_coordinator),
                    color = Color.DarkGray,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            if (state.meshIp.isNotBlank()) Text(stringResource(R.string.mesh_ip, state.meshIp))
            if (state.publicKey.isNotBlank()) Text(
                stringResource(R.string.public_key_short, state.publicKey.take(12)),
                style = MaterialTheme.typography.bodySmall,
                color = Color.DarkGray,
            )
        }
    }
}

@Composable
private fun ExitSelector(state: MeshState, onUseExit: (String) -> Unit, onClearExit: () -> Unit) {
    val exits = state.peers.filter { it.role == "exit" && it.online }
    var requestedRoute by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(state.activeExit, state.selectedExit, state.error) { requestedRoute = null }
    val displayedRoute = requestedRoute ?: state.selectedExit.ifBlank { state.activeExit }
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(stringResource(R.string.exit_route), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = if (displayedRoute.isBlank()) Color.White else if (state.exitTrafficVerified) Color(0xFFE1F3EB) else Color(0xFFFFF1D6)),
            shape = RoundedCornerShape(16.dp),
        ) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(stringResource(R.string.current_route), style = MaterialTheme.typography.labelMedium, color = Color.DarkGray)
                Text(
                    when {
                        requestedRoute != null && requestedRoute!!.isBlank() -> stringResource(R.string.switching_to_direct)
                        requestedRoute != null -> stringResource(R.string.switching_to_exit, requestedRoute!!)
                        state.selectedExit.isNotBlank() && state.activeExit.isBlank() -> stringResource(R.string.switching_to_exit, state.selectedExit)
                        state.activeExit.isBlank() -> stringResource(R.string.direct_active)
                        !state.exitTrafficVerified -> stringResource(R.string.exit_verifying, state.activeExit)
                        else -> stringResource(R.string.exit_verified, state.activeExit)
                    },
                    color = if (displayedRoute.isBlank()) Ink else if (state.exitTrafficVerified) Green else Orange,
                    fontWeight = FontWeight.Bold,
                    style = MaterialTheme.typography.titleMedium,
                )
            }
        }
        RouteButton(
            selected = displayedRoute.isBlank(),
            label = stringResource(R.string.use_direct),
            onClick = {
                if (displayedRoute.isNotBlank() && requestedRoute == null) {
                    requestedRoute = ""
                    onClearExit()
                }
            },
        )
        exits.forEach { peer ->
            RouteButton(
                selected = displayedRoute == peer.name && state.exitTrafficVerified,
                label = stringResource(R.string.use_exit_named, peer.name),
                onClick = {
                    if (displayedRoute != peer.name && requestedRoute == null) {
                        requestedRoute = peer.name
                        onUseExit(peer.name)
                    }
                },
            )
        }
        if (exits.isEmpty()) Text(stringResource(R.string.no_online_exit_nodes), color = Color.Gray)
    }
}

@Composable
private fun RouteButton(selected: Boolean, label: String, onClick: () -> Unit) {
    if (selected) {
        Button(
            onClick = onClick,
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(containerColor = Green, contentColor = Color.White),
        ) { Text("✓ $label", fontWeight = FontWeight.Bold) }
    } else {
        OutlinedButton(onClick = onClick, modifier = Modifier.fillMaxWidth()) { Text(label) }
    }
}

@Composable
private fun localizedPath(path: String): String = when (path.lowercase()) {
    "direct" -> stringResource(R.string.path_direct)
    "relay", "relayed" -> stringResource(R.string.path_relay)
    else -> path
}

private fun validateSettings(coordinator: String, enrollmentCode: String, hostname: String): Int? {
    if (!validCoordinator(coordinator)) return R.string.validation_coordinator_url
    if (!validEnrollmentCode(enrollmentCode, coordinator)) return R.string.validation_enrollment_code
    if (hostname.isBlank()) return R.string.validation_device_name_required
    if (!validDeviceName(hostname)) return R.string.validation_device_name_format
    return null
}
