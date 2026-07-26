package com.ratelmesh.android

import com.ratelmesh.android.data.ClientSettings
import com.ratelmesh.android.data.IdentityResetCoordinator
import com.ratelmesh.android.data.requiresIdentityReset
import java.io.File
import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class BrandAssetsTest {
    @Test
    fun credentialResetOperationsAreProcessWideSerialized() {
        val active = AtomicInteger()
        val maximum = AtomicInteger()
        val ready = CountDownLatch(12)
        val start = CountDownLatch(1)
        val done = CountDownLatch(12)
        val pool = Executors.newFixedThreadPool(12)
        repeat(12) {
            pool.execute {
                ready.countDown()
                start.await()
                IdentityResetCoordinator.serialized {
                    maximum.updateAndGet { previous -> maxOf(previous, active.incrementAndGet()) }
                    Thread.sleep(5)
                    active.decrementAndGet()
                }
                done.countDown()
            }
        }
        assertTrue(ready.await(2, TimeUnit.SECONDS))
        start.countDown()
        assertTrue(done.await(5, TimeUnit.SECONDS))
        pool.shutdownNow()
        assertEquals(1, maximum.get())
    }

    @Test
    fun remoteAccessRejectsAuthorityAndPathInjection() {
        assertEquals("ssh://100.64.0.8:22", RemoteAccessTarget.url("ssh", "100.64.0.8", 22))
        assertEquals("vnc://[fd00::8]:5900", RemoteAccessTarget.url("vnc", "fd00::8", 5900))
        listOf(
            "office.example",
            "100.64.0.8@evil.example",
            "100.64.0.8/path",
            "100.64.0.8?x=1",
            "[fd00::8]",
            "fd00::8%wlan0",
        ).forEach { assertNull(RemoteAccessTarget.url("ssh", it, 22)) }
        assertNull(RemoteAccessTarget.url("https", "100.64.0.8", 22))
        assertNull(RemoteAccessTarget.url("ssh", "100.64.0.8", 0))
    }

    private val appDir: File by lazy {
        val working = File(requireNotNull(System.getProperty("user.dir")))
        sequenceOf(
            File(working, "app"),
            working,
            File(working, "clients/android/app"),
        ).first { File(it, "src/main/AndroidManifest.xml").isFile }
    }

    @Test
    fun `accepted launcher exports remain exact`() {
        val expected = mapOf(
            "mipmap-mdpi/ic_launcher.png" to "2fecb168a223bd740c3436e80970247c468c4d6330ac32ba13bffcd796d79c42",
            "mipmap-hdpi/ic_launcher.png" to "9c1c5d25011dab4b0cebe9bcf58114192182421ef17f3653244d191d06a8d24c",
            "mipmap-xhdpi/ic_launcher.png" to "6dc040715acca492127a9346f8b7374c5ee7fa3e9de629540a3426c63470c56d",
            "mipmap-xxhdpi/ic_launcher.png" to "32ef6368fff9728d6397a5d24658ffae6e76900c92c6ed0835c2f3a4baf86f44",
            "mipmap-xxxhdpi/ic_launcher.png" to "0ff9321ca925153cf17ac75a42239af2799ccdf7ac1a18f103eadcda45bd68a8",
        )

        expected.forEach { (relativePath, digest) ->
            val asset = File(appDir, "src/main/res/$relativePath")
            assertTrue("$relativePath must exist", asset.isFile)
            assertEquals("$relativePath must remain the accepted v3 mark", digest, asset.sha256())
        }
    }

    @Test
    fun `adaptive launcher keeps the v3 mark inside the mask safe zone`() {
        val adaptive = File(appDir, "src/main/res/mipmap-anydpi-v26/ic_launcher.xml").readText()
        val foreground = File(appDir, "src/main/res/drawable/ic_launcher_foreground.xml").readText()
        val inAppMark = File(appDir, "src/main/res/drawable/brand_mark.xml").readText()
        val manifest = File(appDir, "src/main/AndroidManifest.xml").readText()

        assertTrue(adaptive.contains("""android:drawable="@drawable/ic_launcher_foreground""""))
        assertTrue(adaptive.contains("""android:drawable="@color/ic_launcher_background""""))
        assertTrue(foreground.contains("""android:scaleX="0.62""""))
        assertTrue(foreground.contains("""android:scaleY="0.62""""))
        assertTrue(foreground.contains("M81,131C61,113 46,112 34,124"))
        assertTrue(inAppMark.contains("M192,158L256,132L320,158"))
        assertTrue(manifest.contains("""android:roundIcon="@mipmap/ic_launcher""""))
    }

    @Test
    fun `notification uses the monochrome honey badger mesh mark`() {
        val source = File(appDir, "src/main/res/drawable/ic_notification.xml").readText()

        assertTrue(source.contains("""android:viewportWidth="512""""))
        assertTrue(source.contains("M81,131C61,113 46,112 34,124"))
        assertTrue(source.contains("""android:fillType="evenOdd""""))
        assertTrue(source.contains("M192,158L256,132L320,158"))
        assertEquals("the crown must use the three-endpoint v3 mesh", 3, "a8,8 0,1 1,-16,0".toRegex().findAll(source).count())
        assertFalse("notification icons must remain monochrome", source.contains("#20B9E8", ignoreCase = true))
    }

    @Test
    fun `legacy shield era visual tokens cannot return`() {
        val uiSource = File(appDir, "src/main/java/com/ratelmesh/android/MainActivity.kt").readText()
        val platformTheme = File(appDir, "src/main/res/values/themes.xml").readText()
        val combined = uiSource + platformTheme

        listOf("Shield", "ic_shield", "0xFFF6F3EC", "#F6F3EC", "0xFFFF9F1C", "#FF9F1C").forEach {
            assertFalse("legacy visual reference returned: $it", combined.contains(it, ignoreCase = true))
        }
        assertTrue(combined.contains("#0B0F14"))
    }

    @Test
    fun `brand theme owns the production palette`() {
        val theme = File(appDir, "src/main/java/com/ratelmesh/android/RatelMeshTheme.kt").readText()

        listOf(
            "0xFF0B0F14",
            "0xFF20B9E8",
            "0xFF006A8C",
            "0xFFF4F7F9",
            "0xFF42515C",
            "0xFF16956C",
            "0xFF006A4E",
            "0xFFFFB4AB",
        ).forEach {
            assertTrue("missing brand token $it", theme.contains(it))
        }
        assertTrue(theme.contains("isSystemInDarkTheme()"))
        assertTrue(theme.contains("LightColors"))
        assertTrue(theme.contains("DarkColors"))
        assertTrue(theme.contains("tertiary = AccessibleMeshSuccess"))
        assertTrue(theme.contains("tertiary = MeshSuccess"))
    }

    @Test
    fun `light semantic text colors meet wcag contrast`() {
        listOf(0xF4F7F9, 0xD9F3FB).forEach { background ->
            assertTrue(contrast(0x006A8C, background) >= 4.5)
            assertTrue(contrast(0x006A4E, background) >= 4.5)
        }
    }

    @Test
    fun `dark critical and responsive header structure cannot regress`() {
        val source = File(appDir, "src/main/java/com/ratelmesh/android/MainActivity.kt").readText()

        assertTrue(source.contains("ConnectionPhase.ERROR -> stringResource(R.string.status_failed) to CriticalOnDark"))
        assertTrue(source.contains("color = CriticalOnDark"))
        assertTrue(source.contains("BoxWithConstraints"))
        assertTrue(source.contains("maxWidth < 360.dp"))
        assertTrue(source.contains("fontScale >= 1.3f"))
        assertTrue(source.contains("Brand(Modifier.weight(1f))"))
        assertTrue(source.contains("contentDescription = fullDescription"))
        assertTrue(source.contains("languageShortLabel(selected)"))
        assertTrue(source.contains("FlowRow("))
        assertTrue(source.contains("verticalArrangement = Arrangement.spacedBy(8.dp)"))
        assertTrue(source.contains("this.selected = language == selected"))
        assertTrue(source.contains("this.selected = true"))
        assertTrue(source.contains("contentDescription = remoteAccessAccessibilityLabel"))
        assertFalse(source.contains("""Text("✓ ${'$'}label""""))
    }

    @Test
    fun `vpn service uses the selected app language for foreground messages`() {
        val source = File(
            appDir,
            "src/main/java/com/ratelmesh/android/service/MeshVpnService.kt",
        ).readText()

        assertTrue(source.contains("override fun attachBaseContext(newBase: Context)"))
        assertTrue(source.contains("AppLanguagePreferences.localizedContext(newBase)"))
        assertTrue(source.contains("ACTION_REFRESH_LANGUAGE"))
        assertTrue(source.contains("notification(connecting = !tunnelUp)"))
        assertFalse(source.contains("ACTION_REFRESH_LANGUAGE -> scope.launch { stopSession() }"))
        assertFalse(source.contains("error.message"))
        assertFalse(source.contains("error.javaClass.simpleName"))
        assertTrue(source.contains("error = getString(R.string.error_connection_failed)"))
        assertTrue(source.contains("private fun withoutLiveSession("))
        assertTrue(source.contains("exitTrafficVerified = false"))
        assertTrue(source.contains("exitClients = emptyList()"))
        assertTrue(source.contains("enrollmentRequired = false"))
        assertTrue(source.contains("stopAfterSystemTunnelDown"))
        assertTrue(source.contains("withTimeoutOrNull(ON_DESTROY_JOIN_TIMEOUT_MS)"))
        assertFalse(source.contains("runBlocking { job?.join() }"))

        val activity = File(
            appDir,
            "src/main/java/com/ratelmesh/android/MainActivity.kt",
        ).readText()
        assertTrue(activity.contains("AppLanguagePreferences.save(this, language)"))
        assertTrue(activity.contains("MeshVpnService.refreshLanguage(this)"))
    }

    @Test
    fun `credential changes reset identity before the core can restart`() {
        val settings = File(
            appDir,
            "src/main/java/com/ratelmesh/android/data/SecureSettings.kt",
        ).readText()
        val service = File(
            appDir,
            "src/main/java/com/ratelmesh/android/service/MeshVpnService.kt",
        ).readText()

        assertTrue(settings.contains("KEY_IDENTITY_RESET_PENDING"))
        assertTrue(settings.contains("fun resetIdentityIfPending(reset: () -> Unit)"))
        assertTrue(settings.contains("IdentityResetCoordinator.serialized"))
        assertTrue(service.contains("resetIdentityIfPending"))
        val reset = service.indexOf("resetIdentityIfPending")
        val start = service.indexOf("core.startApp(")
        assertTrue(reset >= 0 && start > reset)
        assertTrue(service.contains("deleteRecursively()"))

        val old = ClientSettings("https://control.ratelmesh.com", "old-code", "phone")
        assertFalse(requiresIdentityReset(old, old))
        assertTrue(requiresIdentityReset(old, old.copy(authKey = "new-code")))
        assertTrue(requiresIdentityReset(old, old.copy(coordinatorUrl = "https://other.example")))
        assertFalse(requiresIdentityReset(old, old.copy(hostname = "renamed-phone")))
        assertFalse(requiresIdentityReset(old, old.copy(authKey = "")))
    }

    @Test
    fun `teardown preserves actionable enrollment state and exposes no configuration`() {
        val service = File(
            appDir,
            "src/main/java/com/ratelmesh/android/service/MeshVpnService.kt",
        ).readText()
        val manifest = File(appDir, "src/main/AndroidManifest.xml").readText()
        val extraction = File(appDir, "src/main/res/xml/data_extraction_rules.xml").readText()

        assertTrue(service.contains("enrollmentRequired = current.enrollmentRequired"))
        val teardown = service.substringAfter("private fun withoutLiveSession(")
            .substringBefore("private fun releaseCoreService()")
        assertFalse(teardown.contains("enrollmentRequired = false"))
        assertFalse(service.contains("Log."))
        assertFalse(service.contains("println("))
        assertTrue(service.contains("PendingIntent.FLAG_IMMUTABLE"))
        assertTrue(manifest.contains("""android:allowBackup="false""""))
        assertTrue(manifest.contains("""android:exported="false""""))
        assertTrue(extraction.contains("""<exclude domain="sharedpref" path="." />"""))
        assertTrue(extraction.contains("""<exclude domain="file" path="." />"""))
    }

    private fun File.sha256(): String {
        val hash = MessageDigest.getInstance("SHA-256").digest(readBytes())
        return hash.joinToString("") { "%02x".format(it) }
    }

    private fun contrast(foreground: Int, background: Int): Double {
        val lighter = maxOf(luminance(foreground), luminance(background))
        val darker = minOf(luminance(foreground), luminance(background))
        return (lighter + 0.05) / (darker + 0.05)
    }

    private fun luminance(rgb: Int): Double {
        fun channel(shift: Int): Double {
            val value = ((rgb shr shift) and 0xff) / 255.0
            return if (value <= 0.04045) value / 12.92 else Math.pow((value + 0.055) / 1.055, 2.4)
        }
        return 0.2126 * channel(16) + 0.7152 * channel(8) + 0.0722 * channel(0)
    }
}
