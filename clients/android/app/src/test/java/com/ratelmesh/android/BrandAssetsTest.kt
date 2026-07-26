package com.ratelmesh.android

import java.io.File
import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BrandAssetsTest {
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
