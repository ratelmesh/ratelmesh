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
            "mipmap-mdpi/ic_launcher.png" to "24ee7a2baf1770a4c15c32887321a1bd98a77efca737dcd4c567eba42af8b5c0",
            "mipmap-hdpi/ic_launcher.png" to "59e221fbf2d63229507d9aad1abda1602fa535208eab57c4fc7b08dca2cb1a19",
            "mipmap-xhdpi/ic_launcher.png" to "b5b9c608f472c0d4eda0ea1ebf4fe91c44cbe9cb8e8ebf80d432a556d1b1f0e3",
            "mipmap-xxhdpi/ic_launcher.png" to "48772cab688e2887280417684855908ae9025b2fa15117ab05a2887d69f47983",
            "mipmap-xxxhdpi/ic_launcher.png" to "b694482a44f1046b2fbb2e251e416a58007137cb9bebb218446f616928ab222d",
        )

        expected.forEach { (relativePath, digest) ->
            val asset = File(appDir, "src/main/res/$relativePath")
            assertTrue("$relativePath must exist", asset.isFile)
            assertEquals("$relativePath must remain the accepted micro mark", digest, asset.sha256())
        }
    }

    @Test
    fun `notification uses the monochrome honey badger mesh mark`() {
        val source = File(appDir, "src/main/res/drawable/ic_notification.xml").readText()

        assertTrue(source.contains("""android:viewportWidth="512""""))
        assertTrue(source.contains("M81,131C61,113 46,112 34,124"))
        assertTrue(source.contains("""android:fillType="evenOdd""""))
        assertEquals("the crown must retain all six mesh nodes", 6, "a7,7 0,1 1,-14,0".toRegex().findAll(source).count())
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
