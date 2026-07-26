package com.ratelmesh.android

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

internal val RatelBlack = Color(0xFF0B0F14)
internal val RatelSurface = Color(0xFF111820)
internal val RatelRaisedSurface = Color(0xFF18222C)
internal val RatelWhite = Color(0xFFF4F7F9)
internal val MeshCyan = Color(0xFF20B9E8)
internal val AccessibleMeshCyan = Color(0xFF006A8C)
internal val MeshOutline = Color(0xFF42515C)
internal val MeshSuccess = Color(0xFF16956C)
internal val AccessibleMeshSuccess = Color(0xFF006A4E)
internal val CriticalOnDark = Color(0xFFFFB4AB)

private val LightColors = lightColorScheme(
    primary = AccessibleMeshCyan,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFD9F3FB),
    onPrimaryContainer = Color(0xFF052B38),
    tertiary = AccessibleMeshSuccess,
    onTertiary = Color.White,
    secondary = RatelBlack,
    onSecondary = RatelWhite,
    background = RatelWhite,
    onBackground = RatelBlack,
    surface = Color.White,
    onSurface = RatelBlack,
    surfaceVariant = Color(0xFFE6EDF0),
    onSurfaceVariant = Color(0xFF42515C),
    outline = Color(0xFF72838E),
)

private val DarkColors = darkColorScheme(
    primary = MeshCyan,
    onPrimary = RatelBlack,
    primaryContainer = Color(0xFF063E50),
    onPrimaryContainer = Color(0xFFA8E7F7),
    tertiary = MeshSuccess,
    onTertiary = RatelBlack,
    secondary = RatelWhite,
    onSecondary = RatelBlack,
    background = RatelBlack,
    onBackground = RatelWhite,
    surface = RatelSurface,
    onSurface = RatelWhite,
    surfaceVariant = RatelRaisedSurface,
    onSurfaceVariant = Color(0xFFB7C4CC),
    outline = MeshOutline,
)

@Composable
internal fun RatelMeshTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (isSystemInDarkTheme()) DarkColors else LightColors,
        content = content,
    )
}
