package com.ratelmesh.android

import android.content.Context
import android.content.res.Configuration
import java.util.Locale

internal enum class AppLanguage(val tag: String) {
    SYSTEM("system"),
    ENGLISH("en"),
    SPANISH("es"),
    GERMAN("de"),
    FRENCH("fr"),
    JAPANESE("ja"),
    KOREAN("ko"),
    ITALIAN("it"),
    DUTCH("nl"),
    POLISH("pl"),
    SWEDISH("sv"),
    PORTUGUESE_BRAZIL("pt-BR"),
    SIMPLIFIED_CHINESE("zh-CN"),
    TRADITIONAL_CHINESE("zh-TW"),
}

internal object AppLanguagePreferences {
    private const val PREFERENCES = "ratelmesh-language"
    private const val KEY = "language"

    fun load(context: Context): AppLanguage {
        val stored = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .getString(KEY, AppLanguage.SYSTEM.tag)
        return AppLanguage.entries.firstOrNull { it.tag == stored } ?: AppLanguage.SYSTEM
    }

    fun save(context: Context, language: AppLanguage) {
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
            .edit().putString(KEY, language.tag).apply()
    }

    fun localizedContext(context: Context): Context {
        val language = load(context)
        if (language == AppLanguage.SYSTEM) return context
        val configuration = Configuration(context.resources.configuration)
        configuration.setLocale(Locale.forLanguageTag(language.tag))
        return context.createConfigurationContext(configuration)
    }
}
