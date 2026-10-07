package com.secureshield.ai.network

import android.content.Context
import com.secureshield.ai.BuildConfig
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

/**
 * Single source of truth for the SecureShield backend base URL.
 *
 * Manages URL validation, persistent storage via SharedPreferences,
 * default fallback to [BuildConfig.BASE_URL] (e.g. http://10.0.2.2:8000/ on emulator),
 * and immediate runtime synchronization with [ApiClient].
 */
object ServerSettings {
    const val PREFS_NAME = "secureshield_settings"
    const val KEY_SERVER_BASE_URL = "server_base_url"

    /**
     * Initializes [ApiClient.baseUrl] from saved preferences, falling back
     * to the default build configuration base URL.
     */
    @Synchronized
    fun init(context: Context) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val saved = prefs.getString(KEY_SERVER_BASE_URL, null)
        if (!saved.isNullOrBlank() && isValidServerUrl(saved)) {
            ApiClient.setBaseUrl(saved)
        } else {
            ApiClient.setBaseUrl(getDefaultBaseUrl())
        }
    }

    /**
     * Returns the build-configured default base URL, normalized with a trailing slash.
     */
    fun getDefaultBaseUrl(): String = ApiClient.normalizeBaseUrl(BuildConfig.BASE_URL)

    /**
     * Retrieves the current base URL. If [context] is supplied and preferences
     * have a valid entry, guarantees synchronization before returning.
     */
    fun getServerUrl(context: Context? = null): String {
        if (context != null) {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val saved = prefs.getString(KEY_SERVER_BASE_URL, null)
            if (!saved.isNullOrBlank() && isValidServerUrl(saved)) {
                val normalized = ApiClient.normalizeBaseUrl(saved)
                if (ApiClient.baseUrl != normalized) {
                    ApiClient.setBaseUrl(normalized)
                }
                return normalized
            }
        }
        return ApiClient.baseUrl
    }

    /**
     * Validates, normalizes, persists, and immediately updates [ApiClient.baseUrl].
     * Returns true if saved successfully, false if the URL is invalid.
     */
    @Synchronized
    fun saveServerUrl(context: Context, rawUrl: String): Boolean {
        if (!isValidServerUrl(rawUrl)) {
            return false
        }
        val normalized = ApiClient.normalizeBaseUrl(rawUrl)
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_SERVER_BASE_URL, normalized)
            .apply()
        ApiClient.setBaseUrl(normalized)
        return true
    }

    /**
     * Strict URL validation ensuring valid HTTP/HTTPS scheme and non-empty hostname.
     */
    fun isValidServerUrl(rawUrl: String?): Boolean {
        if (rawUrl.isNullOrBlank()) return false
        val trimmed = rawUrl.trim()
        if (!trimmed.startsWith("http://", ignoreCase = true) && !trimmed.startsWith("https://", ignoreCase = true)) {
            return false
        }
        val parsed = trimmed.toHttpUrlOrNull() ?: return false
        return parsed.host.isNotBlank()
    }

    /**
     * Resets preferences back to the default build configuration base URL.
     */
    @Synchronized
    fun resetToDefault(context: Context) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .remove(KEY_SERVER_BASE_URL)
            .apply()
        ApiClient.setBaseUrl(getDefaultBaseUrl())
    }
}
