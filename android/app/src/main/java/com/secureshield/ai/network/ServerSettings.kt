package com.secureshield.ai.network

import android.content.Context
import android.os.Build
import com.secureshield.ai.BuildConfig
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

/**
 * Single source of truth for the SecureShield backend base URL.
 *
 * Manages URL validation, persistent storage via SharedPreferences,
 * default fallback to production cloud URL or [BuildConfig.BASE_URL],
 * and immediate runtime synchronization with [ApiClient].
 */
object ServerSettings {
    const val PREFS_NAME = "secureshield_settings"
    const val KEY_SERVER_BASE_URL = "server_base_url"

    const val PRODUCTION_CLOUD_URL = "https://secureshield-ai-yzn2.onrender.com/"

    /**
     * Detects if the current running runtime is an Android Emulator.
     */
    fun isEmulator(): Boolean {
        return (Build.FINGERPRINT.startsWith("generic")
                || Build.FINGERPRINT.startsWith("unknown")
                || Build.MODEL.contains("google_sdk")
                || Build.MODEL.contains("Emulator")
                || Build.MODEL.contains("Android SDK built for x86")
                || Build.MANUFACTURER.contains("Genymotion")
                || Build.HARDWARE.contains("goldfish")
                || Build.HARDWARE.contains("ranchu")
                || Build.PRODUCT.contains("sdk")
                || Build.PRODUCT.contains("robolectric")
                || (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic"))
                || "google_sdk" == Build.PRODUCT)
    }

    /**
     * Checks if a URL points to emulator-only loopback addresses.
     */
    fun isEmulatorLoopbackUrl(url: String?): Boolean {
        if (url == null) return false
        val lower = url.lowercase()
        return lower.contains("10.0.2.2") || lower.contains("127.0.0.1") || lower.contains("localhost")
    }

    /**
     * Initializes [ApiClient.baseUrl] from saved preferences, falling back
     * to the default build configuration base URL.
     *
     * Automatically migrates physical devices away from emulator loopbacks (10.0.2.2)
     * to [PRODUCTION_CLOUD_URL] so users never encounter connection timeouts.
     */
    @Synchronized
    fun init(context: Context) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val saved = prefs.getString(KEY_SERVER_BASE_URL, null)

        val targetUrl = when {
            !saved.isNullOrBlank() && isValidServerUrl(saved) -> {
                if (!isEmulator() && isEmulatorLoopbackUrl(saved)) {
                    saveServerUrl(context, PRODUCTION_CLOUD_URL)
                    PRODUCTION_CLOUD_URL
                } else {
                    saved
                }
            }
            else -> {
                val defaultUrl = getDefaultBaseUrl()
                if (!isEmulator() && isEmulatorLoopbackUrl(defaultUrl)) {
                    saveServerUrl(context, PRODUCTION_CLOUD_URL)
                    PRODUCTION_CLOUD_URL
                } else {
                    defaultUrl
                }
            }
        }

        ApiClient.setBaseUrl(targetUrl)
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
     * Resets preferences back to the default build configuration base URL or cloud production URL.
     */
    @Synchronized
    fun resetToDefault(context: Context) {
        val target = if (!isEmulator() && isEmulatorLoopbackUrl(getDefaultBaseUrl())) {
            PRODUCTION_CLOUD_URL
        } else {
            getDefaultBaseUrl()
        }
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .remove(KEY_SERVER_BASE_URL)
            .apply()
        ApiClient.setBaseUrl(target)
    }
}
