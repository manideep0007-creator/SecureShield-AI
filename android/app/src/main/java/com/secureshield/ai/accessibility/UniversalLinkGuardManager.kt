package com.secureshield.ai.accessibility

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.provider.Settings
import android.text.TextUtils
import android.view.accessibility.AccessibilityManager

object UniversalLinkGuardManager {
    private const val PREFS_NAME = "universal_guard_prefs"
    private const val KEY_PROTECTION_ENABLED = "universal_guard_enabled"

    /**
     * Checks if the UniversalLinkGuardService is enabled in Android's accessibility settings.
     * Uses AccessibilityManager (the official API for Android 10-14+) with Settings.Secure fallback.
     */
    fun isServiceEnabledInSettings(context: Context): Boolean {
        // 1. Primary check: AccessibilityManager query (official public API supported across all Android versions)
        try {
            val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager
            if (am != null) {
                val enabledServices = am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
                val found = enabledServices.any { service ->
                    val sInfo = service.resolveInfo?.serviceInfo
                    sInfo != null &&
                        sInfo.packageName == context.packageName &&
                        sInfo.name.endsWith("UniversalLinkGuardService")
                }
                if (found) return true
            }
        } catch (_: Exception) {}

        // 2. Secondary check: Settings.Secure query
        try {
            val expectedComponentName = ComponentName(context, UniversalLinkGuardService::class.java)
            val enabledServicesSetting = Settings.Secure.getString(
                context.contentResolver,
                Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES
            )
            if (!enabledServicesSetting.isNullOrBlank()) {
                val colonSplitter = TextUtils.SimpleStringSplitter(':')
                colonSplitter.setString(enabledServicesSetting)
                while (colonSplitter.hasNext()) {
                    val componentNameString = colonSplitter.next()
                    val enabledComponent = ComponentName.unflattenFromString(componentNameString)
                    if (enabledComponent != null && (enabledComponent == expectedComponentName ||
                            (enabledComponent.packageName == expectedComponentName.packageName &&
                             enabledComponent.className.endsWith("UniversalLinkGuardService")))) {
                        return true
                    }
                }
            }
        } catch (_: Exception) {}

        return false
    }

    /**
     * Protection is fully active when the service is enabled in Android Settings
     * AND the user hasn't toggled it off in the app.
     */
    fun isProtectionActive(context: Context): Boolean {
        return isServiceEnabledInSettings(context) && isUserPreferenceEnabled(context)
    }

    fun isUserPreferenceEnabled(context: Context): Boolean {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getBoolean(KEY_PROTECTION_ENABLED, true)
    }

    fun setUserPreferenceEnabled(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_PROTECTION_ENABLED, enabled)
            .apply()
    }

    /**
     * Launches the Android Accessibility Settings screen where the user can enable the service.
     */
    fun openAccessibilitySettings(context: Context) {
        val intent = Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK
        }
        context.startActivity(intent)
    }
}
