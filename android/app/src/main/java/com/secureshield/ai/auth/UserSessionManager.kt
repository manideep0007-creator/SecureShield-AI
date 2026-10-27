package com.secureshield.ai.auth

import android.content.Context
import android.content.SharedPreferences

object UserSessionManager {
    private const val PREFS_NAME = "secureshield_auth_session"
    private const val KEY_IS_LOGGED_IN = "is_logged_in"
    private const val KEY_USER_ID = "user_id"
    private const val KEY_EMAIL = "email"
    private const val KEY_FULL_NAME = "full_name"
    private const val KEY_PROVIDER = "provider"
    private const val KEY_TOKEN = "auth_token"
    private const val KEY_DB_FILE = "db_file"

    private fun getPrefs(context: Context): SharedPreferences {
        return context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    fun saveSession(context: Context, auth: AuthResponse) {
        getPrefs(context).edit().apply {
            putBoolean(KEY_IS_LOGGED_IN, true)
            putString(KEY_USER_ID, auth.user.user_id)
            putString(KEY_EMAIL, auth.user.email)
            putString(KEY_FULL_NAME, auth.user.full_name)
            putString(KEY_PROVIDER, auth.user.provider)
            putString(KEY_TOKEN, auth.token)
            putString(KEY_DB_FILE, auth.user.db_file)
            apply()
        }
    }

    fun isLoggedIn(context: Context): Boolean {
        return getPrefs(context).getBoolean(KEY_IS_LOGGED_IN, false)
    }

    fun getUserId(context: Context): String {
        return getPrefs(context).getString(KEY_USER_ID, "guest") ?: "guest"
    }

    fun getUserEmail(context: Context): String {
        return getPrefs(context).getString(KEY_EMAIL, "") ?: ""
    }

    fun getUserFullName(context: Context): String {
        return getPrefs(context).getString(KEY_FULL_NAME, "User") ?: "User"
    }

    fun getAuthToken(context: Context): String? {
        return getPrefs(context).getString(KEY_TOKEN, null)
    }

    fun getUserDatabaseName(context: Context): String {
        val uid = getUserId(context)
        return "secureshield_user_${uid}.db"
    }

    fun clearSession(context: Context) {
        getPrefs(context).edit().clear().apply()
    }
}
