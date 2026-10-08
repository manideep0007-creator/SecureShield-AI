package com.secureshield.ai.network

import android.content.Context
import android.content.SharedPreferences
import java.util.UUID

/**
 * Provides a unique, persistent client_id generated once on the device
 * and sent with every scan request for multi-tenant isolation.
 */
object ClientIdProvider {
    private const val PREFS_NAME = "secureshield_client_prefs"
    private const val KEY_CLIENT_ID = "client_id"

    @Volatile
    private var cachedClientId: String? = null

    fun getClientId(context: Context): String {
        cachedClientId?.let { return it }

        synchronized(this) {
            cachedClientId?.let { return it }
            val prefs: SharedPreferences = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            var id = prefs.getString(KEY_CLIENT_ID, null)
            if (id.isNullOrBlank()) {
                id = UUID.randomUUID().toString()
                prefs.edit().putString(KEY_CLIENT_ID, id).apply()
            }
            cachedClientId = id
            return id
        }
    }

    /**
     * For unit testing: allows resetting or injecting a fixed client ID.
     */
    fun setClientIdForTesting(context: Context?, id: String?) {
        synchronized(this) {
            cachedClientId = id
            if (context != null) {
                val prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                if (id != null) {
                    prefs.edit().putString(KEY_CLIENT_ID, id).apply()
                } else {
                    prefs.edit().remove(KEY_CLIENT_ID).apply()
                }
            }
        }
    }
}
