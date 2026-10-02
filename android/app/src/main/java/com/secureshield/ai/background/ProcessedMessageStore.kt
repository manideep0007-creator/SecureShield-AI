package com.secureshield.ai.background

import android.content.Context
import org.json.JSONArray

object ProcessedMessageStore {
    private const val PREFS_NAME = "processed_messages_prefs"
    private const val KEY_MESSAGE_IDS = "processed_ids"
    private const val MAX_ENTRIES = 500

    fun isProcessed(context: Context, messageId: String): Boolean {
        return getIds(context).contains(messageId)
    }

    fun markProcessed(context: Context, messageId: String) {
        val ids = getIds(context).toMutableList()
        if (ids.contains(messageId)) return
        ids.add(messageId)
        if (ids.size > MAX_ENTRIES) {
            ids.removeAt(0)
        }
        val encoded = JSONArray(ids).toString()
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_MESSAGE_IDS, encoded)
            .apply()
    }

    private fun getIds(context: Context): List<String> {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val encoded = prefs.getString(KEY_MESSAGE_IDS, null) ?: return emptyList()
        return try {
            val array = JSONArray(encoded)
            List(array.length()) { array.getString(it) }
        } catch (_: Exception) {
            emptyList()
        }
    }
}