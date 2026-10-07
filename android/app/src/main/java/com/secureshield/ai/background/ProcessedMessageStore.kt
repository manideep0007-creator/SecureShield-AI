package com.secureshield.ai.background

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.ConcurrentHashMap

object ProcessedMessageStore {
    private const val PREFS_NAME = "processed_messages_prefs"
    private const val KEY_MESSAGE_IDS = "processed_ids"
    private const val KEY_URL_TIMESTAMPS = "processed_url_timestamps"
    private const val MAX_ENTRIES = 500
    private const val MAX_URL_ENTRIES = 500

    const val DEFAULT_URL_TTL_MILLIS: Long = 10 * 60 * 1000L // 10 minutes

    // High-performance in-memory cache for accessibility service events
    private val inMemoryUrlTimestamps = ConcurrentHashMap<String, Long>()

    // --- Message ID Methods (Existing) ---

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

    // --- URL Short-TTL Dedupe Cache Methods ---

    /**
     * Checks if a URL was already processed within the given TTL window (default ~10 minutes).
     */
    fun isUrlProcessed(
        context: Context,
        url: String,
        ttlMillis: Long = DEFAULT_URL_TTL_MILLIS,
        currentTimeMillis: Long = System.currentTimeMillis()
    ): Boolean {
        val normalized = url.trim()
        if (normalized.isEmpty()) return true

        // 1. Fast in-memory check
        val memTimestamp = inMemoryUrlTimestamps[normalized]
        if (memTimestamp != null) {
            if (currentTimeMillis - memTimestamp < ttlMillis) {
                return true
            } else {
                inMemoryUrlTimestamps.remove(normalized)
            }
        }

        // 2. Persistent storage fallback
        val storedMap = getUrlTimestampsFromPrefs(context)
        val diskTimestamp = storedMap[normalized]
        if (diskTimestamp != null) {
            if (currentTimeMillis - diskTimestamp < ttlMillis) {
                inMemoryUrlTimestamps[normalized] = diskTimestamp
                return true
            } else {
                removeUrlFromPrefs(context, normalized)
            }
        }

        return false
    }

    /**
     * Marks a URL as processed with a timestamp.
     */
    fun markUrlProcessed(
        context: Context,
        url: String,
        timestampMillis: Long = System.currentTimeMillis()
    ) {
        val normalized = url.trim()
        if (normalized.isEmpty()) return

        inMemoryUrlTimestamps[normalized] = timestampMillis
        saveUrlTimestampToPrefs(context, normalized, timestampMillis)
    }

    /**
     * Clears all in-memory and persisted URL cache entries (useful for testing or manual reset).
     */
    fun clearUrlCache(context: Context) {
        inMemoryUrlTimestamps.clear()
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .remove(KEY_URL_TIMESTAMPS)
            .apply()
    }

    private fun getUrlTimestampsFromPrefs(context: Context): Map<String, Long> {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val jsonStr = prefs.getString(KEY_URL_TIMESTAMPS, null) ?: return emptyMap()
        return try {
            val json = JSONObject(jsonStr)
            val result = mutableMapOf<String, Long>()
            val keys = json.keys()
            while (keys.hasNext()) {
                val key = keys.next()
                result[key] = json.getLong(key)
            }
            result
        } catch (_: Exception) {
            emptyMap()
        }
    }

    private fun saveUrlTimestampToPrefs(context: Context, url: String, timestamp: Long) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val map = getUrlTimestampsFromPrefs(context).toMutableMap()
        map[url] = timestamp

        // Evict expired entries and enforce MAX_URL_ENTRIES
        val now = System.currentTimeMillis()
        val iterator = map.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (now - entry.value > DEFAULT_URL_TTL_MILLIS) {
                iterator.remove()
            }
        }
        if (map.size > MAX_URL_ENTRIES) {
            val oldestKey = map.minByOrNull { it.value }?.key
            if (oldestKey != null) map.remove(oldestKey)
        }

        val json = JSONObject()
        for ((k, v) in map) {
            json.put(k, v)
        }
        prefs.edit().putString(KEY_URL_TIMESTAMPS, json.toString()).apply()
    }

    private fun removeUrlFromPrefs(context: Context, url: String) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val map = getUrlTimestampsFromPrefs(context).toMutableMap()
        if (map.remove(url) != null) {
            val json = JSONObject()
            for ((k, v) in map) {
                json.put(k, v)
            }
            prefs.edit().putString(KEY_URL_TIMESTAMPS, json.toString()).apply()
        }
    }
}