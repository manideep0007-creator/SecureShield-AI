package com.secureshield.ai.history

import android.content.Context
import com.secureshield.ai.network.UnifiedScanResponse
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class ScanHistoryRepository(
    private val store: ScanHistoryStore,
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO
) {
    constructor(context: Context) : this(AndroidScanHistoryStore(ScanHistoryDatabase(context)))
    constructor(context: Context, databaseName: String) : this(AndroidScanHistoryStore(ScanHistoryDatabase(context, databaseName)))

    suspend fun saveCompletedScan(result: UnifiedScanResponse, sourceType: String): Boolean = withContext(dispatcher) {
        runCatching {
            val record = ScanHistorySanitizer.fromResponse(result, sourceType) ?: return@runCatching false
            store.insert(record)
        }.getOrDefault(false)
    }

    suspend fun getPage(limit: Int = ScanHistorySanitizer.DEFAULT_PAGE_SIZE, offset: Int = 0, filter: ScanHistoryFilter = ScanHistoryFilter()): List<ScanHistoryRecord> =
        withContext(dispatcher) {
            val safeLimit = limit.coerceIn(1, ScanHistorySanitizer.MAX_PAGE_SIZE)
            val safeOffset = offset.coerceAtLeast(0)
            runCatching { store.getPage(safeLimit, safeOffset, filter) }.getOrDefault(emptyList())
        }

    suspend fun getById(scanId: String): ScanHistoryRecord? =
        withContext(dispatcher) { runCatching { store.getById(scanId) }.getOrNull() }

    suspend fun delete(scanId: String): Boolean =
        withContext(dispatcher) { runCatching { store.delete(scanId) }.getOrDefault(false) }

    suspend fun deleteAll(): Boolean =
        withContext(dispatcher) { runCatching { store.deleteAll(); true }.getOrDefault(false) }

    suspend fun updateFeedbackState(scanId: String, feedbackState: String): Boolean =
        withContext(dispatcher) {
            if (feedbackState !in FEEDBACK_STATES) return@withContext false
            runCatching { store.updateFeedbackState(scanId, feedbackState) }.getOrDefault(false)
        }

    fun close() {
        runCatching { store.close() }
    }
}

interface ScanHistoryStore {
    fun insert(record: ScanHistoryRecord): Boolean
    fun getPage(limit: Int, offset: Int, filter: ScanHistoryFilter): List<ScanHistoryRecord>
    fun getById(scanId: String): ScanHistoryRecord?
    fun delete(scanId: String): Boolean
    fun deleteAll()
    fun updateFeedbackState(scanId: String, feedbackState: String): Boolean
    fun close() = Unit
}

private class AndroidScanHistoryStore(private val database: ScanHistoryDatabase) : ScanHistoryStore {
    override fun insert(record: ScanHistoryRecord) = database.insert(record)
    override fun getPage(limit: Int, offset: Int, filter: ScanHistoryFilter) = database.getPage(limit, offset, filter)
    override fun getById(scanId: String) = database.getById(scanId)
    override fun delete(scanId: String) = database.delete(scanId)
    override fun deleteAll() { database.deleteAll() }
    override fun updateFeedbackState(scanId: String, feedbackState: String) = database.updateFeedbackState(scanId, feedbackState)
    override fun close() = database.close()
}

private val FEEDBACK_STATES = setOf("positive", "negative")