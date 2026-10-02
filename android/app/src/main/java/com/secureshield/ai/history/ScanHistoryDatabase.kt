package com.secureshield.ai.history

import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

object ScanHistorySchema {
    const val TABLE_HISTORY = "scan_history"
    const val COLUMN_SCAN_ID = "scan_id"
    const val COLUMN_TIMESTAMP = "timestamp_millis"
    const val COLUMN_SOURCE_TYPE = "source_type"
    const val COLUMN_CLASSIFICATION = "classification"
    const val COLUMN_RISK_SCORE = "risk_score"
    const val COLUMN_CONFIDENCE = "confidence"
    const val COLUMN_RECOMMENDED_ACTION = "recommended_action"
    const val COLUMN_REASONS = "reasons_json"
    const val COLUMN_FLAGS = "flags_json"
    const val COLUMN_EVIDENCE_KEYS = "evidence_keys_json"
    const val COLUMN_FEEDBACK_STATE = "feedback_state"

    const val CREATE_HISTORY_TABLE = """CREATE TABLE IF NOT EXISTS scan_history (
        scan_id TEXT PRIMARY KEY NOT NULL,
        timestamp_millis INTEGER NOT NULL,
        source_type TEXT NOT NULL CHECK (source_type IN ('url','file','share','gmail','unknown')),
        classification TEXT NOT NULL CHECK (classification IN ('Safe','Suspicious','Deceptive','Phishing','Malware')),
        risk_score REAL NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
        confidence REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
        recommended_action TEXT NOT NULL,
        reasons_json TEXT NOT NULL,
        flags_json TEXT NOT NULL,
        evidence_keys_json TEXT NOT NULL DEFAULT '[]',
        feedback_state TEXT CHECK (feedback_state IS NULL OR feedback_state IN ('positive','negative'))
    )"""

    val CREATE_INDEX_STATEMENTS = listOf(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_history_scan_id ON scan_history(scan_id)",
        "CREATE INDEX IF NOT EXISTS idx_scan_history_timestamp ON scan_history(timestamp_millis DESC)",
        "CREATE INDEX IF NOT EXISTS idx_scan_history_classification ON scan_history(classification, timestamp_millis DESC)",
        "CREATE INDEX IF NOT EXISTS idx_scan_history_source ON scan_history(source_type, timestamp_millis DESC)"
    )

    fun upgradeStatements(oldVersion: Int, columns: Set<String>): List<String> = buildList {
        if (oldVersion < 2 && COLUMN_EVIDENCE_KEYS !in columns) {
            add("ALTER TABLE $TABLE_HISTORY ADD COLUMN $COLUMN_EVIDENCE_KEYS TEXT NOT NULL DEFAULT '[]'")
        }
        if (oldVersion < 3 && COLUMN_FEEDBACK_STATE !in columns) {
            add("ALTER TABLE $TABLE_HISTORY ADD COLUMN $COLUMN_FEEDBACK_STATE TEXT")
        }
    }
}

class ScanHistoryDatabase(
    context: Context,
    databaseName: String = DATABASE_NAME
) : SQLiteOpenHelper(context.applicationContext, databaseName, null, DATABASE_VERSION) {

    override fun onCreate(db: SQLiteDatabase) {
        createHistoryTable(db)
        createIndexes(db)
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        if (!tableExists(db, TABLE_HISTORY)) createHistoryTable(db)
        val columns = getColumns(db, TABLE_HISTORY)
        ScanHistorySchema.upgradeStatements(oldVersion, columns).forEach(db::execSQL)
        createIndexes(db)
    }

    fun insert(record: ScanHistoryRecord): Boolean {
        val values = record.toContentValues()
        return writableDatabase.insertWithOnConflict(TABLE_HISTORY, null, values, SQLiteDatabase.CONFLICT_IGNORE) != -1L
    }

    fun getById(scanId: String): ScanHistoryRecord? = readableDatabase.query(
        TABLE_HISTORY,
        null,
        "$COLUMN_SCAN_ID = ?",
        arrayOf(scanId),
        null,
        null,
        null,
        "1"
    ).use { cursor -> if (cursor.moveToFirst()) cursor.toRecordOrNull() else null }

    fun getPage(limit: Int, offset: Int, filter: ScanHistoryFilter = ScanHistoryFilter()): List<ScanHistoryRecord> {
        val safeLimit = limit.coerceIn(1, ScanHistorySanitizer.MAX_PAGE_SIZE)
        val safeOffset = offset.coerceAtLeast(0)
        val conditions = mutableListOf<String>()
        val args = mutableListOf<String>()
        filter.classification?.takeIf { it in CLASSIFICATIONS }?.let {
            conditions += "$COLUMN_CLASSIFICATION = ?"
            args += it
        }
        filter.sourceType?.lowercase()?.takeIf { it in SOURCE_TYPES }?.let {
            conditions += "$COLUMN_SOURCE_TYPE = ?"
            args += it
        }
        val selection = conditions.takeIf { it.isNotEmpty() }?.joinToString(" AND ")
        return readableDatabase.query(
            TABLE_HISTORY,
            null,
            selection,
            args.toTypedArray().takeIf { selection != null },
            null,
            null,
            "$COLUMN_TIMESTAMP DESC, $COLUMN_SCAN_ID DESC",
            "$safeLimit OFFSET $safeOffset"
        ).use { cursor ->
            buildList {
                while (cursor.moveToNext()) cursor.toRecordOrNull()?.let(::add)
            }
        }
    }

    fun delete(scanId: String): Boolean = writableDatabase.delete(
        TABLE_HISTORY,
        "$COLUMN_SCAN_ID = ?",
        arrayOf(scanId)
    ) > 0

    fun deleteAll(): Int = writableDatabase.delete(TABLE_HISTORY, null, null)

    fun updateFeedbackState(scanId: String, feedbackState: String): Boolean {
        if (feedbackState !in FEEDBACK_STATES) return false
        val values = ContentValues().apply { put(COLUMN_FEEDBACK_STATE, feedbackState) }
        return writableDatabase.update(TABLE_HISTORY, values, "$COLUMN_SCAN_ID = ?", arrayOf(scanId)) > 0
    }

    private fun createHistoryTable(db: SQLiteDatabase) {
        db.execSQL(ScanHistorySchema.CREATE_HISTORY_TABLE)
    }

    private fun createIndexes(db: SQLiteDatabase) {
        ScanHistorySchema.CREATE_INDEX_STATEMENTS.forEach(db::execSQL)
    }

    private fun tableExists(db: SQLiteDatabase, table: String): Boolean = db.rawQuery(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", arrayOf(table)
    ).use { it.moveToFirst() }

    private fun getColumns(db: SQLiteDatabase, table: String): Set<String> =
        db.rawQuery("PRAGMA table_info($table)", null).use { cursor ->
            val nameIndex = cursor.getColumnIndex("name")
            buildSet {
                while (cursor.moveToNext()) if (nameIndex >= 0) add(cursor.getString(nameIndex))
            }
        }

    private fun ScanHistoryRecord.toContentValues() = ContentValues().apply {
        put(COLUMN_SCAN_ID, scanId)
        put(COLUMN_TIMESTAMP, timestampMillis)
        put(COLUMN_SOURCE_TYPE, sourceType)
        put(COLUMN_CLASSIFICATION, classification)
        put(COLUMN_RISK_SCORE, riskScore.toDouble())
        put(COLUMN_CONFIDENCE, confidence.toDouble())
        put(COLUMN_RECOMMENDED_ACTION, recommendedAction)
        put(COLUMN_REASONS, ScanHistorySanitizer.encode(reasons))
        put(COLUMN_FLAGS, ScanHistorySanitizer.encode(flags))
        put(COLUMN_EVIDENCE_KEYS, ScanHistorySanitizer.encode(evidenceKeys))
        feedbackState?.let { put(COLUMN_FEEDBACK_STATE, it) }
    }

    private fun Cursor.toRecordOrNull(): ScanHistoryRecord? = try {
        val feedbackIndex = getColumnIndex(COLUMN_FEEDBACK_STATE)
        ScanHistoryRecord(
            scanId = getString(getColumnIndexOrThrow(COLUMN_SCAN_ID)),
            timestampMillis = getLong(getColumnIndexOrThrow(COLUMN_TIMESTAMP)),
            sourceType = getString(getColumnIndexOrThrow(COLUMN_SOURCE_TYPE)),
            classification = getString(getColumnIndexOrThrow(COLUMN_CLASSIFICATION)),
            riskScore = getFloat(getColumnIndexOrThrow(COLUMN_RISK_SCORE)),
            confidence = getFloat(getColumnIndexOrThrow(COLUMN_CONFIDENCE)),
            recommendedAction = getString(getColumnIndexOrThrow(COLUMN_RECOMMENDED_ACTION)),
            reasons = ScanHistorySanitizer.decode(getString(getColumnIndexOrThrow(COLUMN_REASONS))),
            flags = ScanHistorySanitizer.decode(getString(getColumnIndexOrThrow(COLUMN_FLAGS))),
            evidenceKeys = ScanHistorySanitizer.decode(getString(getColumnIndexOrThrow(COLUMN_EVIDENCE_KEYS))),
            feedbackState = if (feedbackIndex >= 0) getString(feedbackIndex)?.takeIf(FEEDBACK_STATES::contains) else null
        )
    } catch (_: Exception) {
        null
    }

    private companion object {
        const val DATABASE_NAME = "secure_scan_history.db"
        const val DATABASE_VERSION = 3
        const val TABLE_HISTORY = ScanHistorySchema.TABLE_HISTORY
        const val COLUMN_SCAN_ID = ScanHistorySchema.COLUMN_SCAN_ID
        const val COLUMN_TIMESTAMP = ScanHistorySchema.COLUMN_TIMESTAMP
        const val COLUMN_SOURCE_TYPE = ScanHistorySchema.COLUMN_SOURCE_TYPE
        const val COLUMN_CLASSIFICATION = ScanHistorySchema.COLUMN_CLASSIFICATION
        const val COLUMN_RISK_SCORE = ScanHistorySchema.COLUMN_RISK_SCORE
        const val COLUMN_CONFIDENCE = ScanHistorySchema.COLUMN_CONFIDENCE
        const val COLUMN_RECOMMENDED_ACTION = ScanHistorySchema.COLUMN_RECOMMENDED_ACTION
        const val COLUMN_REASONS = ScanHistorySchema.COLUMN_REASONS
        const val COLUMN_FLAGS = ScanHistorySchema.COLUMN_FLAGS
        const val COLUMN_EVIDENCE_KEYS = ScanHistorySchema.COLUMN_EVIDENCE_KEYS
        const val COLUMN_FEEDBACK_STATE = ScanHistorySchema.COLUMN_FEEDBACK_STATE
        val CLASSIFICATIONS = setOf("Safe", "Suspicious", "Deceptive", "Phishing", "Malware")
        val SOURCE_TYPES = setOf("url", "file", "share", "gmail", "unknown")
        val FEEDBACK_STATES = setOf("positive", "negative")
    }
}