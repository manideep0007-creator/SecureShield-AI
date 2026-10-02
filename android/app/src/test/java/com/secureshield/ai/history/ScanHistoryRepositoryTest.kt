package com.secureshield.ai.history

import com.google.gson.Gson
import com.secureshield.ai.network.EvidenceItem
import com.secureshield.ai.network.RiskAssessment
import com.secureshield.ai.network.UnifiedScanResponse
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.sql.DriverManager
import java.util.UUID

class ScanHistoryRepositoryTest {
    @Test
    fun `successful insertion and duplicate scan prevention`() = runTest {
        val fixture = fixture()
        val result = response(ID_A)

        assertTrue(fixture.repository.saveCompletedScan(result, "url"))
        assertFalse(fixture.repository.saveCompletedScan(result, "url"))
        assertEquals(1, fixture.repository.getPage().size)
    }

    @Test
    fun `retrieval is newest first and supports lookup by scan id`() = runTest {
        val fixture = fixture()
        fixture.store.insert(record(ID_A, 100))
        fixture.store.insert(record(ID_B, 200))

        val page = fixture.repository.getPage()
        assertEquals(listOf(ID_B, ID_A), page.map { it.scanId })
        assertEquals(ID_A, fixture.repository.getById(ID_A)?.scanId)
        assertNull(fixture.repository.getById(ID_C))
    }

    @Test
    fun `classification and source filters are applied safely`() = runTest {
        val fixture = fixture()
        fixture.store.insert(record(ID_A, 100, "Safe", "url"))
        fixture.store.insert(record(ID_B, 200, "Phishing", "gmail"))
        fixture.store.insert(record(ID_C, 300, "Phishing", "share"))

        assertEquals(2, fixture.repository.getPage(filter = ScanHistoryFilter(classification = "Phishing")).size)
        assertEquals(ID_B, fixture.repository.getPage(filter = ScanHistoryFilter(sourceType = "gmail")).single().scanId)
        assertEquals(ID_B, fixture.repository.getPage(filter = ScanHistoryFilter("Phishing", "gmail")).single().scanId)
        assertEquals(3, fixture.repository.getPage(filter = ScanHistoryFilter(sourceType = "gmail' OR 1=1 --")).size)
    }

    @Test
    fun `history retrieval is limited and paginated`() = runTest {
        val fixture = fixture()
        (1..105).forEach { index -> fixture.store.insert(record(uuid(index), index.toLong())) }

        val firstPage = fixture.repository.getPage(limit = 3, offset = 0)
        val secondPage = fixture.repository.getPage(limit = 3, offset = 3)
        assertEquals(3, firstPage.size)
        assertEquals(3, secondPage.size)
        assertTrue(firstPage.map { it.scanId }.intersect(secondPage.map { it.scanId }.toSet()).isEmpty())
        assertEquals(1, fixture.repository.getPage(limit = 0).size)
        assertEquals(ScanHistorySanitizer.MAX_PAGE_SIZE, fixture.repository.getPage(limit = 1000).size)
    }

    @Test
    fun `individual deletion only removes selected history`() = runTest {
        val fixture = fixture()
        fixture.store.insert(record(ID_A, 100))
        fixture.store.insert(record(ID_B, 200))

        assertTrue(fixture.repository.delete(ID_A))
        assertNull(fixture.repository.getById(ID_A))
        assertNotNull(fixture.repository.getById(ID_B))
    }

    @Test
    fun `delete all and empty history are safe`() = runTest {
        val fixture = fixture()
        assertTrue(fixture.repository.getPage().isEmpty())
        assertNull(fixture.repository.getById(ID_A))
        fixture.store.insert(record(ID_A, 100))

        assertTrue(fixture.repository.deleteAll())
        assertTrue(fixture.repository.getPage().isEmpty())
    }

    @Test
    fun `malformed serialized summaries are handled safely`() {
        assertTrue(ScanHistorySanitizer.decode("{broken").isEmpty())
        assertEquals(listOf("valid"), ScanHistorySanitizer.decode(Gson().toJson(listOf("valid"))))
    }

    @Test
    fun `history write failure does not alter the successful scan result`() = runTest {
        val result = response(ID_A)
        val repository = ScanHistoryRepository(FailingStore, Dispatchers.Unconfined)

        assertFalse(repository.saveCompletedScan(result, "url"))
        assertEquals(ID_A, result.scan_id)
        assertEquals(90f, result.risk_score)
        assertEquals("Phishing", result.classification)
    }

    @Test
    fun `sensitive body URLs emails and evidence values are never stored`() = runTest {
        val fixture = fixture()
        val privateBody = "private-gmail-body alice@example.test https://secret.example password=hunter2"

        assertTrue(fixture.repository.saveCompletedScan(response(ID_A, evidenceValue = privateBody), "gmail"))
        val serialized = Gson().toJson(fixture.repository.getById(ID_A))

        assertFalse(serialized.contains("private-gmail-body"))
        assertFalse(serialized.contains("alice@example.test"))
        assertFalse(serialized.contains("secret.example"))
        assertFalse(serialized.contains("hunter2"))
        assertFalse(serialized.contains("sensitive evidence"))
        assertTrue(serialized.contains("url_engine_evidence"))
    }

    @Test
    fun `feedback state is attached to one history row and removed locally only`() = runTest {
        val fixture = fixture()
        fixture.store.insert(record(ID_A, 100))

        assertTrue(fixture.repository.updateFeedbackState(ID_A, "positive"))
        assertFalse(fixture.repository.updateFeedbackState(ID_A, "up"))
        assertEquals(1, fixture.repository.getPage().size)
        assertEquals("positive", fixture.repository.getById(ID_A)?.feedbackState)
        assertTrue(fixture.repository.delete(ID_A))
        assertEquals(1, fixture.store.backendFeedbackRecords)
    }

    @Test
    fun `schema migration preserves existing scan and Phase12 feedback rows`() {
        val file = File.createTempFile("history-migration-", ".db")
        try {
            DriverManager.getConnection("jdbc:sqlite:${file.absolutePath}").use { connection ->
                connection.createStatement().use { statement ->
                    statement.execute(
                        """CREATE TABLE scan_history (
                            scan_id TEXT PRIMARY KEY NOT NULL,
                            timestamp_millis INTEGER NOT NULL,
                            source_type TEXT NOT NULL,
                            classification TEXT NOT NULL,
                            risk_score REAL NOT NULL,
                            confidence REAL NOT NULL,
                            recommended_action TEXT NOT NULL,
                            reasons_json TEXT NOT NULL,
                            flags_json TEXT NOT NULL
                        )""".trimIndent()
                    )
                    statement.execute("CREATE TABLE feedback (id INTEGER PRIMARY KEY, feedback_value TEXT NOT NULL)")
                }
                connection.prepareStatement(
                    "INSERT INTO scan_history VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
                ).use { insert ->
                    insert.setString(1, ID_A)
                    insert.setLong(2, 100)
                    insert.setString(3, "url")
                    insert.setString(4, "Safe")
                    insert.setDouble(5, 10.0)
                    insert.setDouble(6, 0.5)
                    insert.setString(7, "Caution")
                    insert.setString(8, "[]")
                    insert.setString(9, "[]")
                    insert.executeUpdate()
                }
                connection.createStatement().use { it.execute("INSERT INTO feedback VALUES (1, 'negative')") }

                val columns = connection.createStatement().use { statement ->
                    statement.executeQuery("PRAGMA table_info(scan_history)").use { rows ->
                        buildSet { while (rows.next()) add(rows.getString("name")) }
                    }
                }
                ScanHistorySchema.upgradeStatements(oldVersion = 1, columns = columns).forEach { sql ->
                    connection.createStatement().use { it.execute(sql) }
                }
                ScanHistorySchema.CREATE_INDEX_STATEMENTS.forEach { sql ->
                    connection.createStatement().use { it.execute(sql) }
                }

                val oldHistoryCount = connection.createStatement().use { statement ->
                    statement.executeQuery("SELECT COUNT(*) FROM scan_history").use { it.next(); it.getInt(1) }
                }
                val feedback = connection.createStatement().use { statement ->
                    statement.executeQuery("SELECT feedback_value FROM feedback WHERE id = 1").use { it.next(); it.getString(1) }
                }
                val indexes = connection.createStatement().use { statement ->
                    statement.executeQuery("PRAGMA index_list(scan_history)").use { rows ->
                        buildSet { while (rows.next()) add(rows.getString("name")) }
                    }
                }
                assertEquals(1, oldHistoryCount)
                assertEquals("negative", feedback)
                assertTrue(indexes.contains("idx_scan_history_scan_id"))
                assertTrue(indexes.contains("idx_scan_history_timestamp"))
            }
        } finally {
            file.delete()
        }
    }

    private fun fixture(): TestHistoryFixture {
        val store = MemoryHistoryStore()
        return TestHistoryFixture(store, ScanHistoryRepository(store, Dispatchers.Unconfined))
    }

    private fun record(id: String, timestamp: Long, classification: String = "Safe", source: String = "url") =
        ScanHistoryRecord(id, timestamp, source, classification, 25f, 0.75f, "Use caution.", listOf("Safe summary."), listOf("suspicious_tld"), listOf("url_engine_evidence"))

    private fun response(
        id: String,
        reasons: List<String> = listOf("Safe summary."),
        evidenceValue: String = "sensitive evidence"
    ) = UnifiedScanResponse(
        scan_id = id,
        status = "completed",
        results = emptyList(),
        total_engines = 0,
        completed_engines = 0,
        skipped_engines = 0,
        risk_assessment = RiskAssessment(90f, "Phishing", 0.9f, listOf("url_engine"), emptyList(), listOf("ip_based_host"), listOf(EvidenceItem("url_engine_evidence", evidenceValue, "private detail")), reasons, "Do not sign in."),
        risk_score = 90f,
        classification = "Phishing"
    )

    private fun uuid(value: Int) = "00000000-0000-4000-8000-${value.toString().padStart(12, '0')}"

    private data class TestHistoryFixture(val store: MemoryHistoryStore, val repository: ScanHistoryRepository)

    private class MemoryHistoryStore : ScanHistoryStore {
        private val rows = linkedMapOf<String, ScanHistoryRecord>()
        var backendFeedbackRecords = 1

        override fun insert(record: ScanHistoryRecord): Boolean {
            if (rows.containsKey(record.scanId)) return false
            rows[record.scanId] = record
            return true
        }

        override fun getPage(limit: Int, offset: Int, filter: ScanHistoryFilter): List<ScanHistoryRecord> = rows.values
            .filter { selected ->
                val classification = filter.classification?.takeIf { it in setOf("Safe", "Suspicious", "Deceptive", "Phishing", "Malware") }
                classification == null || selected.classification == classification
            }
            .filter { selected ->
                val source = filter.sourceType?.lowercase()?.takeIf { it in setOf("url", "file", "share", "gmail", "unknown") }
                source == null || selected.sourceType == source
            }
            .sortedWith(compareByDescending<ScanHistoryRecord> { it.timestampMillis }.thenByDescending { it.scanId })
            .drop(offset.coerceAtLeast(0))
            .take(limit.coerceIn(1, ScanHistorySanitizer.MAX_PAGE_SIZE))

        override fun getById(scanId: String): ScanHistoryRecord? = rows[scanId]
        override fun delete(scanId: String) = rows.remove(scanId) != null
        override fun deleteAll() { rows.clear() }
        override fun updateFeedbackState(scanId: String, feedbackState: String): Boolean {
            val record = rows[scanId] ?: return false
            rows[scanId] = record.copy(feedbackState = feedbackState)
            return true
        }
    }

    private object FailingStore : ScanHistoryStore {
        override fun insert(record: ScanHistoryRecord): Boolean = error("database unavailable")
        override fun getPage(limit: Int, offset: Int, filter: ScanHistoryFilter) = emptyList<ScanHistoryRecord>()
        override fun getById(scanId: String): ScanHistoryRecord? = null
        override fun delete(scanId: String) = false
        override fun deleteAll() = Unit
        override fun updateFeedbackState(scanId: String, feedbackState: String) = false
    }

    companion object {
        private const val ID_A = "11111111-1111-4111-8111-111111111111"
        private const val ID_B = "22222222-2222-4222-8222-222222222222"
        private const val ID_C = "33333333-3333-4333-8333-333333333333"
    }
}