package com.secureshield.ai

import android.app.AlertDialog
import android.content.Intent
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.secureshield.ai.history.ScanHistoryRecord
import com.secureshield.ai.history.ScanHistoryRepository
import kotlinx.coroutines.launch
import java.text.DateFormat
import java.util.Date

class ScanHistoryActivity : AppCompatActivity() {
    private lateinit var historyContainer: LinearLayout
    private lateinit var emptyMessage: TextView
    private lateinit var loadMoreButton: Button
    private val repositoryDelegate = lazy { ScanHistoryRepository(applicationContext) }
    private val repository by repositoryDelegate
    private val displayedRecords = mutableListOf<ScanHistoryRecord>()
    private var loading = false
    private var hasMore = true

    private var pendingScanId: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_scan_history)
        historyContainer = findViewById(R.id.scan_history_items)
        emptyMessage = findViewById(R.id.scan_history_empty)
        loadMoreButton = findViewById(R.id.scan_history_load_more)

        findViewById<Button>(R.id.scan_history_back).setOnClickListener { finish() }
        findViewById<Button>(R.id.scan_history_clear_all).setOnClickListener { confirmDeleteAll() }
        loadMoreButton.setOnClickListener { loadNextPage() }
        
        pendingScanId = intent?.getStringExtra("scan_id")
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        setIntent(intent)
        pendingScanId = intent?.getStringExtra("scan_id")
        checkPendingScanAndReload()
    }

    override fun onResume() {
        super.onResume()
        checkPendingScanAndReload()
    }

    private fun checkPendingScanAndReload() {
        val scanId = pendingScanId
        pendingScanId = null
        
        if (scanId != null) {
            lifecycleScope.launch {
                val record = repository.getById(scanId)
                reloadHistory()
                if (record != null) {
                    showDetails(record)
                }
            }
        } else {
            reloadHistory()
        }
    }

    private fun reloadHistory() {
        displayedRecords.clear()
        historyContainer.removeAllViews()
        hasMore = true
        loadMoreButton.visibility = View.GONE
        loadNextPage()
    }

    private fun loadNextPage() {
        if (loading || !hasMore) return
        loading = true
        lifecycleScope.launch {
            val offset = displayedRecords.size
            val page = repository.getPage(offset = offset)
            page.forEach { record ->
                displayedRecords += record
                historyContainer.addView(createHistoryRow(record))
            }
            hasMore = page.size == com.secureshield.ai.history.ScanHistorySanitizer.DEFAULT_PAGE_SIZE
            emptyMessage.visibility = if (displayedRecords.isEmpty()) View.VISIBLE else View.GONE
            loadMoreButton.visibility = if (hasMore) View.VISIBLE else View.GONE
            loading = false
        }
    }

    private fun createHistoryRow(record: ScanHistoryRecord): View {
        val row = layoutInflater.inflate(R.layout.item_history_card, historyContainer, false)
        val textSourceDate = row.findViewById<TextView>(R.id.history_item_source_and_date)
        val badge = row.findViewById<TextView>(R.id.history_item_badge)
        val textSummary = row.findViewById<TextView>(R.id.history_item_summary)
        val btnDetails = row.findViewById<View>(R.id.history_item_btn_details)
        val btnDelete = row.findViewById<View>(R.id.history_item_btn_delete)

        textSourceDate.text = "${record.sourceType.uppercase()} • ${formatTimestamp(record.timestampMillis)}"
        badge.text = record.classification.uppercase()

        when (record.classification.lowercase()) {
            "safe" -> {
                badge.setBackgroundResource(R.drawable.bg_badge_safe)
                badge.setTextColor(0xFF10B981.toInt())
            }
            "suspicious", "deceptive" -> {
                badge.setBackgroundResource(R.drawable.bg_badge_warning)
                badge.setTextColor(0xFFF59E0B.toInt())
            }
            "phishing", "malware" -> {
                badge.setBackgroundResource(R.drawable.bg_badge_threat)
                badge.setTextColor(0xFFEF4444.toInt())
            }
            else -> {
                badge.setBackgroundResource(R.drawable.bg_badge_neutral)
                badge.setTextColor(0xFFFFFFFF.toInt())
            }
        }

        textSummary.text = "Risk: ${formatNumber(record.riskScore)}/100 • Conf: ${formatPercent(record.confidence)}"
        btnDetails.setOnClickListener { showDetails(record) }
        btnDelete.setOnClickListener { confirmDelete(record) }
        row.setOnClickListener { showDetails(record) }
        return row
    }

    private fun showDetails(record: ScanHistoryRecord) {
        val details = buildString {
            appendLine("Classification: ${record.classification}")
            appendLine("Risk score: ${formatNumber(record.riskScore)} / 100")
            appendLine("Confidence: ${formatPercent(record.confidence)}")
            appendLine("Source: ${record.sourceType}")
            appendLine("Scanned: ${formatTimestamp(record.timestampMillis)}")
            appendLine("Feedback: ${record.feedbackState ?: "Not submitted locally"}")
            appendLine()
            appendLine("Reasons:")
            if (record.reasons.isEmpty()) appendLine("None") else record.reasons.forEach { appendLine("• $it") }
            appendLine()
            appendLine("Recommended action:")
            appendLine(record.recommendedAction.ifBlank { "None" })
            appendLine()
            appendLine("Flags:")
            appendLine(record.flags.takeIf(List<String>::isNotEmpty)?.joinToString() ?: "None")
            appendLine()
            appendLine("Evidence keys:")
            appendLine(record.evidenceKeys.takeIf(List<String>::isNotEmpty)?.joinToString() ?: "None")
        }
        AlertDialog.Builder(this)
            .setTitle("${record.classification} scan")
            .setMessage(details)
            .setPositiveButton("Close", null)
            .show()
    }

    private fun confirmDelete(record: ScanHistoryRecord) {
        AlertDialog.Builder(this)
            .setTitle("Delete scan history?")
            .setMessage("This removes the local history entry only. Backend feedback is kept.")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Delete") { _, _ ->
                lifecycleScope.launch {
                    if (repository.delete(record.scanId)) reloadHistory()
                    else Toast.makeText(this@ScanHistoryActivity, "History entry could not be deleted.", Toast.LENGTH_SHORT).show()
                }
            }
            .show()
    }

    private fun confirmDeleteAll() {
        AlertDialog.Builder(this)
            .setTitle("Delete all scan history?")
            .setMessage("This permanently removes local history entries only. Feedback stored by the backend is not deleted.")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Delete all") { _, _ ->
                lifecycleScope.launch {
                    if (repository.deleteAll()) reloadHistory()
                    else Toast.makeText(this@ScanHistoryActivity, "History could not be deleted.", Toast.LENGTH_SHORT).show()
                }
            }
            .show()
    }

    private fun formatTimestamp(timestampMillis: Long): String =
        DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(timestampMillis))

    private fun formatNumber(value: Float): String = String.format(java.util.Locale.US, "%.1f", value)

    private fun formatPercent(value: Float): String = String.format(java.util.Locale.US, "%.0f%%", value * 100)

    override fun onDestroy() {
        if (repositoryDelegate.isInitialized()) repository.close()
        super.onDestroy()
    }
}