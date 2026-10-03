package com.secureshield.ai

import android.app.AlertDialog
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

    private fun createHistoryRow(record: ScanHistoryRecord): View = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(12, 12, 12, 12)

        val summary = TextView(this@ScanHistoryActivity).apply {
            text = "${record.sourceType.uppercase()}  •  ${formatTimestamp(record.timestampMillis)}\n" +
                "${record.classification}  •  Risk ${formatNumber(record.riskScore)}  •  Confidence ${formatPercent(record.confidence)}"
            textSize = 16f
            setOnClickListener { showDetails(record) }
        }
        addView(summary)

        val actions = LinearLayout(this@ScanHistoryActivity).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.END
        }
        actions.addView(Button(this@ScanHistoryActivity).apply {
            text = "Details"
            setOnClickListener { showDetails(record) }
        })
        actions.addView(Button(this@ScanHistoryActivity).apply {
            text = "Delete"
            setOnClickListener { confirmDelete(record) }
        })
        addView(actions)
        addView(View(this@ScanHistoryActivity).apply {
            setBackgroundColor(0xFFE0E0E0.toInt())
            layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 1)
        })
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

    private fun formatNumber(value: Float): String = "%.1f".format(value)

    private fun formatPercent(value: Float): String = "%.0f%%".format(value * 100)

    override fun onDestroy() {
        if (repositoryDelegate.isInitialized()) repository.close()
        super.onDestroy()
    }
}