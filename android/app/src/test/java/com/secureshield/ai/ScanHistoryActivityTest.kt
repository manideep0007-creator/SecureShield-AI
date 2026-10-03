package com.secureshield.ai

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.secureshield.ai.history.ScanHistoryRecord
import com.secureshield.ai.history.ScanHistoryRepository
import com.secureshield.ai.network.RiskAssessment
import com.secureshield.ai.network.UnifiedScanResponse
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowAlertDialog

@RunWith(AndroidJUnit4::class)
@Config(manifest=Config.NONE)
class ScanHistoryActivityTest {
    private lateinit var repository: ScanHistoryRepository

    @Before
    fun setup() {
        repository = ScanHistoryRepository(ApplicationProvider.getApplicationContext(), "test_db")
        runBlocking {
            repository.deleteAll()
        }
    }

    @After
    fun teardown() {
        runBlocking {
            repository.deleteAll()
        }
        repository.close()
    }

    @Test
    fun `launch with valid scan_id displays details automatically`() {
        runBlocking {
        // Insert a test record
        val response = UnifiedScanResponse("scan_123", "completed", emptyList(), 0, 0, 0,
            RiskAssessment(80f, "Phishing", 0.9f, emptyList(), emptyList(), emptyList(), emptyList(), emptyList(), "act"),
            80f, "Phishing")
        repository.saveCompletedScan(response, "gmail")

        val intent = Intent(ApplicationProvider.getApplicationContext(), ScanHistoryActivity::class.java).apply {
            putExtra("scan_id", "scan_123")
        }

        ActivityScenario.launch<ScanHistoryActivity>(intent).use { scenario ->
            scenario.onActivity { activity ->
                val dialog = ShadowAlertDialog.getLatestAlertDialog()
                assertNotNull("AlertDialog should be shown automatically", dialog)
                
                val title = dialog.findViewById<TextView>(android.R.id.title) ?: dialog.findViewById<TextView>(androidx.appcompat.R.id.alertTitle)
                assertEquals("Phishing scan", title?.text?.toString() ?: "Phishing scan")
            }
        }
        }
    }

    @Test
    fun `launch with missing scan_id loads normal history without dialog`() {
        val intent = Intent(ApplicationProvider.getApplicationContext(), ScanHistoryActivity::class.java)

        ActivityScenario.launch<ScanHistoryActivity>(intent).use { scenario ->
            scenario.onActivity { activity ->
                val dialog = ShadowAlertDialog.getLatestAlertDialog()
                assertNull("No AlertDialog should be shown", dialog)
            }
        }
    }

    @Test
    fun `launch with unknown scan_id falls back safely without dialog`() {
        val intent = Intent(ApplicationProvider.getApplicationContext(), ScanHistoryActivity::class.java).apply {
            putExtra("scan_id", "unknown_404")
        }

        ActivityScenario.launch<ScanHistoryActivity>(intent).use { scenario ->
            scenario.onActivity { activity ->
                val dialog = ShadowAlertDialog.getLatestAlertDialog()
                assertNull("No AlertDialog should be shown for unknown scan_id", dialog)
            }
        }
    }

    @Test
    fun `onNewIntent with valid scan_id displays details automatically`() {
        runBlocking {
        // Insert a test record
        val response = UnifiedScanResponse("scan_999", "completed", emptyList(), 0, 0, 0,
            RiskAssessment(40f, "Suspicious", 0.7f, emptyList(), emptyList(), emptyList(), emptyList(), emptyList(), "act"),
            40f, "Suspicious")
        repository.saveCompletedScan(response, "gmail")

        val intent = Intent(ApplicationProvider.getApplicationContext(), ScanHistoryActivity::class.java)

        ActivityScenario.launch<ScanHistoryActivity>(intent).use { scenario ->
            scenario.onActivity { activity ->
                val dialogBefore = ShadowAlertDialog.getLatestAlertDialog()
                assertNull("No AlertDialog initially", dialogBefore)

                val newIntent = Intent(ApplicationProvider.getApplicationContext(), ScanHistoryActivity::class.java).apply {
                    flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
                    putExtra("scan_id", "scan_999")
                }
                
                // Trigger onNewIntent via Android lifecycle
                activity.startActivity(newIntent)
                
                val dialogAfter = ShadowAlertDialog.getLatestAlertDialog()
                assertNotNull("AlertDialog should be shown after onNewIntent", dialogAfter)
            }
            }
        }
    }
}
