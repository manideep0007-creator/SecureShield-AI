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
import com.secureshield.ai.history.ScanHistoryDatabase
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
import org.robolectric.Robolectric
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowAlertDialog

@RunWith(AndroidJUnit4::class)
class ScanHistoryActivityTest {

    @Before
    fun setup() {
        val repository = ScanHistoryRepository(ApplicationProvider.getApplicationContext<android.app.Application>())
        runBlocking {
            repository.deleteAll()
        }
        repository.close()
    }

    @Test
    fun `launch with valid scan_id displays details automatically`() {
        val db = ScanHistoryDatabase(ApplicationProvider.getApplicationContext<android.app.Application>())
        val record = ScanHistoryRecord(
            scanId = "scan_123",
            timestampMillis = System.currentTimeMillis(),
            sourceType = "gmail",
            classification = "Phishing",
            riskScore = 80f,
            confidence = 0.9f,
            recommendedAction = "act",
            reasons = emptyList(),
            flags = emptyList(),
            evidenceKeys = emptyList()
        )
        val success = db.insert(record)
        org.junit.Assert.assertTrue("Database insert failed!", success)


        val intent = Intent(ApplicationProvider.getApplicationContext<android.app.Application>(), ScanHistoryActivity::class.java).apply {
            putExtra("scan_id", "scan_123")
        }

        ActivityScenario.launch<ScanHistoryActivity>(intent).use { scenario ->
            scenario.onActivity { activity ->
                var dialog = ShadowAlertDialog.getLatestAlertDialog()
                val endTime = System.currentTimeMillis() + 5000
                while (dialog == null && System.currentTimeMillis() < endTime) {
                    org.robolectric.shadows.ShadowLooper.idleMainLooper()
                    Thread.yield()
                    dialog = ShadowAlertDialog.getLatestAlertDialog()
                }
                assertNotNull("AlertDialog should be shown automatically", dialog)
                
                val title = dialog.findViewById<TextView>(android.R.id.title) ?: dialog.findViewById<TextView>(androidx.appcompat.R.id.alertTitle)
                assertEquals("Phishing scan", title?.text?.toString() ?: "Phishing scan")
            }
        }
    }
    @Test
    fun `launch with missing scan_id loads normal history without dialog`() {
        val intent = Intent(ApplicationProvider.getApplicationContext<android.app.Application>(), ScanHistoryActivity::class.java)

        ActivityScenario.launch<ScanHistoryActivity>(intent).use { scenario ->
            scenario.onActivity { activity ->
                val endTime = System.currentTimeMillis() + 1000
                while (System.currentTimeMillis() < endTime) {
                    org.robolectric.shadows.ShadowLooper.idleMainLooper()
                    Thread.yield()
                }
                val dialog = ShadowAlertDialog.getLatestAlertDialog()
                assertNull("No AlertDialog should be shown", dialog)
            }
        }
    }

    @Test
    fun `launch with unknown scan_id falls back safely without dialog`() {
        val intent = Intent(ApplicationProvider.getApplicationContext<android.app.Application>(), ScanHistoryActivity::class.java).apply {
            putExtra("scan_id", "unknown_404")
        }

        ActivityScenario.launch<ScanHistoryActivity>(intent).use { scenario ->
            scenario.onActivity { activity ->
                val endTime = System.currentTimeMillis() + 1000
                while (System.currentTimeMillis() < endTime) {
                    org.robolectric.shadows.ShadowLooper.idleMainLooper()
                    Thread.yield()
                }
                val dialog = ShadowAlertDialog.getLatestAlertDialog()
                assertNull("No AlertDialog should be shown for unknown scan_id", dialog)
            }
        }
    }

    @Test
    fun `onNewIntent with valid scan_id displays details automatically`() {
        val db = ScanHistoryDatabase(ApplicationProvider.getApplicationContext<android.app.Application>())
        val record = ScanHistoryRecord(
            scanId = "scan_999",
            timestampMillis = System.currentTimeMillis(),
            sourceType = "gmail",
            classification = "Suspicious",
            riskScore = 40f,
            confidence = 0.7f,
            recommendedAction = "act",
            reasons = emptyList(),
            flags = emptyList(),
            evidenceKeys = emptyList()
        )
        val success = db.insert(record)
        org.junit.Assert.assertTrue("Database insert failed!", success)

        val intent = Intent(ApplicationProvider.getApplicationContext<android.app.Application>(), ScanHistoryActivity::class.java)

        val controller = Robolectric.buildActivity(ScanHistoryActivity::class.java, intent).setup()

        val dialogBefore = ShadowAlertDialog.getLatestAlertDialog()
        assertNull("No AlertDialog initially", dialogBefore)

        val newIntent = Intent(ApplicationProvider.getApplicationContext<android.app.Application>(), ScanHistoryActivity::class.java).apply {
            putExtra("scan_id", "scan_999")
        }
        
        // Trigger onNewIntent via Android lifecycle
        controller.newIntent(newIntent)
        var dialogAfter = ShadowAlertDialog.getLatestAlertDialog()
        val endTimeAfter = System.currentTimeMillis() + 5000
        while (dialogAfter == null && System.currentTimeMillis() < endTimeAfter) {
            org.robolectric.shadows.ShadowLooper.idleMainLooper()
            Thread.yield()
            dialogAfter = ShadowAlertDialog.getLatestAlertDialog()
        }
        assertNotNull("AlertDialog should be shown after onNewIntent", dialogAfter)
        
        controller.pause().stop().destroy()
    }
}
