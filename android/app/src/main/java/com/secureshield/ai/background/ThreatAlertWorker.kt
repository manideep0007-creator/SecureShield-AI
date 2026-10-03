package com.secureshield.ai.background

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.google.android.gms.auth.api.signin.GoogleSignIn
import com.google.android.gms.common.api.Scope
import com.google.api.services.gmail.GmailScopes
import com.secureshield.ai.GmailFetchResult
import com.secureshield.ai.GmailScanner
import com.secureshield.ai.MainActivity
import com.secureshield.ai.R
import com.secureshield.ai.history.ScanHistoryRepository
import com.secureshield.ai.network.ApiClient
import com.secureshield.ai.network.ScanInput
import com.secureshield.ai.network.UnifiedScanResponse
import com.secureshield.ai.network.UnifiedScanResponseParser
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class ThreatAlertWorker(
    appContext: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(appContext, workerParams) {

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        val success = BackgroundScanner.execute(object : BackgroundDependencies {
            override val isEnabled: Boolean
                get() = BackgroundProtectionManager.isEnabled(applicationContext)
            
            override val accountActive: Boolean
                get() {
                    val account = GoogleSignIn.getLastSignedInAccount(applicationContext)
                    return account != null && GoogleSignIn.hasPermissions(account, Scope(GmailScopes.GMAIL_READONLY))
                }

            override fun updateLastCheck() {
                BackgroundProtectionManager.updateLastCheck(applicationContext)
            }

            override suspend fun fetchUnreadMessages(): GmailFetchResult {
                val account = GoogleSignIn.getLastSignedInAccount(applicationContext) ?: throw Exception("No account")
                return GmailScanner(applicationContext, account).fetchUnreadMessages()
            }

            override fun isProcessed(messageId: String): Boolean =
                ProcessedMessageStore.isProcessed(applicationContext, messageId)

            override fun markProcessed(messageId: String) {
                ProcessedMessageStore.markProcessed(applicationContext, messageId)
            }

            override suspend fun scan(input: ScanInput): UnifiedScanResponse? {
                val response = ApiClient.api.scan(input)
                if (response.isSuccessful) {
                    val body = response.body() ?: return null
                    return UnifiedScanResponseParser.parse(body)
                }
                throw Exception("HTTP Error")
            }

            override suspend fun saveHistory(result: UnifiedScanResponse, source: String) {
                val repo = ScanHistoryRepository(applicationContext)
                repo.saveCompletedScan(result, source)
                repo.close()
            }

            override fun notifyThreat(classification: String, score: Float, action: String, scanId: String) {
                sendThreatNotification(classification, score, action, scanId)
            }
        })

        if (success) Result.success() else Result.retry()
    }

    private fun sendThreatNotification(classification: String, riskScore: Float, recommendedAction: String, scanId: String) {
        try {
            val intent = Intent(applicationContext, com.secureshield.ai.ScanHistoryActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
                putExtra("scan_id", scanId)
            }
            val pendingIntent = PendingIntent.getActivity(
                applicationContext, scanId.hashCode(), intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )

            val safeMessage = "Threat detected (score: ${riskScore.toInt()}). $recommendedAction"

            val builder = NotificationCompat.Builder(applicationContext, "SS_ALERTS")
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle("Potential $classification detected")
                .setContentText(safeMessage)
                .setStyle(NotificationCompat.BigTextStyle().bigText(safeMessage))
                .setContentIntent(pendingIntent)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setAutoCancel(true)
            
            val notificationId = scanId.hashCode()
            NotificationManagerCompat.from(applicationContext).notify(notificationId, builder.build())
        } catch (e: SecurityException) {
            // Missing notification permission, fail gracefully
        }
    }
}