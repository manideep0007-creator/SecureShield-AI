package com.secureshield.ai

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.BadParcelableException
import android.provider.OpenableColumns
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.widget.SwitchCompat
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.lifecycle.lifecycleScope
import com.google.android.gms.auth.api.signin.GoogleSignIn
import com.google.android.gms.auth.api.signin.GoogleSignInOptions
import com.google.android.gms.auth.api.signin.GoogleSignInAccount
import com.google.android.gms.auth.api.signin.GoogleSignInStatusCodes
import com.google.android.gms.common.api.Scope
import com.google.api.services.gmail.GmailScopes
import com.secureshield.ai.network.ApiClient
import com.secureshield.ai.network.ScanInput
import com.secureshield.ai.network.UnifiedScanResponse
import com.secureshield.ai.network.FeedbackRequest
import com.secureshield.ai.network.MalformedScanResponseException
import com.secureshield.ai.network.UnifiedScanResponseParser
import com.secureshield.ai.network.fileBytesAsBackendJsonValue
import com.secureshield.ai.feedback.FeedbackSubmissionManager
import com.secureshield.ai.feedback.FeedbackSubmissionResult
import com.secureshield.ai.feedback.FeedbackSubmissionUiPolicy
import com.secureshield.ai.history.ScanHistoryRepository
import com.secureshield.ai.background.BackgroundProtectionManager
import com.secureshield.ai.share.ShareDispatchResult
import com.secureshield.ai.share.SharedFileReadResult
import com.secureshield.ai.share.SharedIntentPayload
import com.secureshield.ai.share.SharedIntentRouter
import com.google.gson.JsonParseException
import com.google.gson.stream.MalformedJsonException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.Job
import kotlinx.coroutines.withContext
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withTimeout
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.SocketTimeoutException

class MainActivity : AppCompatActivity() {

    private lateinit var badgeCategory: TextView
    private lateinit var textTarget: TextView
    private lateinit var textScore: TextView
    private lateinit var textReasons: TextView
    private lateinit var textAction: TextView
    private lateinit var progressBar: ProgressBar
    private lateinit var btnScanGmail: Button
    
    private lateinit var layoutFeedback: LinearLayout
    private lateinit var btnThumbUp: Button
    private lateinit var btnThumbDown: Button
    
    private var currentResult: UnifiedScanResponse? = null
    private var currentResultSourceType = "unknown"
    private var gmailScanInProgress = false
    private var gmailSessionInvalid = false
    private val feedbackSubmissionManager by lazy {
        FeedbackSubmissionManager { request -> ApiClient.api.sendFeedback(request) }
    }
    private val scanHistoryRepositoryDelegate = lazy { ScanHistoryRepository(applicationContext) }
    private val scanHistoryRepository by scanHistoryRepositoryDelegate

    private val googleSignInLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        var account: GoogleSignInAccount? = null
        var statusCode: Int? = null
        try {
            account = GoogleSignIn.getSignedInAccountFromIntent(result.data)
                .getResult(com.google.android.gms.common.api.ApiException::class.java)
        } catch (error: com.google.android.gms.common.api.ApiException) {
            statusCode = error.statusCode
        } catch (_: Exception) {
            statusCode = if (result.resultCode != RESULT_OK) GoogleSignInStatusCodes.SIGN_IN_CANCELLED else null
        }

        when (GmailOAuthOutcomeMapper.classify(account != null, statusCode, GoogleSignInStatusCodes.SIGN_IN_CANCELLED)) {
            GmailOAuthOutcome.AUTHORIZED -> processUnreadMessages(account!!)
            GmailOAuthOutcome.CANCELLED -> finishGmailFlow("Gmail sign-in was cancelled.")
            GmailOAuthOutcome.FAILED -> finishGmailFlow("Gmail authorization failed. Please try again.")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        
        badgeCategory = findViewById(R.id.badge_category)
        textTarget = findViewById(R.id.text_target)
        textScore = findViewById(R.id.text_score)
        textReasons = findViewById(R.id.text_reasons)
        textAction = findViewById(R.id.text_action)
        progressBar = findViewById(R.id.progress_bar)
        btnScanGmail = findViewById(R.id.btn_scan_gmail)
        
        layoutFeedback = findViewById(R.id.layout_feedback)
        btnThumbUp = findViewById(R.id.btn_thumb_up)
        btnThumbDown = findViewById(R.id.btn_thumb_down)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel("SS_ALERTS", "SecureShield Alerts", NotificationManager.IMPORTANCE_HIGH)
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }

        btnThumbUp.setOnClickListener { submitFeedback("up") }
        btnThumbDown.setOnClickListener { submitFeedback("down") }

        val switchBackgroundProtection = findViewById<SwitchCompat>(R.id.switch_background_protection)
        val textBackgroundStatus = findViewById<TextView>(R.id.text_background_status)

        switchBackgroundProtection.isChecked = BackgroundProtectionManager.isEnabled(this)
        updateBackgroundStatusText(textBackgroundStatus)

        switchBackgroundProtection.setOnCheckedChangeListener { _, isChecked ->
            BackgroundProtectionManager.setEnabled(this, isChecked)
            updateBackgroundStatusText(textBackgroundStatus)
            if (isChecked) {
                Toast.makeText(this, "Periodic background checks enabled.", Toast.LENGTH_SHORT).show()
            }
        }

        btnScanGmail.setOnClickListener {
            beginGmailScan()
        }

        findViewById<Button>(R.id.btn_scan_history).setOnClickListener {
            startActivity(Intent(this, ScanHistoryActivity::class.java))
        }

        handleIntent(intent)
    }

    private fun submitFeedback(value: String) {
        val result = currentResult ?: return
        val request = FeedbackRequest(
            scan_id = result.scan_id,
            user_feedback = if (value == "up") "positive" else "negative",
            classification_at_scan_time = result.classification,
            risk_score_at_scan_time = result.risk_score,
            confidence_at_scan_time = result.risk_assessment.confidence,
            source_type = currentResultSourceType
        )
        btnThumbUp.isEnabled = false
        btnThumbDown.isEnabled = false
        lifecycleScope.launch {
            when (val submission = feedbackSubmissionManager.submit(request)) {
                FeedbackSubmissionResult.Submitted -> {
                    if (FeedbackSubmissionUiPolicy.shouldDismissFeedback(submission) && currentResult?.scan_id == request.scan_id) {
                        layoutFeedback.visibility = View.GONE
                        lifecycleScope.launch(Dispatchers.IO) {
                            scanHistoryRepository.updateFeedbackState(request.scan_id, request.user_feedback)
                        }
                        Toast.makeText(this@MainActivity, "Feedback saved.", Toast.LENGTH_SHORT).show()
                    }
                }
                FeedbackSubmissionResult.AlreadySubmitted -> {
                    if (FeedbackSubmissionUiPolicy.shouldDismissFeedback(submission) && currentResult?.scan_id == request.scan_id) {
                        layoutFeedback.visibility = View.GONE
                        Toast.makeText(this@MainActivity, "Feedback was already recorded for this scan.", Toast.LENGTH_SHORT).show()
                    }
                }
                FeedbackSubmissionResult.InProgress ->
                    Toast.makeText(this@MainActivity, "Feedback submission is already in progress.", Toast.LENGTH_SHORT).show()
                is FeedbackSubmissionResult.HttpFailure ->
                    Toast.makeText(this@MainActivity, "Feedback could not be sent (HTTP ${submission.statusCode}). The scan result is still available; retry later.", Toast.LENGTH_LONG).show()
                FeedbackSubmissionResult.NetworkFailure ->
                    Toast.makeText(this@MainActivity, "Feedback could not be sent. The scan result is still available; retry later.", Toast.LENGTH_LONG).show()
                FeedbackSubmissionResult.MalformedResponse ->
                    Toast.makeText(this@MainActivity, "Feedback response was invalid. The scan result is still available; retry later.", Toast.LENGTH_LONG).show()
            }
            if (currentResult?.scan_id == request.scan_id && layoutFeedback.visibility == View.VISIBLE) {
                btnThumbUp.isEnabled = true
                btnThumbDown.isEnabled = true
            }
        }
    }

    private fun updateBackgroundStatusText(textView: TextView) {
        val isEnabled = BackgroundProtectionManager.isEnabled(this)
        val lastCheck = BackgroundProtectionManager.getLastCheck(this)
        if (!isEnabled) {
            textView.text = "Protection inactive"
        } else {
            val lastStr = if (lastCheck > 0) java.text.DateFormat.getDateTimeInstance(java.text.DateFormat.MEDIUM, java.text.DateFormat.SHORT).format(java.util.Date(lastCheck)) else "Never"
            textView.text = "Protection active (Last check: $lastStr)"
        }
    }

    private fun beginGmailScan() {
        if (gmailScanInProgress) return
        gmailScanInProgress = true
        btnScanGmail.isEnabled = false
        val gmailScope = Scope(GmailScopes.GMAIL_READONLY)
        val account = GoogleSignIn.getLastSignedInAccount(this)
        if (!gmailSessionInvalid && account != null && GoogleSignIn.hasPermissions(account, gmailScope)) {
            processUnreadMessages(account)
            return
        }

        val options = GoogleSignInOptions.Builder(GoogleSignInOptions.DEFAULT_SIGN_IN)
            .requestEmail()
            .requestScopes(gmailScope)
            .build()
        try {
            googleSignInLauncher.launch(GoogleSignIn.getClient(this, options).signInIntent)
        } catch (_: Exception) {
            finishGmailFlow("Could not start Google sign-in. Please try again.")
        }
    }

    private fun processUnreadMessages(account: GoogleSignInAccount) {
        gmailSessionInvalid = false
        badgeCategory.text = "Loading unread Gmail messages..."
        progressBar.visibility = View.VISIBLE

        lifecycleScope.launch {
            try {
                when (val fetch = GmailScanner(this@MainActivity, account).fetchUnreadMessages()) {
                    GmailFetchResult.NoUnreadMessages -> finishGmailFlow("No unread Gmail messages found.")
                    is GmailFetchResult.NoReadableMessages -> finishGmailFlow("Unread messages had no supported text body.")
                    is GmailFetchResult.Failure -> {
                        if (fetch.kind == GmailFailureKind.AUTHENTICATION_REQUIRED) gmailSessionInvalid = true
                        finishGmailFlow(gmailFailureMessage(fetch.kind))
                    }
                    is GmailFetchResult.Messages -> {
                        GmailEmailScanDispatcher.dispatch(fetch.emails) { email ->
                            textTarget.text = buildString {
                                appendLine("From: ${email.sender ?: "Unknown sender"}")
                                email.recipient?.let { appendLine("To: $it") }
                                email.subject?.let { appendLine("Subject: $it") }
                                append("Message: ${email.messageId}")
                            }
                            progressBar.visibility = View.VISIBLE
                            executeScan(email.toScanInput(), "Gmail message scanned", "Email", "gmail").join()
                        }
                        finishGmailFlow()
                    }
                }
            } catch (_: Exception) {
                finishGmailFlow("Could not retrieve Gmail messages. Please try again.")
            }
        }
    }

    private fun gmailFailureMessage(kind: GmailFailureKind): String = when (kind) {
        GmailFailureKind.AUTHENTICATION_REQUIRED -> "Gmail authorization expired. Reconnect Gmail to continue."
        GmailFailureKind.PERMISSION_DENIED -> "Gmail read access was denied. Reconnect and grant Gmail read permission."
        GmailFailureKind.TIMEOUT -> "Gmail request timed out. Check your network and try again."
        GmailFailureKind.NETWORK -> "Network error while retrieving Gmail messages."
        GmailFailureKind.API -> "Gmail API request failed. Please try again."
        GmailFailureKind.MALFORMED_RESPONSE -> "Gmail returned an unreadable message response."
    }

    private fun finishGmailFlow(message: String? = null) {
        progressBar.visibility = View.GONE
        message?.let { badgeCategory.text = it }
        gmailScanInProgress = false
        btnScanGmail.isEnabled = true
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        if (intent == null) return
        setIntent(intent)
        handleIntent(intent)
    }

    override fun onDestroy() {
        if (scanHistoryRepositoryDelegate.isInitialized()) scanHistoryRepository.close()
        super.onDestroy()
    }

    private fun handleIntent(intent: Intent) {
        if (intent.action != Intent.ACTION_SEND) return

        val streamUri = getSharedStreamUri(intent)
        val sharedText = try {
            (intent.getCharSequenceExtra(Intent.EXTRA_TEXT)
                ?: intent.getCharSequenceExtra(Intent.EXTRA_HTML_TEXT))?.toString()
        } catch (_: RuntimeException) {
            null
        }
        val intentData = intent.data
        val dataUri = intentData?.toString()?.takeIf {
            it.startsWith("http://", ignoreCase = true) || it.startsWith("https://", ignoreCase = true)
        }
        val contentUri = streamUri ?: intentData?.takeIf {
            it.scheme == ContentResolver.SCHEME_CONTENT || it.scheme == ContentResolver.SCHEME_FILE
        }
        val mimeType = intent.type ?: contentUri?.let { uri ->
            try {
                contentResolver.getType(uri)
            } catch (_: SecurityException) {
                null
            }
        }
        val payload = SharedIntentPayload(
            action = intent.action,
            mimeType = mimeType,
            text = sharedText,
            streamUri = contentUri?.toString(),
            dataUri = dataUri
        )

        val result = SharedIntentRouter.dispatch(payload, ::readSharedFile) { input, kind ->
            progressBar.visibility = View.VISIBLE
            layoutFeedback.visibility = View.GONE
            textTarget.text = when (kind) {
                com.secureshield.ai.share.SharedScanKind.FILE -> "File: ${input.file_name}"
                com.secureshield.ai.share.SharedScanKind.URL -> "URL:\n${input.url}"
                com.secureshield.ai.share.SharedScanKind.TEXT -> input.text.orEmpty()
            }
            val sourceType = when (kind) {
                com.secureshield.ai.share.SharedScanKind.FILE -> "file"
                com.secureshield.ai.share.SharedScanKind.URL -> "url"
                com.secureshield.ai.share.SharedScanKind.TEXT -> "share"
            }
            executeScan(input, "Shared content scanned", kind.label, sourceType)
        }
        if (result is ShareDispatchResult.Rejected) {
            progressBar.visibility = View.GONE
            layoutFeedback.visibility = View.GONE
            badgeCategory.text = result.message
        }
    }

    private fun getSharedStreamUri(intent: Intent): Uri? = try {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
        } else {
            @Suppress("DEPRECATION")
            (intent.getParcelableExtra<android.os.Parcelable>(Intent.EXTRA_STREAM) as? Uri)
        }
    } catch (_: BadParcelableException) {
        null
    } catch (_: SecurityException) {
        null
    }

    private fun readSharedFile(uriString: String): SharedFileReadResult {
        val uri = Uri.parse(uriString)
        var fileName = uri.lastPathSegment ?: "shared_file"
        var reportedSize = -1L
        try {
            contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    val sizeIndex = cursor.getColumnIndex(OpenableColumns.SIZE)
                    if (nameIndex >= 0) fileName = cursor.getString(nameIndex) ?: fileName
                    if (sizeIndex >= 0) reportedSize = cursor.getLong(sizeIndex)
                }
            }
        } catch (_: SecurityException) {
            return SharedFileReadResult.Failure("Shared file permission was denied.")
        } catch (_: Exception) {
            return SharedFileReadResult.Failure("Shared file details could not be read.")
        }

        val maximumBytes = 10 * 1024 * 1024
        if (reportedSize > maximumBytes) {
            return SharedFileReadResult.Failure("Shared file is too large (maximum 10 MB).")
        }

        return try {
            val content = contentResolver.openInputStream(uri)?.use { input ->
                val output = ByteArrayOutputStream(minOf(maximumBytes, reportedSize.coerceAtLeast(0).toInt()))
                val buffer = ByteArray(8192)
                var totalBytes = 0
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    totalBytes += count
                    if (totalBytes > maximumBytes) {
                        return SharedFileReadResult.Failure("Shared file is too large (maximum 10 MB).")
                    }
                    output.write(buffer, 0, count)
                }
                fileBytesAsBackendJsonValue(output.toByteArray())
            } ?: return SharedFileReadResult.Failure("Shared file could not be opened.")
            SharedFileReadResult.Success(fileName, content)
        } catch (_: SecurityException) {
            SharedFileReadResult.Failure("Shared file permission was denied.")
        } catch (error: IllegalArgumentException) {
            SharedFileReadResult.Failure(error.message ?: "Unsupported shared file encoding.")
        } catch (_: OutOfMemoryError) {
            SharedFileReadResult.Failure("Shared file is too large to process.")
        } catch (_: Exception) {
            SharedFileReadResult.Failure("Shared file could not be read.")
        }
    }

    private fun executeScan(input: ScanInput, notifyTitle: String, categorySuffix: String, sourceType: String = "unknown"): Job {
        currentResult = null
        layoutFeedback.visibility = View.GONE
        btnThumbUp.isEnabled = true
        btnThumbDown.isEnabled = true
        return lifecycleScope.launch {
            try {
                val response = withTimeout(35000L) {
                    withContext(Dispatchers.IO) {
                        ApiClient.api.scan(input)
                    }
                }
                
                progressBar.visibility = View.GONE
                if (response.isSuccessful) {
                    val responseJson = response.body()
                    if (responseJson != null) {
                        val result = UnifiedScanResponseParser.parse(responseJson)
                        currentResult = result
                        currentResultSourceType = sourceType
                        lifecycleScope.launch(Dispatchers.IO) {
                            scanHistoryRepository.saveCompletedScan(result, sourceType)
                        }
                        layoutFeedback.visibility = View.VISIBLE
                        badgeCategory.text = "${result.classification} ($categorySuffix)"
                        val confidencePct = (result.risk_assessment.confidence * 100).toInt()
                        textScore.text = "Risk Score: ${result.risk_score} / 100 (Conf: ${confidencePct}%)"
                        val assessment = result.risk_assessment
                        val explanationLines = buildList {
                            addAll(assessment.reasons)
                            if (assessment.flags.isNotEmpty()) add("Indicators: ${assessment.flags.joinToString()}")
                            assessment.evidence.forEach { item ->
                                add(item.description?.takeIf(String::isNotBlank) ?: "${item.key}: ${item.value}")
                            }
                        }.distinct()
                        textReasons.text = if (explanationLines.isNotEmpty()) explanationLines.joinToString("\n• ", prefix = "• ") else "None"
                        textAction.text = result.risk_assessment.recommended_action
                        
                        sendPushNotification(notifyTitle, "Risk: ${result.classification}")
                    } else {
                        badgeCategory.text = "Malformed Response (Empty Body)"
                    }
                } else {
                    val sc = response.code()
                    badgeCategory.text = "HTTP Error: $sc"
                }
            } catch (e: TimeoutCancellationException) {
                progressBar.visibility = View.GONE
                badgeCategory.text = "Network Timeout: Scan took too long."
            } catch (e: SocketTimeoutException) {
                progressBar.visibility = View.GONE
                badgeCategory.text = "Network Timeout: Scan took too long."
            } catch (e: MalformedScanResponseException) {
                progressBar.visibility = View.GONE
                badgeCategory.text = "Malformed Response: ${e.message}"
            } catch (e: JsonParseException) {
                progressBar.visibility = View.GONE
                badgeCategory.text = "Malformed Response: Invalid JSON."
            } catch (e: MalformedJsonException) {
                progressBar.visibility = View.GONE
                badgeCategory.text = "Malformed Response: Invalid JSON."
            } catch (e: IOException) {
                progressBar.visibility = View.GONE
                badgeCategory.text = "Network Error: ${e.message}"
            } catch (e: Exception) {
                progressBar.visibility = View.GONE
                badgeCategory.text = "Network Error: ${e.message}"
            }
        }
    }

    private fun sendPushNotification(title: String, message: String) {
        try {
            val intent = Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
            }
            val pendingIntent = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)

            val builder = NotificationCompat.Builder(this, "SS_ALERTS")
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle(title)
                .setContentText(message)
                .setContentIntent(pendingIntent)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .setAutoCancel(true)
            
            NotificationManagerCompat.from(this).notify(System.currentTimeMillis().toInt(), builder.build())
        } catch (e: SecurityException) {
            e.printStackTrace()
        }
    }
}
