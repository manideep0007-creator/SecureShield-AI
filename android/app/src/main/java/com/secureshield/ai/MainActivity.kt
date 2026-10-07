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
import android.widget.EditText
import androidx.appcompat.app.AlertDialog
import java.net.ConnectException
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
import com.secureshield.ai.accessibility.UniversalLinkGuardManager
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
    private lateinit var textFeedbackStatus: TextView

    private lateinit var switchUniversalGuard: SwitchCompat
    private lateinit var textUniversalGuardStatus: TextView
    private lateinit var btnAccessibilitySettings: Button
    
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
            GmailOAuthOutcome.FAILED -> {
                finishGmailFlow("Gmail authorization failed. Please try again.")
                showGmailSetupOrDemoDialog(statusCode)
            }
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
        textFeedbackStatus = findViewById(R.id.text_feedback_status)

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

        switchUniversalGuard = findViewById(R.id.switch_universal_guard)
        textUniversalGuardStatus = findViewById(R.id.text_universal_guard_status)
        btnAccessibilitySettings = findViewById(R.id.btn_accessibility_settings)

        updateUniversalGuardUi()

        btnAccessibilitySettings.setOnClickListener {
            promptAndOpenAccessibilitySettings()
        }

        switchUniversalGuard.setOnClickListener {
            val isServiceOn = UniversalLinkGuardManager.isServiceEnabledInSettings(this)
            if (!isServiceOn) {
                // If service not enabled in Android Accessibility settings, prompt user to enable it
                switchUniversalGuard.isChecked = false
                promptAndOpenAccessibilitySettings()
            } else {
                val isNowChecked = switchUniversalGuard.isChecked
                UniversalLinkGuardManager.setUserPreferenceEnabled(this, isNowChecked)
                updateUniversalGuardUi()
                val msg = if (isNowChecked) "Universal Link Protection active across all apps." else "Universal Link Protection paused."
                Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
            }
        }

        btnScanGmail.setOnClickListener {
            beginGmailScan()
        }
        btnScanGmail.setOnLongClickListener {
            scanDemoGmailMessage()
            true
        }

        val prefs = getSharedPreferences("secureshield_settings", Context.MODE_PRIVATE)
        val savedUrl = prefs.getString("server_base_url", null)
        if (!savedUrl.isNullOrBlank()) {
            ApiClient.setBaseUrl(savedUrl)
        }

        findViewById<Button>(R.id.btn_scan_history).setOnClickListener {
            startActivity(Intent(this, ScanHistoryActivity::class.java))
        }

        findViewById<Button>(R.id.btn_server_settings)?.setOnClickListener {
            showServerConfigDialog()
        }

        handleIntent(intent)
    }

    private fun submitFeedback(value: String) {
        val result = currentResult ?: return
        val request = FeedbackRequest(
            scan_id = result.scan_id,
            user_feedback = if (value == "up" || value == "positive" || value == "correct") "positive" else "negative",
            classification_at_scan_time = result.classification,
            risk_score_at_scan_time = result.risk_score,
            confidence_at_scan_time = result.risk_assessment.confidence,
            source_type = currentResultSourceType
        )
        // Optimistic UI: disable buttons immediately
        btnThumbUp.isEnabled = false
        btnThumbDown.isEnabled = false
        textFeedbackStatus.text = "Submitting..."
        textFeedbackStatus.visibility = View.VISIBLE

        lifecycleScope.launch {
            when (val submission = feedbackSubmissionManager.submit(request)) {
                FeedbackSubmissionResult.Submitted -> {
                    if (currentResult?.scan_id == request.scan_id) {
                        btnThumbUp.isEnabled = false
                        btnThumbDown.isEnabled = false
                        textFeedbackStatus.text = "Feedback recorded ✓"
                        textFeedbackStatus.visibility = View.VISIBLE
                        lifecycleScope.launch(Dispatchers.IO) {
                            scanHistoryRepository.updateFeedbackState(request.scan_id, request.user_feedback)
                        }
                        Toast.makeText(this@MainActivity, "Feedback saved.", Toast.LENGTH_SHORT).show()
                    }
                }
                FeedbackSubmissionResult.AlreadySubmitted -> {
                    if (currentResult?.scan_id == request.scan_id) {
                        btnThumbUp.isEnabled = false
                        btnThumbDown.isEnabled = false
                        textFeedbackStatus.text = "Already submitted"
                        textFeedbackStatus.visibility = View.VISIBLE
                    }
                }
                FeedbackSubmissionResult.InProgress ->
                    Toast.makeText(this@MainActivity, "Feedback submission is already in progress.", Toast.LENGTH_SHORT).show()
                is FeedbackSubmissionResult.HttpFailure -> {
                    if (currentResult?.scan_id == request.scan_id) {
                        btnThumbUp.isEnabled = true
                        btnThumbDown.isEnabled = true
                        textFeedbackStatus.visibility = View.GONE
                    }
                    Toast.makeText(this@MainActivity, "Feedback could not be sent (HTTP ${submission.statusCode}). The scan result is still available; retry later.", Toast.LENGTH_LONG).show()
                }
                FeedbackSubmissionResult.NetworkFailure -> {
                    if (currentResult?.scan_id == request.scan_id) {
                        btnThumbUp.isEnabled = true
                        btnThumbDown.isEnabled = true
                        textFeedbackStatus.visibility = View.GONE
                    }
                    Toast.makeText(this@MainActivity, "Feedback could not be sent. The scan result is still available; retry later.", Toast.LENGTH_LONG).show()
                }
                FeedbackSubmissionResult.MalformedResponse -> {
                    if (currentResult?.scan_id == request.scan_id) {
                        btnThumbUp.isEnabled = true
                        btnThumbDown.isEnabled = true
                        textFeedbackStatus.visibility = View.GONE
                    }
                    Toast.makeText(this@MainActivity, "Feedback response was invalid. The scan result is still available; retry later.", Toast.LENGTH_LONG).show()
                }
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

    private fun updateUniversalGuardUi() {
        val isServiceOn = UniversalLinkGuardManager.isServiceEnabledInSettings(this)
        val isUserPrefOn = UniversalLinkGuardManager.isUserPreferenceEnabled(this)
        if (!isServiceOn) {
            switchUniversalGuard.isChecked = false
            textUniversalGuardStatus.text = "Accessibility service inactive (Tap button to enable)"
            textUniversalGuardStatus.setTextColor(0xFFD32F2F.toInt())
        } else {
            switchUniversalGuard.isChecked = isUserPrefOn
            if (isUserPrefOn) {
                textUniversalGuardStatus.text = "Protection active (Scanning links in all apps)"
                textUniversalGuardStatus.setTextColor(0xFF388E3C.toInt())
            } else {
                textUniversalGuardStatus.text = "Paused by user"
                textUniversalGuardStatus.setTextColor(0xFF757575.toInt())
            }
        }
    }

    private fun promptAndOpenAccessibilitySettings() {
        AlertDialog.Builder(this)
            .setTitle("Enable Universal Link Protection")
            .setMessage(
                "To scan on-screen links across WhatsApp, Instagram, browsers, and all apps, enable the Accessibility Service:\n\n" +
                "1. Tap 'Open Settings' below.\n" +
                "2. Tap 'Downloaded apps' (or 'Installed services').\n" +
                "3. Select 'SecureShield Universal Link Guard'.\n" +
                "4. Turn the switch ON and tap 'Allow'."
            )
            .setPositiveButton("Open Settings") { _, _ ->
                UniversalLinkGuardManager.openAccessibilitySettings(this)
            }
            .setNegativeButton("Cancel", null)
            .show()
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
                        val msg = gmailFailureMessage(fetch.kind)
                        finishGmailFlow(msg)
                        showGmailFetchFailureDialog(msg)
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

    private fun showGmailSetupOrDemoDialog(statusCode: Int?) {
        val statusDetail = when (statusCode) {
            10 -> " (Developer Error: Debug SHA-1 not registered in Google Cloud Console)"
            8 -> " (Internal Error: Google Play Services or Network issue)"
            null -> ""
            else -> " (Error Code: $statusCode)"
        }
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("Gmail Authorization Notice")
            .setMessage(
                "Google Sign-In could not complete$statusDetail.\n\n" +
                "To scan real Gmail messages, package 'com.secureshield.ai' and your debug SHA-1 must be registered under an Android OAuth Client ID in Google Cloud Console with the Gmail API enabled.\n\n" +
                "Would you like to run a simulated demo scan with a sample phishing email to test the detection engine?"
            )
            .setPositiveButton("Run Demo Scan") { _, _ ->
                scanDemoGmailMessage()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showGmailFetchFailureDialog(errorDetail: String) {
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("Gmail Sync Notice")
            .setMessage(
                "Could not retrieve Gmail messages ($errorDetail).\n\n" +
                "To scan real Gmail messages, package 'com.secureshield.ai' and your debug SHA-1 must be registered under an Android OAuth Client ID in Google Cloud Console with the Gmail API enabled.\n\n" +
                "Would you like to run a simulated demo scan with a sample phishing email to test the detection engine?"
            )
            .setPositiveButton("Run Demo Scan") { _, _ ->
                scanDemoGmailMessage()
            }
            .setNeutralButton("Retry") { _, _ ->
                beginGmailScan()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun scanDemoGmailMessage() {
        if (gmailScanInProgress) return
        gmailScanInProgress = true
        btnScanGmail.isEnabled = false
        badgeCategory.text = "Loading demo Gmail message..."
        progressBar.visibility = View.VISIBLE

        val demoEmail = GmailEmail(
            messageId = "demo-msg-001",
            sender = "security-alert@amazon-security-update.xyz",
            recipient = "user@gmail.com",
            subject = "URGENT: Your account has been suspended",
            bodyText = "Dear customer, your account has been locked due to unauthorized activity. Please verify your identity immediately: http://192.168.1.1@secure-login-verify.xyz/account",
            embeddedUrls = listOf("http://192.168.1.1@secure-login-verify.xyz/account")
        )

        lifecycleScope.launch {
            textTarget.text = buildString {
                appendLine("From: ${demoEmail.sender}")
                demoEmail.recipient?.let { appendLine("To: $it") }
                demoEmail.subject?.let { appendLine("Subject: $it") }
                append("Message: ${demoEmail.messageId}")
            }
            executeScan(demoEmail.toScanInput(), "Gmail message scanned", "Email", "gmail").join()
            finishGmailFlow()
        }
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        if (intent == null) return
        setIntent(intent)
        handleIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        updateUniversalGuardUi()
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
            textFeedbackStatus.visibility = View.GONE
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
            textFeedbackStatus.visibility = View.GONE
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
        textFeedbackStatus.visibility = View.GONE
        textFeedbackStatus.text = ""
        btnThumbUp.isEnabled = true
        btnThumbDown.isEnabled = true
        progressBar.visibility = View.VISIBLE
        badgeCategory.setOnClickListener(null)
        textReasons.setOnClickListener(null)
        return lifecycleScope.launch {
            try {
                val response = withTimeout(35000L) {
                    withContext(Dispatchers.IO) {
                        ApiClient.api.scan(input)
                    }
                }
                
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
                        if (feedbackSubmissionManager.isSubmitted(result.scan_id)) {
                            btnThumbUp.isEnabled = false
                            btnThumbDown.isEnabled = false
                            textFeedbackStatus.text = "Already submitted"
                            textFeedbackStatus.visibility = View.VISIBLE
                        } else {
                            btnThumbUp.isEnabled = true
                            btnThumbDown.isEnabled = true
                            textFeedbackStatus.visibility = View.GONE
                            textFeedbackStatus.text = ""
                        }
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
            } catch (e: ConnectException) {
                badgeCategory.text = "Connection Failed"
                textScore.text = "Cannot reach server"
                textReasons.text = "Could not connect to ${ApiClient.baseUrl}\n1. Check your phone Wi-Fi (must be same network as PC).\n2. Ensure backend server is running.\n\n👉 Tap here to configure Server IP."
                val errorClick = View.OnClickListener { showServerConfigDialog() }
                badgeCategory.setOnClickListener(errorClick)
                textReasons.setOnClickListener(errorClick)
            } catch (e: TimeoutCancellationException) {
                badgeCategory.text = "Network Timeout"
                textScore.text = "Scan took too long"
                textReasons.text = "Server at ${ApiClient.baseUrl} took over 35s to respond.\nIf scanning a file, ensure external services are reachable.\n\n👉 Tap here to configure Server IP."
                val errorClick = View.OnClickListener { showServerConfigDialog() }
                badgeCategory.setOnClickListener(errorClick)
                textReasons.setOnClickListener(errorClick)
            } catch (e: SocketTimeoutException) {
                badgeCategory.text = "Network Timeout"
                textScore.text = "Connection timed out"
                textReasons.text = "Socket timed out connecting to ${ApiClient.baseUrl}\nCheck your network connection or PC firewall.\n\n👉 Tap here to configure Server IP."
                val errorClick = View.OnClickListener { showServerConfigDialog() }
                badgeCategory.setOnClickListener(errorClick)
                textReasons.setOnClickListener(errorClick)
            } catch (e: MalformedScanResponseException) {
                badgeCategory.text = "Malformed Response: ${e.message}"
            } catch (e: JsonParseException) {
                badgeCategory.text = "Malformed Response: Invalid JSON."
            } catch (e: MalformedJsonException) {
                badgeCategory.text = "Malformed Response: Invalid JSON."
            } catch (e: IOException) {
                badgeCategory.text = "Network Error: ${e.message}"
                textReasons.text = "Network error connecting to ${ApiClient.baseUrl}\n\n👉 Tap here to configure Server IP."
                val errorClick = View.OnClickListener { showServerConfigDialog() }
                badgeCategory.setOnClickListener(errorClick)
                textReasons.setOnClickListener(errorClick)
            } catch (e: Exception) {
                badgeCategory.text = "Network Error: ${e.message}"
            } finally {
                progressBar.visibility = View.GONE
            }
        }
    }

    private fun showServerConfigDialog() {
        val input = EditText(this).apply {
            hint = "http://192.168.x.x:8000/"
            setText(ApiClient.baseUrl)
            setSelection(text.length)
            setPadding(48, 24, 48, 24)
        }

        val dialog = AlertDialog.Builder(this)
            .setTitle("Server Connection Settings")
            .setMessage("Current Base URL:\n${ApiClient.baseUrl}\n\nEnter backend IP and port:")
            .setView(input)
            .setPositiveButton("Save") { _, _ ->
                val newUrl = input.text.toString().trim()
                if (newUrl.startsWith("http://") || newUrl.startsWith("https://")) {
                    ApiClient.setBaseUrl(newUrl)
                    getSharedPreferences("secureshield_settings", Context.MODE_PRIVATE)
                        .edit()
                        .putString("server_base_url", ApiClient.baseUrl)
                        .apply()
                    Toast.makeText(this, "Server URL updated to: ${ApiClient.baseUrl}", Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(this, "Invalid URL. Must begin with http:// or https://", Toast.LENGTH_LONG).show()
                }
            }
            .setNeutralButton("Test Connection", null)
            .setNegativeButton("Cancel", null)
            .create()

        dialog.setOnShowListener {
            val testButton = dialog.getButton(AlertDialog.BUTTON_NEUTRAL)
            testButton.setOnClickListener {
                val candidateUrl = input.text.toString().trim()
                if (!candidateUrl.startsWith("http://") && !candidateUrl.startsWith("https://")) {
                    Toast.makeText(this, "Enter a valid URL starting with http:// or https://", Toast.LENGTH_SHORT).show()
                    return@setOnClickListener
                }
                testButton.isEnabled = false
                testButton.text = "Testing..."
                lifecycleScope.launch {
                    val originalUrl = ApiClient.baseUrl
                    try {
                        ApiClient.setBaseUrl(candidateUrl)
                        val start = System.currentTimeMillis()
                        val response = withTimeout(10000L) {
                            withContext(Dispatchers.IO) {
                                ApiClient.api.healthCheck()
                            }
                        }
                        val elapsed = System.currentTimeMillis() - start
                        if (response.isSuccessful) {
                            Toast.makeText(this@MainActivity, "Connected! Latency: ${elapsed}ms", Toast.LENGTH_SHORT).show()
                        } else {
                            Toast.makeText(this@MainActivity, "Server responded with HTTP ${response.code()}", Toast.LENGTH_LONG).show()
                        }
                    } catch (e: Exception) {
                        ApiClient.setBaseUrl(originalUrl)
                        Toast.makeText(this@MainActivity, "Connection failed: ${e.message ?: "Unknown error"}", Toast.LENGTH_LONG).show()
                    } finally {
                        testButton.isEnabled = true
                        testButton.text = "Test Connection"
                    }
                }
            }
        }

        dialog.show()
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
