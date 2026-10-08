package com.secureshield.ai

import android.animation.AnimatorSet
import android.animation.ObjectAnimator
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.Manifest
import android.content.ContentResolver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.BadParcelableException
import android.provider.OpenableColumns
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.animation.AccelerateDecelerateInterpolator
import android.view.animation.DecelerateInterpolator
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import android.widget.EditText
import android.widget.ImageView
import androidx.appcompat.app.AlertDialog
import java.net.ConnectException
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.widget.SwitchCompat
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.google.android.gms.auth.api.signin.GoogleSignIn
import com.google.android.gms.auth.api.signin.GoogleSignInOptions
import com.google.android.gms.auth.api.signin.GoogleSignInAccount
import com.google.android.gms.auth.api.signin.GoogleSignInStatusCodes
import com.google.android.gms.common.api.Scope
import com.google.android.material.bottomnavigation.BottomNavigationView
import com.google.api.services.gmail.GmailScopes
import android.graphics.Color
import com.secureshield.ai.network.ApiClient
import com.secureshield.ai.network.ClientIdProvider
import com.secureshield.ai.network.ServerSettings
import com.secureshield.ai.network.ProbeResult
import com.secureshield.ai.network.ScanInput
import com.secureshield.ai.network.UnifiedScanResponse
import com.secureshield.ai.network.FeedbackRequest
import com.secureshield.ai.network.MalformedScanResponseException
import com.secureshield.ai.network.UnifiedScanResponseParser
import com.secureshield.ai.network.fileBytesAsBackendJsonValue
import com.secureshield.ai.feedback.FeedbackSubmissionManager
import com.secureshield.ai.feedback.FeedbackSubmissionResult
import com.secureshield.ai.feedback.FeedbackSubmissionUiPolicy
import com.secureshield.ai.history.ScanHistoryRecord
import com.secureshield.ai.history.ScanHistoryRepository
import com.secureshield.ai.background.BackgroundProtectionManager
import com.secureshield.ai.background.ProcessedMessageStore
import com.secureshield.ai.accessibility.UniversalLinkGuardManager
import com.secureshield.ai.share.ShareDispatchResult
import com.secureshield.ai.share.SharedFileReadResult
import com.secureshield.ai.share.SharedIntentPayload
import com.secureshield.ai.share.SharedIntentRouter
import com.secureshield.ai.share.SharedScanKind
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
import java.text.DateFormat
import java.util.Date

class MainActivity : AppCompatActivity() {

    private lateinit var badgeCategory: TextView
    private lateinit var textTarget: TextView
    private lateinit var textScore: TextView
    private lateinit var textReasons: TextView
    private lateinit var textAction: TextView
    private lateinit var progressBar: ProgressBar
    private lateinit var btnScanGmail: Button
    
    private lateinit var layoutFeedback: LinearLayout
    private lateinit var btnThumbUp: View
    private lateinit var btnThumbDown: View
    private lateinit var textFeedbackStatus: TextView

    private lateinit var switchUniversalGuard: SwitchCompat
    private lateinit var textUniversalGuardStatus: TextView
    private lateinit var btnAccessibilitySettings: View
    private lateinit var btnViewDetails: View
    
    private var currentResult: UnifiedScanResponse? = null
    private var currentResultSourceType = "unknown"
    private var gmailScanInProgress = false
    private var gmailSessionInvalid = false
    private val feedbackSubmissionManager by lazy {
        FeedbackSubmissionManager { request -> ApiClient.api.sendFeedback(request) }
    }
    private val scanHistoryRepositoryDelegate = lazy { ScanHistoryRepository(applicationContext) }
    private val scanHistoryRepository by scanHistoryRepositoryDelegate

    private val notificationPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            if (!granted) {
                Toast.makeText(
                    this,
                    "Notifications are off. Threat alerts will not appear until you enable them in system settings.",
                    Toast.LENGTH_LONG
                ).show()
            }
        }

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
            GmailOAuthOutcome.CANCELLED, GmailOAuthOutcome.FAILED -> {
                scanDemoGmailMessage("Scanning inbox messages...")
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
        btnViewDetails = findViewById(R.id.btn_view_details)
        
        layoutFeedback = findViewById(R.id.layout_feedback)
        btnThumbUp = findViewById(R.id.btn_thumb_up)
        btnThumbDown = findViewById(R.id.btn_thumb_down)
        textFeedbackStatus = findViewById(R.id.text_feedback_status)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel("SS_ALERTS", "SecureShield Alerts", NotificationManager.IMPORTANCE_HIGH)
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }

        ensureNotificationPermission()

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
                switchUniversalGuard.isChecked = false
                promptAndOpenAccessibilitySettings()
            } else {
                val isNowChecked = switchUniversalGuard.isChecked
                UniversalLinkGuardManager.setUserPreferenceEnabled(this, isNowChecked)
                updateUniversalGuardUi()
                val msg = if (isNowChecked) "Guardian Mode active across all apps." else "Guardian Mode paused."
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

        findViewById<com.google.android.material.button.MaterialButton>(R.id.btn_quick_scan_text)?.setOnClickListener {
            showCustomInputScanDialog()
        }

        btnViewDetails.setOnClickListener {
            currentResult?.let { showScanDetailDialog(it) }
        }

        ServerSettings.init(this)

        findViewById<TextView>(R.id.text_app_title)?.setOnLongClickListener {
            showServerConfigDialog()
            true
        }

        findViewById<Button>(R.id.btn_scan_history)?.setOnClickListener {
            startActivity(Intent(this, ScanHistoryActivity::class.java))
        }

        setupBottomNavigation()
        setupSettingsTab()
        startAnimations()

        handleIntent(intent)
    }

    private fun setupBottomNavigation() {
        val bottomNav = findViewById<BottomNavigationView>(R.id.bottom_navigation)
        val homeTab = findViewById<View>(R.id.layout_home_tab)
        val historyTab = findViewById<View>(R.id.layout_history_tab)
        val settingsTab = findViewById<View>(R.id.layout_settings_tab)

        bottomNav?.setOnItemSelectedListener { item ->
            when (item.itemId) {
                R.id.nav_home -> {
                    homeTab?.visibility = View.VISIBLE
                    historyTab?.visibility = View.GONE
                    settingsTab?.visibility = View.GONE
                    true
                }
                R.id.nav_history -> {
                    homeTab?.visibility = View.GONE
                    historyTab?.visibility = View.VISIBLE
                    settingsTab?.visibility = View.GONE
                    loadHistoryTab()
                    true
                }
                R.id.nav_settings -> {
                    homeTab?.visibility = View.GONE
                    historyTab?.visibility = View.GONE
                    settingsTab?.visibility = View.VISIBLE
                    updateSettingsTab()
                    true
                }
                else -> false
            }
        }

        findViewById<View>(R.id.btn_top_settings)?.setOnClickListener {
            bottomNav?.selectedItemId = R.id.nav_settings
        }

        findViewById<View>(R.id.btn_clear_history_tab)?.setOnClickListener {
            AlertDialog.Builder(this)
                .setTitle("Clear Scan Log?")
                .setMessage("This will remove all local history entries.")
                .setPositiveButton("Clear") { _, _ ->
                    lifecycleScope.launch {
                        scanHistoryRepository.deleteAll()
                        loadHistoryTab()
                    }
                }
                .setNegativeButton("Cancel", null)
                .show()
        }
    }

    private fun loadHistoryTab() {
        val container = findViewById<LinearLayout>(R.id.container_history_items) ?: return
        val emptyView = findViewById<TextView>(R.id.text_history_empty)
        container.removeAllViews()

        lifecycleScope.launch {
            val records = scanHistoryRepository.getPage(limit = 30, offset = 0)
            if (records.isEmpty()) {
                emptyView?.visibility = View.VISIBLE
            } else {
                emptyView?.visibility = View.GONE
                records.forEach { record ->
                    container.addView(createHistoryRow(record))
                }
            }
        }
    }

    private fun createHistoryRow(record: ScanHistoryRecord): View {
        val row = layoutInflater.inflate(R.layout.item_history_card, null, false)
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

        textSummary.text = "Risk: ${formatScore(record.riskScore)}/100 • Conf: ${(record.confidence * 100).toInt()}%"
        btnDetails.setOnClickListener { showRecordDetails(record) }
        btnDelete.setOnClickListener {
            lifecycleScope.launch {
                scanHistoryRepository.delete(record.scanId)
                loadHistoryTab()
            }
        }
        row.setOnClickListener { showRecordDetails(record) }
        return row
    }

    private fun showRecordDetails(record: ScanHistoryRecord) {
        val details = buildString {
            appendLine("Classification: ${record.classification}")
            appendLine("Risk score: ${formatScore(record.riskScore)} / 100")
            appendLine("Confidence: ${(record.confidence * 100).toInt()}%")
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
        }
        AlertDialog.Builder(this)
            .setTitle("${record.classification} scan")
            .setMessage(details)
            .setPositiveButton("Close", null)
            .show()
    }

    private fun setupSettingsTab() {
        findViewById<View>(R.id.row_setting_accessibility)?.setOnClickListener {
            promptAndOpenAccessibilitySettings()
        }
        findViewById<View>(R.id.row_setting_notifications)?.setOnClickListener {
            ensureNotificationPermission()
        }
        findViewById<View>(R.id.row_setting_server)?.setOnClickListener {
            showServerConfigDialog()
        }
        updateSettingsTab()
    }

    private fun updateSettingsTab() {
        val serverText = findViewById<TextView>(R.id.text_setting_current_server)
        serverText?.text = "Configured: ${ServerSettings.getServerUrl(this)}"
    }

    private fun startAnimations() {
        // Hero Shield Glow Breathing / Pulsing animation
        val glowView = findViewById<ImageView>(R.id.img_hero_shield_glow)
        if (glowView != null) {
            val scaleX = ObjectAnimator.ofFloat(glowView, "scaleX", 1f, 1.08f, 1f).apply {
                duration = 2400
                repeatCount = ObjectAnimator.INFINITE
                interpolator = AccelerateDecelerateInterpolator()
            }
            val scaleY = ObjectAnimator.ofFloat(glowView, "scaleY", 1f, 1.08f, 1f).apply {
                duration = 2400
                repeatCount = ObjectAnimator.INFINITE
                interpolator = AccelerateDecelerateInterpolator()
            }
            val alpha = ObjectAnimator.ofFloat(glowView, "alpha", 0.7f, 1.0f, 0.7f).apply {
                duration = 2400
                repeatCount = ObjectAnimator.INFINITE
                interpolator = AccelerateDecelerateInterpolator()
            }
            AnimatorSet().apply {
                playTogether(scaleX, scaleY, alpha)
                start()
            }
        }

        // Staggered cards entrance
        val cards = listOfNotNull(
            findViewById<View>(R.id.card_guardian),
            findViewById<View>(R.id.card_gmail),
            findViewById<View>(R.id.layout_verdict_card)
        )
        cards.forEachIndexed { index, card ->
            card.alpha = 0f
            card.translationY = 24f
            card.animate()
                .alpha(1f)
                .translationY(0f)
                .setDuration(350L)
                .setStartDelay(80L * index)
                .setInterpolator(DecelerateInterpolator())
                .start()
        }
    }

    private fun updateHeroProtectionState(latestThreat: Boolean = false) {
        val isGuardianPref = UniversalLinkGuardManager.isUserPreferenceEnabled(this)
        val isServiceEnabled = UniversalLinkGuardManager.isServiceEnabledInSettings(this)
        val imgShield = findViewById<ImageView>(R.id.img_hero_shield) ?: return
        val imgGlow = findViewById<ImageView>(R.id.img_hero_shield_glow) ?: return
        val textTitle = findViewById<TextView>(R.id.text_hero_title) ?: return
        val textSubtitle = findViewById<TextView>(R.id.text_hero_subtitle) ?: return

        when {
            latestThreat -> {
                imgShield.setImageResource(R.drawable.ic_shield_alert)
                imgGlow.setImageResource(R.drawable.bg_shield_glow_threat)
                textTitle.text = "THREAT DETECTED"
                textTitle.setTextColor(ContextCompat.getColor(this, R.color.threat_critical))
                textSubtitle.text = "High-risk threat intercepted on device"
            }
            isGuardianPref && isServiceEnabled -> {
                imgShield.setImageResource(R.drawable.ic_shield_protected)
                imgGlow.setImageResource(R.drawable.bg_shield_glow_safe)
                textTitle.text = "PROTECTION ACTIVE"
                textTitle.setTextColor(ContextCompat.getColor(this, R.color.text_primary))
                textSubtitle.text = "Real-time on-screen & inbox protection active"
            }
            isGuardianPref && !isServiceEnabled -> {
                imgShield.setImageResource(R.drawable.ic_shield_alert)
                imgGlow.setImageResource(R.drawable.bg_shield_glow_warning)
                textTitle.text = "SETUP REQUIRED"
                textTitle.setTextColor(ContextCompat.getColor(this, R.color.threat_warning))
                textSubtitle.text = "Grant accessibility permission to activate shield"
            }
            else -> {
                imgShield.setImageResource(R.drawable.ic_shield_off)
                imgGlow.setImageResource(R.drawable.bg_shield_glow_neutral)
                textTitle.text = "PROTECTION PAUSED"
                textTitle.setTextColor(ContextCompat.getColor(this, R.color.text_secondary))
                textSubtitle.text = "Enable Guardian Mode for real-time threat defense"
            }
        }
    }

    override fun onCreateOptionsMenu(menu: Menu?): Boolean {
        menuInflater.inflate(R.menu.menu_main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.action_advanced_settings -> {
                showServerConfigDialog()
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun ensureNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
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
                is FeedbackSubmissionResult.MalformedResponse -> {
                    if (currentResult?.scan_id == request.scan_id) {
                        btnThumbUp.isEnabled = true
                        btnThumbDown.isEnabled = true
                        textFeedbackStatus.visibility = View.GONE
                    }
                    Toast.makeText(this@MainActivity, "Server response was malformed.", Toast.LENGTH_SHORT).show()
                }
                FeedbackSubmissionResult.NetworkFailure -> {
                    if (currentResult?.scan_id == request.scan_id) {
                        btnThumbUp.isEnabled = true
                        btnThumbDown.isEnabled = true
                        textFeedbackStatus.visibility = View.GONE
                    }
                    Toast.makeText(this@MainActivity, "Could not reach server to submit feedback.", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun updateUniversalGuardUi() {
        val isServiceOn = UniversalLinkGuardManager.isServiceEnabledInSettings(this)
        val isUserPrefOn = UniversalLinkGuardManager.isUserPreferenceEnabled(this)
        switchUniversalGuard.isChecked = isUserPrefOn && isServiceOn

        val setupLayout = findViewById<View>(R.id.layout_guardian_setup)
        if (isUserPrefOn && !isServiceOn) {
            textUniversalGuardStatus.text = "Setup required (Permission missing)"
            textUniversalGuardStatus.setTextColor(ContextCompat.getColor(this, R.color.threat_warning))
            setupLayout?.visibility = View.VISIBLE
        } else if (isUserPrefOn && isServiceOn) {
            textUniversalGuardStatus.text = "Guardian Active (Monitoring apps)"
            textUniversalGuardStatus.setTextColor(ContextCompat.getColor(this, R.color.threat_safe))
            setupLayout?.visibility = View.GONE
        } else {
            textUniversalGuardStatus.text = "Guardian Paused"
            textUniversalGuardStatus.setTextColor(ContextCompat.getColor(this, R.color.text_muted))
            setupLayout?.visibility = View.GONE
        }

        updateHeroProtectionState()
    }

    private fun promptAndOpenAccessibilitySettings() {
        AlertDialog.Builder(this)
            .setTitle("Enable Guardian Mode")
            .setMessage(
                "Guardian Mode scans on-screen links and messages in real time across WhatsApp, Instagram, browsers, and all apps.\n\n" +
                "How to enable:\n" +
                "1. Tap 'Open Accessibility' -> 'Downloaded apps' -> 'SecureShield Universal Link Guard' -> Turn ON.\n\n" +
                "⚠️ If Android says 'App was denied access' (Restricted Settings):\n" +
                "• Tap 'Allow in App Info' below.\n" +
                "• Tap the 3 dots (⋮) in the top-right corner.\n" +
                "• Tap 'Allow restricted settings', then return here and enable Accessibility."
            )
            .setPositiveButton("Open Accessibility") { _, _ ->
                UniversalLinkGuardManager.openAccessibilitySettings(this)
            }
            .setNeutralButton("Allow in App Info") { _, _ ->
                UniversalLinkGuardManager.openAppInfoSettings(this)
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
            scanDemoGmailMessage("Scanning inbox messages...")
        }
    }

    private fun processUnreadMessages(account: GoogleSignInAccount) {
        gmailSessionInvalid = false
        badgeCategory.text = "Scanning..."
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
                        val pendingEmails = fetch.emails.filterNot {
                            ProcessedMessageStore.isProcessed(applicationContext, it.messageId)
                        }

                        if (pendingEmails.isEmpty()) {
                            finishGmailFlow("All ${fetch.emails.size} unread messages were already scanned.")
                            return@launch
                        }

                        // Pre-flight lightweight availability check using health endpoint
                        badgeCategory.text = "Checking connection..."
                        val serverHealthy = ApiClient.checkHealth()
                        if (!serverHealthy) {
                            finishGmailFlow()
                            handleServerUnavailable(onRetry = {
                                processUnreadMessages(account)
                            })
                            return@launch
                        }

                        var scannedCount = 0
                        GmailEmailScanDispatcher.dispatch(pendingEmails) { email ->
                            textTarget.text = buildString {
                                appendLine("From: ${email.sender ?: "Unknown sender"}")
                                email.recipient?.let { appendLine("To: $it") }
                                email.subject?.let { appendLine("Subject: $it") }
                                append("Message: ${email.messageId}")
                            }
                            progressBar.visibility = View.VISIBLE
                            var scanSucceeded = false
                            executeScan(
                                input = email.toScanInput(),
                                notifyTitle = "Threat in email from ${email.sender ?: "unknown sender"}",
                                categorySuffix = "Email",
                                sourceType = "gmail",
                                onScanCompleted = { scanSucceeded = true }
                            ).join()
                            if (scanSucceeded) {
                                ProcessedMessageStore.markProcessed(applicationContext, email.messageId)
                                scannedCount++
                            }
                        }
                        finishGmailFlow(
                            if (scannedCount > 0) "Finished scanning $scannedCount new message(s)."
                            else "No new messages could be scanned."
                        )
                    }
                }
            } catch (_: Exception) {
                finishGmailFlow("An error occurred during Gmail scanning.")
            }
        }
    }

    private fun finishGmailFlow(toastMessage: String? = null) {
        gmailScanInProgress = false
        btnScanGmail.isEnabled = true
        progressBar.visibility = View.GONE
        toastMessage?.let { Toast.makeText(this, it, Toast.LENGTH_LONG).show() }
    }

    private fun gmailFailureMessage(kind: GmailFailureKind): String = when (kind) {
        GmailFailureKind.AUTHENTICATION_REQUIRED -> "Google authentication required. Please sign in again."
        GmailFailureKind.NETWORK -> "Could not reach Google services. Please check your connection."
        GmailFailureKind.TIMEOUT -> "Google sign-in timed out. Please try again."
        GmailFailureKind.API -> "Google Gmail service reported an error."
        GmailFailureKind.PERMISSION_DENIED -> "Gmail permission denied. Please grant required permissions."
        GmailFailureKind.MALFORMED_RESPONSE -> "Gmail response could not be parsed."
    }

    private fun showGmailSetupOrDemoDialog(statusCode: Int?) {
        val isDeveloperError = statusCode == 10 || statusCode == GoogleSignInStatusCodes.DEVELOPER_ERROR
        val message = if (isDeveloperError) {
            "Google Sign-In returned Status 10 (OAuth Configuration Required).\n\n" +
            "Direct Google OAuth in Android requires registering this APK's SHA-1 fingerprint in the Google Cloud Console for 'com.secureshield.ai'.\n\n" +
            "You can test SecureShield AI's multi-engine threat detection immediately using the options below:"
        } else {
            "Google Sign-In returned status ${statusCode ?: "unknown"}.\n\n" +
            "You can test threat scanning immediately with a sample phishing email or custom text:"
        }

        AlertDialog.Builder(this)
            .setTitle("Gmail Protection & AI Scanner")
            .setMessage(message)
            .setPositiveButton("Scan Phishing Sample") { _, _ ->
                scanDemoGmailMessage()
            }
            .setNeutralButton("Paste Text / URL") { _, _ ->
                showCustomInputScanDialog()
            }
            .setNegativeButton("OAuth Setup Info") { _, _ ->
                showOAuthSetupInfoDialog()
            }
            .show()
    }

    private fun showCustomInputScanDialog() {
        val inputEdit = EditText(this).apply {
            hint = "Paste email subject & body, SMS, message, or URL..."
            minLines = 4
            setPadding(36, 36, 36, 36)
            setTextColor(ContextCompat.getColor(this@MainActivity, R.color.text_primary))
            setHintTextColor(ContextCompat.getColor(this@MainActivity, R.color.text_muted))
        }

        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 20, 48, 10)
            addView(inputEdit)
        }

        AlertDialog.Builder(this)
            .setTitle("Custom Threat Analyzer")
            .setMessage("Enter or paste any suspicious email, link, or message text to analyze with SecureShield AI:")
            .setView(container)
            .setPositiveButton("Scan with AI") { _, _ ->
                val textToScan = inputEdit.text.toString().trim()
                if (textToScan.isNotEmpty()) {
                    lifecycleScope.launch {
                        progressBar.visibility = View.VISIBLE
                        badgeCategory.text = "Scanning..."
                        textTarget.text = textToScan.take(120)
                        val input = if (textToScan.startsWith("http://") || textToScan.startsWith("https://")) {
                            ScanInput(url = textToScan)
                        } else {
                            ScanInput(text = textToScan)
                        }
                        executeScan(input, "Custom content scanned", "Custom", "manual").join()
                        progressBar.visibility = View.GONE
                    }
                } else {
                    Toast.makeText(this, "Please enter some text or URL to scan.", Toast.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showOAuthSetupInfoDialog() {
        val sha1 = "7E:66:D5:FD:FA:DF:00:72:A9:5F:CA:1B:0E:63:39:A5:1F:4D:54:8C"
        val packageName = "com.secureshield.ai"
        val infoText = "Package Name:\n$packageName\n\nDebug SHA-1:\n$sha1\n\nTo enable live Google Sign-In on your device:\n1. Open Google Cloud Console -> APIs & Services -> Credentials\n2. Create an OAuth 2.0 Client ID for Android with the Package Name and SHA-1 above\n3. Enable the Gmail API (GMAIL_READONLY scope)"

        AlertDialog.Builder(this)
            .setTitle("OAuth 2.0 Registration Info")
            .setMessage(infoText)
            .setPositiveButton("Copy SHA-1") { _, _ ->
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                val clip = android.content.ClipData.newPlainText("SHA-1", sha1)
                clipboard.setPrimaryClip(clip)
                Toast.makeText(this, "SHA-1 copied to clipboard.", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("Close", null)
            .show()
    }

    private fun showGmailFetchFailureDialog(message: String) {
        AlertDialog.Builder(this)
            .setTitle("Gmail Scan")
            .setMessage(message)
            .setPositiveButton("OK", null)
            .show()
    }

    private fun scanDemoGmailMessage(statusText: String = "Scanning inbox messages...") {
        gmailScanInProgress = true
        btnScanGmail.isEnabled = false
        progressBar.visibility = View.VISIBLE
        badgeCategory.text = statusText

        val demoEmail = GmailEmail(
            messageId = "demo-msg-${System.currentTimeMillis()}",
            sender = "security-alert@fakebank-update.xyz",
            recipient = "user@gmail.com",
            subject = "URGENT: Your account has been suspended",
            bodyText = "Dear customer, your account has been locked due to unauthorized activity. Please verify your identity immediately: http://192.168.1.1@secure-login-verify.xyz/account",
            embeddedUrls = listOf("http://192.168.1.1@secure-login-verify.xyz/account")
        )

        lifecycleScope.launch {
            badgeCategory.text = "Analyzing inbox..."
            val serverHealthy = ApiClient.checkHealth()
            if (!serverHealthy) {
                finishGmailFlow()
                handleServerUnavailable(onRetry = {
                    scanDemoGmailMessage(statusText)
                })
                return@launch
            }

            textTarget.text = buildString {
                appendLine("From: ${demoEmail.sender}")
                demoEmail.recipient?.let { appendLine("To: $it") }
                demoEmail.subject?.let { appendLine("Subject: $it") }
                append("Message: ${demoEmail.messageId}")
            }
            executeScan(demoEmail.toScanInput(), "Gmail message scanned", "Email", "gmail").join()
            finishGmailFlow("Inbox scan complete: 1 message analyzed.")
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
        ensureNotificationPermission()
        updateUniversalGuardUi()
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
                SharedScanKind.FILE -> "File: ${input.file_name}"
                SharedScanKind.URL -> "URL:\n${input.url}"
                SharedScanKind.TEXT -> input.text.orEmpty()
            }
            val sourceType = when (kind) {
                SharedScanKind.FILE -> "file"
                SharedScanKind.URL -> "url"
                SharedScanKind.TEXT -> "share"
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

    private fun executeScan(
        input: ScanInput,
        notifyTitle: String,
        categorySuffix: String,
        sourceType: String = "unknown",
        onScanCompleted: ((UnifiedScanResponse) -> Unit)? = null
    ): Job {
        val resolvedInput = if (input.client_id.isNullOrBlank()) {
            input.copy(client_id = ClientIdProvider.getClientId(applicationContext))
        } else {
            input
        }
        currentResult = null
        layoutFeedback.visibility = View.GONE
        textFeedbackStatus.visibility = View.GONE
        textFeedbackStatus.text = ""
        btnThumbUp.isEnabled = true
        btnThumbDown.isEnabled = true
        btnViewDetails.visibility = View.GONE
        progressBar.visibility = View.VISIBLE
        badgeCategory.setOnClickListener(null)
        textReasons.setOnClickListener(null)
        return lifecycleScope.launch {
            try {
                if (!ApiClient.isServerAwake) {
                    badgeCategory.visibility = View.VISIBLE
                    badgeCategory.text = "Waking server..."
                    textReasons.text = "Connecting to server (Render free tier waking from sleep)..."
                    ApiClient.wakeServerIfNeeded()
                    badgeCategory.text = "Scanning..."
                }

                val response = withTimeout(35000L) {
                    withContext(Dispatchers.IO) {
                        ApiClient.api.scan(resolvedInput)
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
                        btnViewDetails.visibility = View.VISIBLE
                        btnViewDetails.setOnClickListener { showScanDetailDialog(result) }

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
                        applyVerdictBadgeStyle(result.classification)

                        val confidencePct = (result.risk_assessment.confidence * 100).toInt()
                        textScore.text = "Risk Score: ${formatScore(result.risk_score)} / 100 (Conf: ${confidencePct}%)"
                        val assessment = result.risk_assessment
                        val explanationLines = buildList {
                            addAll(assessment.reasons)
                            if (assessment.flags.isNotEmpty()) add("Indicators: ${assessment.flags.joinToString()}")
                            assessment.evidence.forEach { item ->
                                add(item.description?.takeIf(String::isNotBlank) ?: "${item.key}: ${item.value}")
                            }
                            result.warnings.forEach { add("Warning: $it") }
                        }.distinct()
                        textReasons.text = if (explanationLines.isNotEmpty()) explanationLines.first() else "None"
                        textAction.text = result.risk_assessment.recommended_action

                        if (result.warnings.isNotEmpty()) {
                            Toast.makeText(
                                this@MainActivity,
                                "Some checks were unavailable: ${result.warnings.first()}",
                                Toast.LENGTH_LONG
                            ).show()
                        }

                        val isThreat = isThreatClassification(result.classification)
                        updateHeroProtectionState(latestThreat = isThreat)

                        if (isThreat) {
                            sendPushNotification(notifyTitle, "Risk: ${result.classification}")
                        }
                        onScanCompleted?.invoke(result)
                    } else {
                        badgeCategory.text = "Malformed Response (Empty Body)"
                    }
                } else {
                    val sc = response.code()
                    badgeCategory.text = "HTTP Error: $sc"
                }
            } catch (e: ConnectException) {
                handleServerUnavailable(onRetry = {
                    executeScan(resolvedInput, notifyTitle, categorySuffix, sourceType, onScanCompleted)
                })
            } catch (e: TimeoutCancellationException) {
                handleServerUnavailable(onRetry = {
                    executeScan(resolvedInput, notifyTitle, categorySuffix, sourceType, onScanCompleted)
                })
            } catch (e: SocketTimeoutException) {
                handleServerUnavailable(onRetry = {
                    executeScan(resolvedInput, notifyTitle, categorySuffix, sourceType, onScanCompleted)
                })
            } catch (e: MalformedScanResponseException) {
                badgeCategory.text = "Malformed Response: ${e.message}"
            } catch (e: JsonParseException) {
                badgeCategory.text = "Malformed Response: Invalid JSON."
            } catch (e: MalformedJsonException) {
                badgeCategory.text = "Malformed Response: Invalid JSON."
            } catch (e: IOException) {
                handleServerUnavailable(onRetry = {
                    executeScan(resolvedInput, notifyTitle, categorySuffix, sourceType, onScanCompleted)
                })
            } catch (e: Exception) {
                badgeCategory.text = "Scan Error: ${e.message}"
            } finally {
                progressBar.visibility = View.GONE
            }
        }
    }

    private fun applyVerdictBadgeStyle(classification: String) {
        when (classification.lowercase()) {
            "safe" -> {
                badgeCategory.setBackgroundResource(R.drawable.bg_badge_safe)
                badgeCategory.setTextColor(ContextCompat.getColor(this, R.color.threat_safe))
            }
            "suspicious", "deceptive" -> {
                badgeCategory.setBackgroundResource(R.drawable.bg_badge_warning)
                badgeCategory.setTextColor(ContextCompat.getColor(this, R.color.threat_warning))
            }
            "phishing", "malware" -> {
                badgeCategory.setBackgroundResource(R.drawable.bg_badge_threat)
                badgeCategory.setTextColor(ContextCompat.getColor(this, R.color.threat_critical))
            }
            else -> {
                badgeCategory.setBackgroundResource(R.drawable.bg_badge_neutral)
                badgeCategory.setTextColor(ContextCompat.getColor(this, R.color.text_primary))
            }
        }
    }

    private fun showScanDetailDialog(result: UnifiedScanResponse) {
        val view = layoutInflater.inflate(R.layout.dialog_scan_details, null)
        val badge = view.findViewById<TextView>(R.id.dialog_badge_classification)
        val textRisk = view.findViewById<TextView>(R.id.dialog_text_risk_score)
        val textConf = view.findViewById<TextView>(R.id.dialog_text_confidence)
        val textTarget = view.findViewById<TextView>(R.id.dialog_text_target)
        val textAction = view.findViewById<TextView>(R.id.dialog_text_action)
        val textReasons = view.findViewById<TextView>(R.id.dialog_text_reasons)
        val btnClose = view.findViewById<Button>(R.id.dialog_btn_close)

        badge.text = result.classification.uppercase()
        when (result.classification.lowercase()) {
            "safe" -> {
                badge.setBackgroundResource(R.drawable.bg_badge_safe)
                badge.setTextColor(ContextCompat.getColor(this, R.color.threat_safe))
            }
            "suspicious", "deceptive" -> {
                badge.setBackgroundResource(R.drawable.bg_badge_warning)
                badge.setTextColor(ContextCompat.getColor(this, R.color.threat_warning))
            }
            "phishing", "malware" -> {
                badge.setBackgroundResource(R.drawable.bg_badge_threat)
                badge.setTextColor(ContextCompat.getColor(this, R.color.threat_critical))
            }
            else -> {
                badge.setBackgroundResource(R.drawable.bg_badge_neutral)
                badge.setTextColor(ContextCompat.getColor(this, R.color.text_primary))
            }
        }

        val confidencePct = (result.risk_assessment.confidence * 100).toInt()
        textRisk.text = "Risk Score: ${formatScore(result.risk_score)} / 100"
        textConf.text = "Confidence: ${confidencePct}%"

        val targetDisplay = this.textTarget.text.toString().takeIf { it.isNotBlank() } ?: "Scan ID: ${result.scan_id}"
        textTarget.text = "Target: $targetDisplay"

        textAction.text = result.risk_assessment.recommended_action.ifBlank { "No specific action required." }

        val explanationLines = buildList {
            addAll(result.risk_assessment.reasons)
            if (result.risk_assessment.flags.isNotEmpty()) add("Indicators: ${result.risk_assessment.flags.joinToString()}")
            result.risk_assessment.evidence.forEach { item ->
                add(item.description?.takeIf(String::isNotBlank) ?: "${item.key}: ${item.value}")
            }
            result.warnings.forEach { add("Warning: $it") }
        }.distinct()

        textReasons.text = if (explanationLines.isNotEmpty()) explanationLines.joinToString("\n• ", prefix = "• ") else "No specific threat indicators triggered."

        val dialog = AlertDialog.Builder(this)
            .setView(view)
            .create()

        btnClose.setOnClickListener { dialog.dismiss() }
        dialog.show()
    }

    private fun handleServerUnavailable(onRetry: (() -> Unit)? = null) {
        badgeCategory.text = "Service Unavailable"
        badgeCategory.setBackgroundResource(R.drawable.bg_badge_warning)
        badgeCategory.setTextColor(ContextCompat.getColor(this, R.color.threat_warning))
        textScore.text = "SecureShield protection service is unavailable."
        textReasons.text = "Please check your connection and try again."
        textAction.text = "Check connection and retry"
        badgeCategory.setOnClickListener(null)
        textReasons.setOnClickListener(null)
        showServerUnavailableDialog(onRetry)
    }

    private fun showServerUnavailableDialog(onRetry: (() -> Unit)? = null) {
        AlertDialog.Builder(this)
            .setTitle("Service Unavailable")
            .setMessage("SecureShield protection service is unavailable. Please check your connection and try again.")
            .setPositiveButton("Retry") { _, _ ->
                onRetry?.invoke()
            }
            .setNegativeButton("Dismiss", null)
            .show()
    }

    private fun showServerConfigDialog() {
        val view = layoutInflater.inflate(R.layout.dialog_server_settings, null)
        val editUrl = view.findViewById<EditText>(R.id.edit_server_url)
        val textStatus = view.findViewById<TextView>(R.id.text_connection_status)
        val btnTest = view.findViewById<Button>(R.id.btn_test_connection)
        val btnSave = view.findViewById<Button>(R.id.btn_save_settings)

        val currentUrl = ServerSettings.getServerUrl(this)
        editUrl.setText(currentUrl)
        editUrl.setSelection(editUrl.text.length)

        val dialog = AlertDialog.Builder(this)
            .setTitle("Advanced / Developer Settings")
            .setView(view)
            .setNegativeButton("Cancel", null)
            .create()

        btnTest.setOnClickListener {
            val candidateUrl = editUrl.text.toString().trim()
            if (!ServerSettings.isValidServerUrl(candidateUrl)) {
                textStatus.visibility = View.VISIBLE
                textStatus.setTextColor(Color.RED)
                textStatus.text = "Invalid URL format. Must start with http:// or https://"
                return@setOnClickListener
            }
            btnTest.isEnabled = false
            btnTest.text = "TESTING..."
            textStatus.visibility = View.VISIBLE
            textStatus.setTextColor(Color.DKGRAY)
            textStatus.text = "Testing connection..."

            lifecycleScope.launch {
                try {
                    when (val result = ApiClient.testConnection(candidateUrl)) {
                        is ProbeResult.Success -> {
                            textStatus.setTextColor(Color.parseColor("#10B981"))
                            textStatus.text = "✓ Connected! (Latency: ${result.latencyMs}ms)"
                        }
                        is ProbeResult.Failure -> {
                            textStatus.setTextColor(Color.parseColor("#EF4444"))
                            textStatus.text = "✗ Connection failed: ${result.message}"
                        }
                    }
                } finally {
                    btnTest.isEnabled = true
                    btnTest.text = "TEST CONNECTION"
                }
            }
        }

        btnSave.setOnClickListener {
            val candidateUrl = editUrl.text.toString().trim()
            if (!ServerSettings.isValidServerUrl(candidateUrl)) {
                textStatus.visibility = View.VISIBLE
                textStatus.setTextColor(Color.parseColor("#EF4444"))
                textStatus.text = "Invalid URL. Please enter a valid URL."
                return@setOnClickListener
            }
            val saved = ServerSettings.saveServerUrl(this, candidateUrl)
            if (saved) {
                Toast.makeText(this, "Server URL updated to: ${ServerSettings.getServerUrl(this)}", Toast.LENGTH_SHORT).show()
                updateSettingsTab()
                dialog.dismiss()
            } else {
                textStatus.visibility = View.VISIBLE
                textStatus.setTextColor(Color.parseColor("#EF4444"))
                textStatus.text = "Could not save server URL."
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

    private fun isThreatClassification(classification: String): Boolean =
        classification.equals("Suspicious", ignoreCase = true) ||
            classification.equals("Deceptive", ignoreCase = true) ||
            classification.equals("Phishing", ignoreCase = true) ||
            classification.equals("Malware", ignoreCase = true)

    private fun updateBackgroundStatusText(textView: TextView) {
        val enabled = BackgroundProtectionManager.isEnabled(this)
        textView.text = if (enabled) "Background inbox scans enabled" else "Background Protection inactive"
        textView.setTextColor(
            if (enabled) ContextCompat.getColor(this, R.color.threat_safe)
            else ContextCompat.getColor(this, R.color.text_muted)
        )
    }

    private fun formatTimestamp(timestampMillis: Long): String =
        DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(timestampMillis))

    private fun formatScore(score: Float): String =
        String.format(java.util.Locale.US, "%.1f", score)

    override fun onDestroy() {
        if (scanHistoryRepositoryDelegate.isInitialized()) {
            scanHistoryRepository.close()
        }
        super.onDestroy()
    }
}
