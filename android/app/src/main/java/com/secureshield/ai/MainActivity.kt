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
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.lifecycle.lifecycleScope
import com.google.android.gms.auth.api.signin.GoogleSignIn
import com.google.android.gms.auth.api.signin.GoogleSignInOptions
import com.google.android.gms.common.api.Scope
import com.google.api.services.gmail.GmailScopes
import com.secureshield.ai.network.ApiClient
import com.secureshield.ai.network.ScanInput
import com.secureshield.ai.network.UnifiedScanResponse
import com.secureshield.ai.network.FeedbackRequest
import com.secureshield.ai.network.MalformedScanResponseException
import com.secureshield.ai.network.UnifiedScanResponseParser
import com.secureshield.ai.network.fileBytesAsBackendJsonValue
import com.secureshield.ai.share.ShareDispatchResult
import com.secureshield.ai.share.SharedFileReadResult
import com.secureshield.ai.share.SharedIntentPayload
import com.secureshield.ai.share.SharedIntentRouter
import com.google.gson.JsonParseException
import com.google.gson.stream.MalformedJsonException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
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

    private val googleSignInLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val task = GoogleSignIn.getSignedInAccountFromIntent(result.data)
        try {
            val account = task.getResult(com.google.android.gms.common.api.ApiException::class.java)
            if (account != null) {
                processLatestEmail(account)
            }
        } catch (e: Exception) {
            badgeCategory.text = "OAuth Unregistered. Simulating Demo Email..."
            simulateGmailFetch()
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

        val btnBackgroundMonitor = findViewById<Button>(R.id.btn_background_monitor)
        btnBackgroundMonitor.setOnClickListener {
            Toast.makeText(this, "Monitoring background... (Wait 5s)", Toast.LENGTH_LONG).show()
            
            val intent = Intent(Intent.ACTION_MAIN)
            intent.addCategory(Intent.CATEGORY_HOME)
            intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK
            startActivity(intent)

            lifecycleScope.launch {
                kotlinx.coroutines.delay(5000) 
                simulateGmailFetch()
            }
        }

        btnScanGmail.setOnClickListener {
            val gso = GoogleSignInOptions.Builder(GoogleSignInOptions.DEFAULT_SIGN_IN)
                .requestEmail()
                .requestScopes(Scope(GmailScopes.GMAIL_READONLY))
                .build()
            val mGoogleSignInClient = GoogleSignIn.getClient(this, gso)
            googleSignInLauncher.launch(mGoogleSignInClient.signInIntent)
        }

        handleIntent(intent)
    }

    private fun submitFeedback(value: String) {
        currentResult?.let { res ->
            layoutFeedback.visibility = View.GONE
            Toast.makeText(this, "Feedback saved!", Toast.LENGTH_SHORT).show()
            lifecycleScope.launch {
                try {
                    withContext(Dispatchers.IO) {
                        ApiClient.api.sendFeedback(FeedbackRequest(res.scan_id, res.risk_score.toInt(), res.classification, value))
                    }
                } catch (e: Exception) {
                    e.printStackTrace()
                }
            }
        }
    }

    private fun processLatestEmail(account: com.google.android.gms.auth.api.signin.GoogleSignInAccount) {
        badgeCategory.text = "Fetching Gmail..."
        progressBar.visibility = View.VISIBLE

        lifecycleScope.launch {
            val scanner = GmailScanner(this@MainActivity, account)
            val msgData = scanner.getLatestMessageData()

            if (msgData == null) {
                progressBar.visibility = View.GONE
                badgeCategory.text = "No Unread Emails Found."
                return@launch
            }

            if (msgData.bodyText.isBlank() && msgData.extractedUrl == null) {
                progressBar.visibility = View.GONE
                badgeCategory.text = "Email contains no parseable text or links."
                return@launch
            }

            badgeCategory.text = "Scanning Email..."
            textTarget.text = "Sender: ${msgData.sender}\nExtracted Link: ${msgData.extractedUrl ?: "None"}"

            executeScan(ScanInput(text = msgData.bodyText, url = msgData.extractedUrl, sender_id = msgData.sender, source_channel = "gmail"), "Gmail Source Scanned", "Email")
        }
    }

    private fun simulateGmailFetch() {
        progressBar.visibility = View.VISIBLE
        badgeCategory.text = "Scanning Demo Email..."
        textTarget.text = "Sender: support@amazon-refunds.com\nExtracted Link: http://192.168.1.1@secure-login-verify.xyz/account"

        val input = ScanInput(
            text = "URGENT! Your account is locked! Please verify your password and send a gift card immediately.",
            url = "http://192.168.1.1@secure-login-verify.xyz/account",
            sender_id = "support@amazon-refunds.com",
            source_channel = "demo_email"
        )
        executeScan(input, "Gmail Demo Scanned", "Email")
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        if (intent == null) return
        setIntent(intent)
        handleIntent(intent)
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
            executeScan(input, "Shared content scanned", kind.label)
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

    private fun executeScan(input: ScanInput, notifyTitle: String, categorySuffix: String) {
        lifecycleScope.launch {
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
