package com.secureshield.ai

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.text.InputType
import android.util.Patterns
import android.view.View
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.google.android.gms.auth.api.signin.GoogleSignIn
import com.google.android.gms.auth.api.signin.GoogleSignInAccount
import com.google.android.gms.auth.api.signin.GoogleSignInOptions
import com.google.android.gms.auth.api.signin.GoogleSignInStatusCodes
import com.google.android.gms.common.api.ApiException
import com.google.android.gms.common.api.CommonStatusCodes
import com.google.android.material.button.MaterialButton
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.gson.Gson
import com.google.gson.JsonObject
import com.secureshield.ai.auth.GoogleAuthRequest
import com.secureshield.ai.auth.LoginRequest
import com.secureshield.ai.auth.RegisterRequest
import com.secureshield.ai.auth.UserSessionManager
import com.secureshield.ai.network.ApiClient
import com.secureshield.ai.network.ServerSettings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class LoginActivity : AppCompatActivity() {

    private var isSignUpMode = false
    private var isPasswordVisible = false

    private lateinit var tabSignIn: TextView
    private lateinit var tabSignUp: TextView
    private lateinit var layoutNameContainer: LinearLayout
    private lateinit var layoutAuthStatus: LinearLayout
    private lateinit var textAuthStatus: TextView
    private lateinit var imgAuthStatusIcon: ImageView
    private lateinit var textAutoCreateHint: TextView

    private lateinit var editFullName: EditText
    private lateinit var editEmail: EditText
    private lateinit var editPassword: EditText
    private lateinit var btnTogglePassword: ImageView
    private lateinit var btnSubmitAuth: MaterialButton
    private lateinit var progressAuth: ProgressBar
    private lateinit var btnGoogleSignIn: View
    private lateinit var btnBiometricLogin: View

    private val googleSignInLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            val task = GoogleSignIn.getSignedInAccountFromIntent(result.data)
            try {
                val account: GoogleSignInAccount = task.getResult(ApiException::class.java)
                val email = account.email
                if (email.isNullOrBlank()) {
                    showStatusMessage("Google account email could not be retrieved.", isError = true)
                    return@registerForActivityResult
                }
                executeGoogleAuth(email, account.displayName ?: "", account.idToken)
            } catch (e: ApiException) {
                when (e.statusCode) {
                    CommonStatusCodes.DEVELOPER_ERROR -> { // 10
                        showStatusMessage(
                            "Google Sign-In is not registered in Google Cloud Console (Code 10). Please sign in with Email & Password above.",
                            isError = true
                        )
                        showGoogleDeveloperErrorDialog()
                    }
                    GoogleSignInStatusCodes.SIGN_IN_CANCELLED -> { // 12501
                        // User cancelled Google sign-in dialog - silently reset without jarring red error
                        hideStatusMessage()
                    }
                    CommonStatusCodes.NETWORK_ERROR -> { // 7
                        showStatusMessage("Google sign-in network error. Please check your internet connection.", isError = true)
                    }
                    else -> {
                        showStatusMessage(
                            "Google sign-in unavailable (Code: ${e.statusCode}). Please sign in with Email & Password above.",
                            isError = true
                        )
                    }
                }
            } catch (e: Exception) {
                showStatusMessage("Google sign-in error: ${e.localizedMessage}", isError = true)
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Initialize server settings (URL & pre-shared API keys)
        ServerSettings.init(this)

        // If already logged in, skip to MainActivity directly
        if (UserSessionManager.isLoggedIn(this)) {
            navigateToMain()
            return
        }

        setContentView(R.layout.activity_login)

        tabSignIn = findViewById(R.id.tab_sign_in)
        tabSignUp = findViewById(R.id.tab_sign_up)
        layoutNameContainer = findViewById(R.id.layout_name_container)
        layoutAuthStatus = findViewById(R.id.layout_auth_status)
        textAuthStatus = findViewById(R.id.text_auth_status)
        imgAuthStatusIcon = findViewById(R.id.img_auth_status_icon)
        textAutoCreateHint = findViewById(R.id.text_auto_create_hint)

        editFullName = findViewById(R.id.edit_full_name)
        editEmail = findViewById(R.id.edit_email)
        editPassword = findViewById(R.id.edit_password)
        btnTogglePassword = findViewById(R.id.btn_toggle_password)
        btnSubmitAuth = findViewById(R.id.btn_submit_auth)
        progressAuth = findViewById(R.id.progress_auth)
        btnGoogleSignIn = findViewById(R.id.btn_google_sign_in)
        btnBiometricLogin = findViewById(R.id.btn_biometric_login)

        // Pre-fill previously remembered email if present
        val savedEmail = UserSessionManager.getUserEmail(this)
        if (savedEmail.isNotBlank()) {
            editEmail.setText(savedEmail)
        }

        setupTabs()
        setupPasswordToggle()
        setupAuthSubmission()
        setupGoogleSignIn()
        setupBiometricUnlock()
    }

    private fun setupTabs() {
        tabSignIn.setOnClickListener {
            if (isSignUpMode) {
                isSignUpMode = false
                updateTabUi()
            }
        }

        tabSignUp.setOnClickListener {
            if (!isSignUpMode) {
                isSignUpMode = true
                updateTabUi()
            }
        }

        textAutoCreateHint.setOnClickListener {
            isSignUpMode = !isSignUpMode
            updateTabUi()
        }

        layoutAuthStatus.setOnClickListener {
            if (!isSignUpMode) {
                isSignUpMode = true
                updateTabUi()
            }
        }
    }

    private fun updateTabUi() {
        hideStatusMessage()
        if (isSignUpMode) {
            tabSignUp.setBackgroundResource(R.drawable.bg_auth_tab_selected)
            tabSignUp.setTextColor(ContextCompat.getColor(this, R.color.cyber_cyan))

            tabSignIn.setBackgroundResource(android.R.color.transparent)
            tabSignIn.setTextColor(ContextCompat.getColor(this, R.color.text_secondary))

            layoutNameContainer.visibility = View.VISIBLE
            textAutoCreateHint.visibility = View.VISIBLE
            textAutoCreateHint.text = "Already have an account? Tap here to SIGN IN."
            btnSubmitAuth.text = "CREATE ACCOUNT"
        } else {
            tabSignIn.setBackgroundResource(R.drawable.bg_auth_tab_selected)
            tabSignIn.setTextColor(ContextCompat.getColor(this, R.color.cyber_cyan))

            tabSignUp.setBackgroundResource(android.R.color.transparent)
            tabSignUp.setTextColor(ContextCompat.getColor(this, R.color.text_secondary))

            layoutNameContainer.visibility = View.GONE
            textAutoCreateHint.visibility = View.VISIBLE
            textAutoCreateHint.text = "⚡ New here? Tap here to REGISTER and create your account."
            btnSubmitAuth.text = "SIGN IN"
        }
    }

    private fun setupPasswordToggle() {
        btnTogglePassword.setOnClickListener {
            isPasswordVisible = !isPasswordVisible
            val selection = editPassword.selectionEnd
            if (isPasswordVisible) {
                editPassword.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            } else {
                editPassword.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            }
            editPassword.setSelection(selection)
        }
    }

    private fun setupAuthSubmission() {
        btnSubmitAuth.setOnClickListener {
            val email = editEmail.text.toString().trim()
            val password = editPassword.text.toString().trim()
            val fullName = editFullName.text.toString().trim()

            if (email.isEmpty() || !Patterns.EMAIL_ADDRESS.matcher(email).matches()) {
                showStatusMessage("Please enter a valid email address.", isError = true)
                editEmail.requestFocus()
                return@setOnClickListener
            }

            if (password.length < 6) {
                showStatusMessage("Password must be at least 6 characters.", isError = true)
                editPassword.requestFocus()
                return@setOnClickListener
            }

            if (isSignUpMode) {
                executeRegister(email, password, fullName)
            } else {
                executeLogin(email, password, fullName)
            }
        }
    }

    private fun executeLogin(email: String, password: String, fullName: String) {
        setLoading(true)
        hideStatusMessage()

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val response = ApiClient.api.login(
                    LoginRequest(email = email, password = password, full_name = fullName)
                )

                withContext(Dispatchers.Main) {
                    setLoading(false)
                    if (response.isSuccessful && response.body() != null) {
                        val auth = response.body()!!
                        UserSessionManager.saveSession(this@LoginActivity, auth)
                        Toast.makeText(this@LoginActivity, "Authenticated. Loading private vault...", Toast.LENGTH_SHORT).show()
                        navigateToMain()
                    } else {
                        val errorJson = response.errorBody()?.string() ?: ""
                        val parsedMessage = parseErrorMessage(errorJson, "Invalid credentials or account not found. Tap REGISTER above to create your account.")
                        showStatusMessage(parsedMessage, isError = true)
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    setLoading(false)
                    showStatusMessage("Connection to defense server failed: ${e.localizedMessage}", isError = true)
                }
            }
        }
    }

    private fun executeRegister(email: String, password: String, fullName: String) {
        setLoading(true)
        hideStatusMessage()

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val response = ApiClient.api.register(
                    RegisterRequest(email = email, password = password, full_name = fullName)
                )

                withContext(Dispatchers.Main) {
                    setLoading(false)
                    if (response.isSuccessful && response.body() != null) {
                        val auth = response.body()!!
                        UserSessionManager.saveSession(this@LoginActivity, auth)
                        Toast.makeText(
                            this@LoginActivity,
                            "Secure account created! Threat vault initialized.",
                            Toast.LENGTH_LONG
                        ).show()
                        navigateToMain()
                    } else if (response.code() == 409) {
                        // Crucial Requirement: "when a user clicks sign up and entered details which he is already registere then app should say user already existed like that."
                        val errorJson = response.errorBody()?.string() ?: ""
                        val msg = parseErrorMessage(
                            errorJson,
                            "User already exists. Please sign in or use Google."
                        )
                        showStatusMessage(msg, isError = true)
                    } else {
                        val errorJson = response.errorBody()?.string() ?: ""
                        val msg = parseErrorMessage(errorJson, "Registration could not be completed.")
                        showStatusMessage(msg, isError = true)
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    setLoading(false)
                    showStatusMessage("Registration error: ${e.localizedMessage}", isError = true)
                }
            }
        }
    }

    private fun setupGoogleSignIn() {
        val gsoBuilder = GoogleSignInOptions.Builder(GoogleSignInOptions.DEFAULT_SIGN_IN)
            .requestEmail()
            .requestProfile()

        val clientIdResId = resources.getIdentifier("default_web_client_id", "string", packageName)
        if (clientIdResId != 0) {
            try {
                val clientId = getString(clientIdResId)
                if (clientId.isNotBlank() && !clientId.startsWith("your-") && clientId.contains(".apps.googleusercontent.com")) {
                    gsoBuilder.requestIdToken(clientId)
                }
            } catch (_: Exception) {}
        }

        val googleClient = GoogleSignIn.getClient(this, gsoBuilder.build())

        btnGoogleSignIn.setOnClickListener {
            hideStatusMessage()
            try {
                val signInIntent = googleClient.signInIntent
                googleSignInLauncher.launch(signInIntent)
            } catch (e: Exception) {
                showStatusMessage("Google Sign-In unavailable: ${e.localizedMessage}", isError = true)
            }
        }
    }

    private fun setupBiometricUnlock() {
        val executor = ContextCompat.getMainExecutor(this)
        var pendingWrapper: UserSessionManager.BiometricCipherWrapper? = null

        val biometricPrompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    pendingWrapper = null
                    if (errorCode != BiometricPrompt.ERROR_USER_CANCELED && errorCode != BiometricPrompt.ERROR_NEGATIVE_BUTTON) {
                        showStatusMessage("Biometric unlock: $errString", isError = true)
                    }
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    val wrapper = pendingWrapper
                    pendingWrapper = null

                    // Strict cryptographic enforcement: Require authenticated cipher from CryptoObject
                    val authenticatedCipher = result.cryptoObject?.cipher
                    if (wrapper == null || authenticatedCipher == null) {
                        showStatusMessage("Biometric authentication lacked required cryptographic proof. Please sign in with your password.", isError = true)
                        return
                    }

                    val decryptedToken = UserSessionManager.completeBiometricDecryption(
                        this@LoginActivity,
                        authenticatedCipher,
                        wrapper.cipherText
                    )
                    if (!decryptedToken.isNullOrBlank()) {
                        Toast.makeText(this@LoginActivity, "Biometric verified. Unlocking vault...", Toast.LENGTH_SHORT).show()
                        navigateToMain()
                    } else {
                        showStatusMessage("Cryptographic session decryption failed. Key may have been invalidated. Please sign in with your password.", isError = true)
                    }
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    showStatusMessage("Biometric not recognized. Please try again.", isError = true)
                }
            })

        btnBiometricLogin.setOnClickListener {
            hideStatusMessage()
            val biometricManager = BiometricManager.from(this)
            val authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG or 
                                 BiometricManager.Authenticators.BIOMETRIC_WEAK or 
                                 BiometricManager.Authenticators.DEVICE_CREDENTIAL

            when (biometricManager.canAuthenticate(authenticators)) {
                BiometricManager.BIOMETRIC_SUCCESS -> {
                    // Session check: A user must have an existing session to unlock via biometrics
                    if (!UserSessionManager.isLoggedIn(this)) {
                        showStatusMessage("No active session found. Please sign in with email and password to initialize your account.", isError = false)
                        return@setOnClickListener
                    }

                    // Cryptographic Keystore key check: Must prepare authenticated decryption cipher
                    val wrapper = UserSessionManager.createBiometricDecryptCipher(this)
                    if (wrapper == null) {
                        showStatusMessage("Session key invalidated or unavailable. Please enter your password to re-authenticate.", isError = true)
                        return@setOnClickListener
                    }

                    val promptInfo = BiometricPrompt.PromptInfo.Builder()
                        .setTitle("Touch / Face ID Unlock")
                        .setSubtitle("Confirm your biometric credentials to decrypt your session")
                        .setAllowedAuthenticators(authenticators)
                        .build()

                    pendingWrapper = wrapper
                    try {
                        // Strict requirement: Never fall back to unauthenticated prompt without CryptoObject
                        biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(wrapper.cipher))
                    } catch (e: Exception) {
                        pendingWrapper = null
                        showStatusMessage("Biometric cryptographic hardware initialization failed. Please enter your password to sign in.", isError = true)
                    }
                }
                BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> {
                    showStatusMessage("No biometric sensor detected on this device.", isError = true)
                }
                BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> {
                    showStatusMessage("Biometric sensor is currently busy or unavailable.", isError = true)
                }
                BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                    showStatusMessage("No fingerprint or face registered. Please enroll one in Android Settings.", isError = true)
                }
                else -> {
                    showStatusMessage("Biometric authentication is not supported or enabled on this device.", isError = true)
                }
            }
        }
    }

    private fun executeGoogleAuth(email: String, fullName: String, idToken: String?) {
        setLoading(true)
        hideStatusMessage()

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val response = ApiClient.api.googleAuth(
                    GoogleAuthRequest(email = email, full_name = fullName, id_token = idToken)
                )

                withContext(Dispatchers.Main) {
                    setLoading(false)
                    if (response.isSuccessful && response.body() != null) {
                        val auth = response.body()!!
                        UserSessionManager.saveSession(this@LoginActivity, auth)
                        Toast.makeText(
                            this@LoginActivity,
                            "Google authentication verified. Threat vault active.",
                            Toast.LENGTH_LONG
                        ).show()
                        navigateToMain()
                    } else {
                        val errorJson = response.errorBody()?.string() ?: ""
                        val msg = parseErrorMessage(errorJson, "Google authentication could not be completed.")
                        showStatusMessage(msg, isError = true)
                    }
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    setLoading(false)
                    showStatusMessage("Google auth error: ${e.localizedMessage}", isError = true)
                }
            }
        }
    }

    private fun showStatusMessage(message: String, isError: Boolean) {
        layoutAuthStatus.visibility = View.VISIBLE
        textAuthStatus.text = message
        if (isError) {
            imgAuthStatusIcon.setImageResource(R.drawable.ic_shield_alert)
            imgAuthStatusIcon.setColorFilter(ContextCompat.getColor(this, R.color.risk_high))
            textAuthStatus.setTextColor(ContextCompat.getColor(this, R.color.risk_high))
        } else {
            imgAuthStatusIcon.setImageResource(R.drawable.ic_shield_protected)
            imgAuthStatusIcon.setColorFilter(ContextCompat.getColor(this, R.color.cyber_cyan))
            textAuthStatus.setTextColor(ContextCompat.getColor(this, R.color.cyber_cyan))
        }
    }

    private fun hideStatusMessage() {
        layoutAuthStatus.visibility = View.GONE
    }

    private fun setLoading(loading: Boolean) {
        btnSubmitAuth.isEnabled = !loading
        btnGoogleSignIn.isEnabled = !loading
        progressAuth.visibility = if (loading) View.VISIBLE else View.GONE
    }

    private fun parseErrorMessage(errorBody: String, defaultMessage: String): String {
        return try {
            val json = Gson().fromJson(errorBody, JsonObject::class.java)
            if (json.has("detail")) {
                val detail = json.get("detail")
                if (detail.isJsonObject && detail.asJsonObject.has("message")) {
                    detail.asJsonObject.get("message").asString
                } else if (detail.isJsonPrimitive) {
                    detail.asString
                } else {
                    defaultMessage
                }
            } else {
                defaultMessage
            }
        } catch (_: Exception) {
            defaultMessage
        }
    }

    private fun getAppSha1Fingerprint(): String {
        return try {
            val packageInfo = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                packageManager.getPackageInfo(packageName, android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES)
            } else {
                @Suppress("DEPRECATION")
                packageManager.getPackageInfo(packageName, android.content.pm.PackageManager.GET_SIGNATURES)
            }
            val signatures = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                packageInfo.signingInfo?.apkContentsSigners
            } else {
                @Suppress("DEPRECATION")
                packageInfo.signatures
            }
            val cert = signatures?.firstOrNull()?.toByteArray() ?: return "7E:66:D5:FD:FA:DF:00:72:A9:5F:CA:1B:0E:63:39:A5:1F:4D:54:8C"
            val md = java.security.MessageDigest.getInstance("SHA-1")
            val digest = md.digest(cert)
            digest.joinToString(":") { "%02X".format(it) }
        } catch (_: Exception) {
            "7E:66:D5:FD:FA:DF:00:72:A9:5F:CA:1B:0E:63:39:A5:1F:4D:54:8C"
        }
    }

    private fun showGoogleDeveloperErrorDialog() {
        val sha1 = getAppSha1Fingerprint()
        val pkg = packageName

        val message = "Google Play Services returned Code 10 (DEVELOPER_ERROR).\n\n" +
            "Google Sign-In requires registering this app's package and SHA-1 signing key in Google Cloud Console (APIs & Services > Credentials > OAuth 2.0 Client ID > Android):\n\n" +
            "• Package Name:\n$pkg\n\n" +
            "• SHA-1 Fingerprint:\n$sha1\n\n" +
            "You can sign in immediately using Email & Password above, or tap 'Copy SHA-1' to configure it in Google Cloud."

        MaterialAlertDialogBuilder(this)
            .setTitle("Google Sign-In Setup")
            .setMessage(message)
            .setPositiveButton("Copy SHA-1") { _, _ ->
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val clip = ClipData.newPlainText("SecureShield SHA-1", sha1)
                clipboard.setPrimaryClip(clip)
                Toast.makeText(this, "SHA-1 fingerprint copied to clipboard!", Toast.LENGTH_LONG).show()
                editEmail.requestFocus()
            }
            .setNeutralButton("Sign In with Email") { _, _ ->
                editEmail.requestFocus()
            }
            .setNegativeButton("Close", null)
            .show()
    }

    private fun navigateToMain() {
        val intent = Intent(this, MainActivity::class.java)
        intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        startActivity(intent)
        finish()
    }
}
