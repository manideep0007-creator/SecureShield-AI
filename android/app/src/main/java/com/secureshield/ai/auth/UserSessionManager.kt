package com.secureshield.ai.auth

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.annotation.VisibleForTesting
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

object UserSessionManager {
    private const val PREFS_NAME = "secureshield_auth_session"
    private const val KEY_IS_LOGGED_IN = "is_logged_in"
    private const val KEY_USER_ID = "user_id"
    private const val KEY_EMAIL = "email"
    private const val KEY_FULL_NAME = "full_name"
    private const val KEY_PROVIDER = "provider"
    private const val KEY_TOKEN = "auth_token_enc"
    private const val KEY_DB_FILE = "db_file"

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "SecureShieldSessionKey"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val GCM_IV_LENGTH = 12
    private const val GCM_TAG_LENGTH = 128

    @set:VisibleForTesting
    internal var secretKeyProvider: (() -> SecretKey?)? = null

    private fun getSecretKey(): SecretKey? {
        secretKeyProvider?.let { return it.invoke() }
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            if (!keyStore.containsAlias(KEY_ALIAS)) {
                val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
                val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build()
                keyGenerator.init(keyGenParameterSpec)
                keyGenerator.generateKey()
            } else {
                keyStore.getKey(KEY_ALIAS, null) as? SecretKey
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun encrypt(plainText: String): String? {
        return try {
            val key = getSecretKey() ?: return null
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val iv = cipher.iv
            val encryptedBytes = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))
            val combined = ByteArray(iv.size + encryptedBytes.size)
            System.arraycopy(iv, 0, combined, 0, iv.size)
            System.arraycopy(encryptedBytes, 0, combined, iv.size, encryptedBytes.size)
            Base64.encodeToString(combined, Base64.NO_WRAP)
        } catch (_: Exception) {
            null
        }
    }

    private fun decrypt(encryptedBase64: String?): String? {
        if (encryptedBase64.isNullOrBlank()) return null
        return try {
            val combined = Base64.decode(encryptedBase64, Base64.NO_WRAP)
            if (combined.size <= GCM_IV_LENGTH) return null
            val key = getSecretKey() ?: return null
            val iv = ByteArray(GCM_IV_LENGTH)
            val cipherText = ByteArray(combined.size - GCM_IV_LENGTH)
            System.arraycopy(combined, 0, iv, 0, GCM_IV_LENGTH)
            System.arraycopy(combined, GCM_IV_LENGTH, cipherText, 0, cipherText.size)

            val cipher = Cipher.getInstance(TRANSFORMATION)
            val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
            cipher.init(Cipher.DECRYPT_MODE, key, spec)
            String(cipher.doFinal(cipherText), Charsets.UTF_8)
        } catch (_: Exception) {
            null
        }
    }

    private fun getPrefs(context: Context): SharedPreferences {
        return context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    fun saveSession(context: Context, auth: AuthResponse): Boolean {
        val encryptedToken = encrypt(auth.token) ?: return false
        getPrefs(context).edit().apply {
            putBoolean(KEY_IS_LOGGED_IN, true)
            putString(KEY_USER_ID, auth.user.user_id)
            putString(KEY_EMAIL, auth.user.email)
            putString(KEY_FULL_NAME, auth.user.full_name)
            putString(KEY_PROVIDER, auth.user.provider)
            putString(KEY_TOKEN, encryptedToken)
            putString(KEY_DB_FILE, auth.user.db_file)
            apply()
        }
        return true
    }

    fun isLoggedIn(context: Context): Boolean {
        return getPrefs(context).getBoolean(KEY_IS_LOGGED_IN, false)
    }

    fun getUserId(context: Context): String {
        return getPrefs(context).getString(KEY_USER_ID, "guest") ?: "guest"
    }

    fun getUserEmail(context: Context): String {
        return getPrefs(context).getString(KEY_EMAIL, "") ?: ""
    }

    fun getUserFullName(context: Context): String {
        return getPrefs(context).getString(KEY_FULL_NAME, "User") ?: "User"
    }

    fun getAuthToken(context: Context): String? {
        val rawOrEncrypted = getPrefs(context).getString(KEY_TOKEN, null) ?: return null
        val decrypted = decrypt(rawOrEncrypted)
        if (decrypted == null) {
            // Decryption failure: cryptographic key was invalidated, rotated, or session storage was tampered.
            // Invalidate session immediately to prevent insecure authentication state.
            clearSession(context)
            return null
        }
        return decrypted
    }

    fun getUserDatabaseName(context: Context): String {
        val uid = getUserId(context)
        return "secureshield_user_${uid}.db"
    }

    fun clearSession(context: Context) {
        getPrefs(context).edit().clear().apply()
    }
}
