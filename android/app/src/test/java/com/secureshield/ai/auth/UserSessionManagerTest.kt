package com.secureshield.ai.auth

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

@RunWith(AndroidJUnit4::class)
class UserSessionManagerTest {

    private lateinit var context: Context
    private lateinit var testKey: SecretKey

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        UserSessionManager.clearSession(context)
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(256)
        testKey = keyGen.generateKey()
        UserSessionManager.secretKeyProvider = { testKey }
    }

    @After
    fun tearDown() {
        UserSessionManager.secretKeyProvider = null
        UserSessionManager.clearSession(context)
    }

    private fun createSampleAuth(token: String = "valid_sample_token_secret_12345"): AuthResponse {
        return AuthResponse(
            status = "authenticated",
            message = "Success",
            token = token,
            user = UserResponse(
                user_id = "usr_998877665544",
                email = "alice@secureshield.ai",
                full_name = "Alice Security",
                provider = "local",
                db_file = "secureshield_user_usr_998877665544.db",
                created_at = "2026-01-01T00:00:00Z",
                last_login_at = "2026-01-01T00:00:00Z"
            )
        )
    }

    @Test
    fun testSuccessfulSaveAndRetrieveSession() {
        val sample = createSampleAuth()
        val saved = UserSessionManager.saveSession(context, sample)
        assertTrue("Session must save successfully when key is valid", saved)

        assertTrue(UserSessionManager.isLoggedIn(context))
        assertEquals("usr_998877665544", UserSessionManager.getUserId(context))
        assertEquals("alice@secureshield.ai", UserSessionManager.getUserEmail(context))
        assertEquals("Alice Security", UserSessionManager.getUserFullName(context))

        val retrievedToken = UserSessionManager.getAuthToken(context)
        assertNotNull("Retrieved token must not be null", retrievedToken)
        assertEquals("valid_sample_token_secret_12345", retrievedToken)
    }

    @Test
    fun testEncryptionFailureDoesNotSaveSession() {
        // Simulate hardware Keystore failure returning null key
        UserSessionManager.secretKeyProvider = { null }

        val sample = createSampleAuth()
        val saved = UserSessionManager.saveSession(context, sample)

        // Must reject saving session without secure hardware encryption
        assertFalse("Session saving must fail if keystore cannot encrypt", saved)
        assertFalse("User must not be logged in after failed encryption", UserSessionManager.isLoggedIn(context))
        assertNull("Auth token must not be persisted in plaintext", UserSessionManager.getAuthToken(context))
    }

    @Test
    fun testDecryptionFailureInvalidatesSession() {
        val sample = createSampleAuth("confidential_token_xyz")
        val saved = UserSessionManager.saveSession(context, sample)
        assertTrue(saved)
        assertTrue(UserSessionManager.isLoggedIn(context))

        // Simulate key invalidation or key rotation by providing a different key
        val differentKeyGen = KeyGenerator.getInstance("AES")
        differentKeyGen.init(256)
        val rotatedKey = differentKeyGen.generateKey()
        UserSessionManager.secretKeyProvider = { rotatedKey }

        // Attempting to read token with mismatched key fails decryption and invalidates session
        val decryptedToken = UserSessionManager.getAuthToken(context)
        assertNull("Decryption with invalidated key must return null", decryptedToken)
        assertFalse("Session must be immediately cleared upon decryption failure", UserSessionManager.isLoggedIn(context))
    }

    @Test
    fun testTamperedCiphertextClearsSession() {
        val sample = createSampleAuth("tamper_test_token")
        UserSessionManager.saveSession(context, sample)

        // Corrupt the stored encrypted token in preferences
        val prefs = context.getSharedPreferences("secureshield_auth_session", Context.MODE_PRIVATE)
        prefs.edit().putString("auth_token_enc", "CorruptedInvalidBase64Payload==").apply()

        val token = UserSessionManager.getAuthToken(context)
        assertNull("Tampered payload must return null token", token)
        assertFalse("Tampered payload must clear active session", UserSessionManager.isLoggedIn(context))
    }

    @Test
    fun testClearSessionWipesAllData() {
        val sample = createSampleAuth()
        UserSessionManager.saveSession(context, sample)
        assertTrue(UserSessionManager.isLoggedIn(context))

        UserSessionManager.clearSession(context)
        assertFalse(UserSessionManager.isLoggedIn(context))
        assertEquals("guest", UserSessionManager.getUserId(context))
        assertEquals("", UserSessionManager.getUserEmail(context))
        assertNull(UserSessionManager.getAuthToken(context))
    }

    @Test
    fun testBiometricCipherGatedDecryptionSuccess() {
        val sample = createSampleAuth("biometric_gated_token_9988")
        val saved = UserSessionManager.saveSession(context, sample)
        assertTrue(saved)

        // Prepare biometric decrypt cipher
        val wrapper = UserSessionManager.createBiometricDecryptCipher(context)
        assertNotNull("Biometric cipher wrapper must be created", wrapper)
        assertNotNull("Cipher instance must be initialized", wrapper!!.cipher)

        // Complete decryption after simulated biometric authentication
        val decrypted = UserSessionManager.completeBiometricDecryption(context, wrapper.cipher, wrapper.cipherText)
        assertNotNull(decrypted)
        assertEquals("biometric_gated_token_9988", decrypted)
        assertTrue(UserSessionManager.isLoggedIn(context))
    }

    @Test
    fun testBiometricDecryptionWithCorruptedDataClearsSession() {
        val sample = createSampleAuth("token_to_fail")
        UserSessionManager.saveSession(context, sample)
        val wrapper = UserSessionManager.createBiometricDecryptCipher(context)
        assertNotNull(wrapper)

        // Corrupt ciphertext
        val corruptedBytes = byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7)
        val decrypted = UserSessionManager.completeBiometricDecryption(context, wrapper!!.cipher, corruptedBytes)
        assertNull("Decryption of corrupted bytes must fail", decrypted)
        assertFalse("Corrupted decryption must wipe active session", UserSessionManager.isLoggedIn(context))
    }
}

