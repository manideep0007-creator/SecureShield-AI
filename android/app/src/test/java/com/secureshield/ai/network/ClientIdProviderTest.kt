package com.secureshield.ai.network

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class ClientIdProviderTest {

    private lateinit var context: Context

    @Before
    fun setup() {
        context = ApplicationProvider.getApplicationContext()
        ClientIdProvider.setClientIdForTesting(context, null)
    }

    @After
    fun teardown() {
        ClientIdProvider.setClientIdForTesting(context, null)
    }

    @Test
    fun `getClientId generates valid UUID when empty`() {
        val id = ClientIdProvider.getClientId(context)
        assertNotNull(id)
        assertTrue("Client ID must be a non-empty string", id.isNotBlank())
        // Verify UUID format
        val parsed = UUID.fromString(id)
        assertNotNull(parsed)
    }

    @Test
    fun `getClientId returns consistent UUID across multiple invocations`() {
        val id1 = ClientIdProvider.getClientId(context)
        val id2 = ClientIdProvider.getClientId(context)
        val id3 = ClientIdProvider.getClientId(context)

        assertEquals(id1, id2)
        assertEquals(id2, id3)
    }

    @Test
    fun `getClientId restores persisted UUID across in-memory cache resets`() {
        val initialId = ClientIdProvider.getClientId(context)
        
        // Reset in-memory cache while preserving SharedPreferences
        ClientIdProvider.setClientIdForTesting(null, null)

        val restoredId = ClientIdProvider.getClientId(context)
        assertEquals(initialId, restoredId)
    }

    @Test
    fun `two distinct devices have different client IDs`() {
        val device1Id = ClientIdProvider.getClientId(context)

        // Simulate a second device with clean preferences
        val secondContext = ApplicationProvider.getApplicationContext<Context>()
        val prefs = secondContext.getSharedPreferences("secureshield_client_prefs", Context.MODE_PRIVATE)
        prefs.edit().clear().commit()
        ClientIdProvider.setClientIdForTesting(null, null)

        val device2Id = ClientIdProvider.getClientId(secondContext)
        assertNotEquals(device1Id, device2Id)
    }
}
