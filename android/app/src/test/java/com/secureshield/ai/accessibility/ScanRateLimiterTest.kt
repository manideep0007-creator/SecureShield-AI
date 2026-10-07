package com.secureshield.ai.accessibility

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ScanRateLimiterTest {

    @Test
    fun tryAcquire_withinLimit_allowsUpToMaxScans() {
        val limiter = ScanRateLimiter(maxScansPerMinute = 3, windowMillis = 60_000L)
        val now = 100_000L

        assertTrue("First scan should be allowed", limiter.tryAcquire(now))
        assertTrue("Second scan should be allowed", limiter.tryAcquire(now + 1000))
        assertTrue("Third scan should be allowed", limiter.tryAcquire(now + 2000))
        assertEquals(3, limiter.currentScanCount(now + 2000))
    }

    @Test
    fun tryAcquire_exceedingLimit_dropsExcessImmediately() {
        val limiter = ScanRateLimiter(maxScansPerMinute = 2, windowMillis = 60_000L)
        val now = 100_000L

        assertTrue(limiter.tryAcquire(now))
        assertTrue(limiter.tryAcquire(now + 1000))

        // Exceeded limit: must return false (drop immediately, do not queue)
        assertFalse("Excess scan 1 must be dropped immediately", limiter.tryAcquire(now + 2000))
        assertFalse("Excess scan 2 must be dropped immediately", limiter.tryAcquire(now + 3000))
        assertEquals(2, limiter.currentScanCount(now + 3000))
    }

    @Test
    fun tryAcquire_afterWindowExpires_allowsNewScans() {
        val limiter = ScanRateLimiter(maxScansPerMinute = 2, windowMillis = 60_000L)
        val now = 100_000L

        assertTrue(limiter.tryAcquire(now))
        assertTrue(limiter.tryAcquire(now + 10_000))
        assertFalse(limiter.tryAcquire(now + 20_000))

        // Jump ahead by 61 seconds (outside window)
        val afterWindow = now + 65_000L
        assertTrue("After 65s, first expired scan should make room for a new scan", limiter.tryAcquire(afterWindow))
    }
}
