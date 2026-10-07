package com.secureshield.ai.accessibility

/**
 * Hard rate-limiter enforcing a maximum of N scans per minute.
 * Drops excess scans immediately without queuing.
 */
class ScanRateLimiter(
    val maxScansPerMinute: Int = 10,
    private val windowMillis: Long = 60_000L
) {
    private val scanTimestamps = ArrayDeque<Long>()

    /**
     * Attempts to acquire a scan permit.
     * Returns true if permitted, false if rate limit is reached (caller must drop the scan).
     */
    @Synchronized
    fun tryAcquire(currentTimeMillis: Long = System.currentTimeMillis()): Boolean {
        // Evict expired timestamps outside the rolling window
        while (scanTimestamps.isNotEmpty() && currentTimeMillis - scanTimestamps.first() > windowMillis) {
            scanTimestamps.removeFirst()
        }

        return if (scanTimestamps.size < maxScansPerMinute) {
            scanTimestamps.addLast(currentTimeMillis)
            true
        } else {
            // Hard rate limit reached: drop immediately, do not queue
            false
        }
    }

    @Synchronized
    fun currentScanCount(currentTimeMillis: Long = System.currentTimeMillis()): Int {
        while (scanTimestamps.isNotEmpty() && currentTimeMillis - scanTimestamps.first() > windowMillis) {
            scanTimestamps.removeFirst()
        }
        return scanTimestamps.size
    }

    @Synchronized
    fun reset() {
        scanTimestamps.clear()
    }
}
