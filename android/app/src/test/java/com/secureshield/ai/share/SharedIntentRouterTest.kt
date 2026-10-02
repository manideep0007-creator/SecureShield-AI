package com.secureshield.ai.share

import com.secureshield.ai.network.ScanInput
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SharedIntentRouterTest {
    private val actionSend = "android.intent.action.SEND"

    @Test
    fun `shared text dispatches one scan`() {
        val scans = mutableListOf<Pair<ScanInput, SharedScanKind>>()
        val result = dispatch(SharedIntentPayload(actionSend, "text/plain", text = "Please review this note"), scans)

        assertTrue(result is ShareDispatchResult.Dispatched)
        assertEquals(1, scans.size)
        assertEquals("Please review this note", scans.single().first.text)
        assertNull(scans.single().first.url)
        assertEquals(SharedScanKind.TEXT, scans.single().second)
    }

    @Test
    fun `shared URL dispatches one scan`() {
        val scans = mutableListOf<Pair<ScanInput, SharedScanKind>>()
        val result = dispatch(SharedIntentPayload(actionSend, "text/plain", text = "https://example.test/path"), scans)

        assertTrue(result is ShareDispatchResult.Dispatched)
        assertEquals(1, scans.size)
        assertNull(scans.single().first.text)
        assertEquals("https://example.test/path", scans.single().first.url)
        assertEquals(SharedScanKind.URL, scans.single().second)
    }

    @Test
    fun `supported shared file dispatches one scan`() {
        val scans = mutableListOf<Pair<ScanInput, SharedScanKind>>()
        var reads = 0
        val result = SharedIntentRouter.dispatch(
            SharedIntentPayload(actionSend, "text/plain", streamUri = "content://provider/note"),
            readFile = {
                reads++
                SharedFileReadResult.Success("note.txt", "shared file body")
            },
            executeScan = { input, kind -> scans += input to kind }
        )

        assertTrue(result is ShareDispatchResult.Dispatched)
        assertEquals(1, reads)
        assertEquals(1, scans.size)
        assertEquals("note.txt", scans.single().first.file_name)
        assertEquals("shared file body", scans.single().first.file_bytes)
        assertEquals(SharedScanKind.FILE, scans.single().second)
    }

    @Test
    fun `text and file attachment are combined into one scan`() {
        val scans = mutableListOf<Pair<ScanInput, SharedScanKind>>()
        val result = dispatch(
            SharedIntentPayload(actionSend, "text/plain", text = "See https://example.test", streamUri = "content://provider/note"),
            scans
        )

        assertTrue(result is ShareDispatchResult.Dispatched)
        assertEquals(1, scans.size)
        assertEquals("See https://example.test", scans.single().first.text)
        assertEquals("https://example.test", scans.single().first.url)
        assertEquals("shared file body", scans.single().first.file_bytes)
    }

    @Test
    fun `multiple share extras trigger execute scan exactly once`() {
        var scanCount = 0
        val result = SharedIntentRouter.dispatch(
            SharedIntentPayload(
                action = actionSend,
                mimeType = "text/plain",
                text = "Review https://example.test",
                streamUri = "content://provider/note",
                dataUri = "https://example.test"
            ),
            readFile = { SharedFileReadResult.Success("note.txt", "shared file body") },
            executeScan = { _, _ -> scanCount++ }
        )

        assertTrue(result is ShareDispatchResult.Dispatched)
        assertEquals(1, scanCount)
    }

    @Test
    fun `missing or empty share data is rejected without scanning`() {
        val scans = mutableListOf<Pair<ScanInput, SharedScanKind>>()
        val missingResult = dispatch(SharedIntentPayload(actionSend, "text/plain"), scans)
        val emptyResult = dispatch(SharedIntentPayload(actionSend, "text/plain", text = "  \n"), scans)
        val emptyFileResult = SharedIntentRouter.dispatch(
            SharedIntentPayload(actionSend, "text/plain", streamUri = "content://provider/empty"),
            readFile = { SharedFileReadResult.Success("empty.txt", "") },
            executeScan = { input, kind -> scans += input to kind }
        )

        assertTrue(missingResult is ShareDispatchResult.Rejected)
        assertTrue(emptyResult is ShareDispatchResult.Rejected)
        assertTrue(emptyFileResult is ShareDispatchResult.Rejected)
        assertTrue(scans.isEmpty())
    }

    @Test
    fun `unsupported MIME type is rejected without reading or scanning`() {
        val scans = mutableListOf<Pair<ScanInput, SharedScanKind>>()
        var reads = 0
        val result = SharedIntentRouter.dispatch(
            SharedIntentPayload(actionSend, "application/pdf", streamUri = "content://provider/document"),
            readFile = { reads++; SharedFileReadResult.Success("doc.pdf", "") },
            executeScan = { input, kind -> scans += input to kind }
        )

        assertTrue(result is ShareDispatchResult.Rejected)
        assertEquals(0, reads)
        assertTrue(scans.isEmpty())
    }

    @Test
    fun `inaccessible shared URI is rejected without scanning`() {
        val scans = mutableListOf<Pair<ScanInput, SharedScanKind>>()
        val result = SharedIntentRouter.dispatch(
            SharedIntentPayload(actionSend, "text/plain", streamUri = "content://provider/private"),
            readFile = { SharedFileReadResult.Failure("Shared file is no longer accessible.") },
            executeScan = { input, kind -> scans += input to kind }
        )

        assertTrue(result is ShareDispatchResult.Rejected)
        assertEquals("Shared file is no longer accessible.", (result as ShareDispatchResult.Rejected).message)
        assertTrue(scans.isEmpty())
    }

    @Test
    fun `missing MIME is accepted when valid shared text is present`() {
        val scans = mutableListOf<Pair<ScanInput, SharedScanKind>>()
        val result = dispatch(SharedIntentPayload(actionSend, null, text = "shared"), scans)

        assertTrue(result is ShareDispatchResult.Dispatched)
        assertEquals(1, scans.size)
    }

    private fun dispatch(
        payload: SharedIntentPayload,
        scans: MutableList<Pair<ScanInput, SharedScanKind>>
    ): ShareDispatchResult = SharedIntentRouter.dispatch(
        payload,
        readFile = { SharedFileReadResult.Success("note.txt", "shared file body") },
        executeScan = { input, kind -> scans += input to kind }
    )
}