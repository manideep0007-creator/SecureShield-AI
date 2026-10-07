package com.secureshield.ai

import android.app.Application
import com.secureshield.ai.network.ServerSettings

/**
 * Application class ensuring centralized initialization for SecureShield-AI.
 * Guarantees that [ServerSettings] loads the persistent base URL on any process
 * startup before any Activity, Worker, or Service accesses [com.secureshield.ai.network.ApiClient].
 */
class SecureShieldApp : Application() {
    override fun onCreate() {
        super.onCreate()
        ServerSettings.init(this)
    }
}
