package com.secureshield.ai

import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class GuardianInterceptActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_guardian_intercept)

        val targetUrl = intent?.getStringExtra("target_url") ?: "http://192.168.1.1@secure-login-verify.xyz/account"
        val classification = intent?.getStringExtra("classification") ?: "Phishing & Credential Theft"
        val score = intent?.getIntExtra("score", 88) ?: 88
        val sourceApp = intent?.getStringExtra("source_app") ?: "Active App"

        findViewById<TextView>(R.id.text_hud_headline)?.text = "High-Risk Link Blocked in $sourceApp"
        findViewById<TextView>(R.id.text_hud_url)?.text = targetUrl
        findViewById<TextView>(R.id.text_hud_score)?.text = score.toString()
        findViewById<TextView>(R.id.text_hud_classification)?.text = classification

        findViewById<Button>(R.id.btn_hud_keep_safe)?.setOnClickListener {
            finish()
        }

        findViewById<Button>(R.id.btn_hud_ignore)?.setOnClickListener {
            finish()
        }
    }
}
