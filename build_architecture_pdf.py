import os
import subprocess
import pymupdf

def build_pdf():
    pdf_filename = "SecureShield_AI_System_Architecture.pdf"
    html_filename = "SecureShield_AI_System_Architecture_temp.html"
    
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SecureShield-AI System Architecture Document</title>
<style>
  @page {
    size: A4 portrait;
    margin: 12mm 14mm 14mm 14mm;
    @bottom-right {
      content: "Page " counter(page);
      font-family: 'Segoe UI', Roboto, Helvetica, sans-serif;
      font-size: 8pt;
      color: #64748b;
    }
    @bottom-left {
      content: "SecureShield-AI System Architecture | Confidential";
      font-family: 'Segoe UI', Roboto, Helvetica, sans-serif;
      font-size: 8pt;
      color: #64748b;
    }
  }

  body {
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, Helvetica, Arial, sans-serif;
    color: #1e293b;
    background-color: #ffffff;
    line-height: 1.5;
    font-size: 9pt;
    margin: 0;
    padding: 0;
  }

  .page-break {
    page-break-before: always;
  }
  .avoid-break {
    page-break-inside: avoid;
  }

  /* Cover Page */
  .cover-page {
    height: 94vh;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    padding: 30px 15px 15px 15px;
    box-sizing: border-box;
  }
  .cover-header {
    border-bottom: 3.5px solid #0f172a;
    padding-bottom: 25px;
  }
  .cover-title {
    font-size: 32pt;
    font-weight: 800;
    color: #0f172a;
    margin: 12px 0 6px 0;
    letter-spacing: -0.5px;
  }
  .cover-subtitle {
    font-size: 16pt;
    font-weight: 600;
    color: #2563eb;
    margin: 0 0 15px 0;
  }
  .cover-doc-type {
    display: inline-block;
    background-color: #0f172a;
    color: #ffffff;
    font-size: 9pt;
    font-weight: 700;
    padding: 5px 14px;
    border-radius: 4px;
    text-transform: uppercase;
    letter-spacing: 1px;
  }
  .cover-body {
    margin: 40px 0;
  }
  .cover-desc {
    font-size: 11pt;
    color: #334155;
    line-height: 1.7;
    max-width: 95%;
  }
  .cover-meta-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 15px;
    background-color: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 20px;
    margin-top: 35px;
  }
  .meta-item {
    font-size: 9pt;
  }
  .meta-label {
    font-weight: 700;
    color: #64748b;
    text-transform: uppercase;
    font-size: 7.5pt;
    letter-spacing: 0.5px;
  }
  .meta-value {
    color: #0f172a;
    font-weight: 600;
    margin-top: 2px;
  }
  .cover-footer {
    border-top: 1px solid #e2e8f0;
    padding-top: 15px;
    font-size: 8.5pt;
    color: #64748b;
    display: flex;
    justify-content: space-between;
  }

  /* Section Headings */
  h1 {
    font-size: 14pt;
    font-weight: 700;
    color: #0f172a;
    border-bottom: 1.5px solid #cbd5e1;
    padding-bottom: 4px;
    margin-top: 16px;
    margin-bottom: 8px;
    page-break-after: avoid;
  }
  h2 {
    font-size: 11.5pt;
    font-weight: 700;
    color: #1e3a8a;
    margin-top: 14px;
    margin-bottom: 6px;
    page-break-after: avoid;
  }
  h3 {
    font-size: 10pt;
    font-weight: 700;
    color: #0f172a;
    margin-top: 10px;
    margin-bottom: 4px;
    page-break-after: avoid;
  }
  p {
    margin: 0 0 7px 0;
  }
  ul, ol {
    margin: 0 0 8px 0;
    padding-left: 20px;
  }
  li {
    margin-bottom: 3px;
  }
  code {
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 8pt;
    background-color: #f1f5f9;
    color: #0f172a;
    padding: 1px 4px;
    border-radius: 3px;
    border: 1px solid #e2e8f0;
  }

  /* Tables */
  table {
    width: 100%;
    border-collapse: collapse;
    margin: 8px 0 12px 0;
    font-size: 8pt;
    page-break-inside: avoid;
  }
  th {
    background-color: #0f172a;
    color: #ffffff;
    font-weight: 600;
    text-align: left;
    padding: 5px 8px;
    border: 1px solid #0f172a;
  }
  td {
    padding: 4px 8px;
    border: 1px solid #cbd5e1;
    vertical-align: top;
  }
  tr:nth-child(even) {
    background-color: #f8fafc;
  }

  /* Badges */
  .badge {
    display: inline-block;
    padding: 1px 5px;
    border-radius: 3px;
    font-size: 6.5pt;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.4px;
  }
  .badge-impl {
    background-color: #dcfce7;
    color: #166534;
    border: 1px solid #86efac;
  }
  .badge-ext {
    background-color: #dbeafe;
    color: #1e40af;
    border: 1px solid #93c5fd;
  }
  .badge-lim {
    background-color: #fef3c7;
    color: #92400e;
    border: 1px solid #fcd34d;
  }
  .badge-danger {
    background-color: #fee2e2;
    color: #991b1b;
    border: 1px solid #fca5a5;
  }

  /* File path citation tag */
  .filepath {
    font-family: 'Consolas', monospace;
    font-size: 7.5pt;
    color: #2563eb;
    background-color: #eff6ff;
    padding: 1px 4px;
    border-radius: 3px;
    border: 1px solid #bfdbfe;
    display: inline-block;
  }

  /* Callouts */
  .callout {
    border-left: 3.5px solid #2563eb;
    background-color: #f8fafc;
    padding: 7px 11px;
    margin: 8px 0;
    border-radius: 0 5px 5px 0;
    font-size: 8.5pt;
  }
  .callout-title {
    font-weight: 700;
    color: #1e3a8a;
    margin-bottom: 2px;
  }

  /* Diagram Box */
  .diagram-box {
    background-color: #ffffff;
    border: 1px solid #cbd5e1;
    border-radius: 6px;
    padding: 10px;
    margin: 8px 0 12px 0;
    page-break-inside: avoid;
  }
  .diagram-caption {
    font-size: 7.5pt;
    font-weight: 600;
    color: #475569;
    text-align: center;
    margin-top: 6px;
    border-top: 1px dashed #e2e8f0;
    padding-top: 4px;
  }
  svg {
    display: block;
    margin: 0 auto;
    max-width: 100%;
    height: auto;
  }
</style>
</head>
<body>

<!-- ========================================================================= -->
<!-- 1. COVER PAGE -->
<!-- ========================================================================= -->
<div class="cover-page">
  <div class="cover-header">
    <div class="cover-doc-type">System Architecture Document</div>
    <div class="cover-title">SecureShield-AI</div>
    <div class="cover-subtitle">Intelligent Phishing & Threat Detection System</div>
    <div style="font-size: 10.5pt; color: #475569; font-weight: 500;">
      A Multi-Tiered Cognitive Security System Integrating Parallel Detection Engines, Static Behavioral Intelligence, Bayesian Risk Fusion, and Deterministic Explainability.
    </div>
  </div>

  <div class="cover-body">
    <div class="cover-desc">
      This architecture specification documents the complete, operational implementation of the SecureShield-AI defense ecosystem. Derived via direct source-code inspection of the Android native client and FastAPI backend services following all 21 completed engineering phases and legacy deprecation cleanups.
    </div>

    <div class="cover-meta-grid">
      <div class="meta-item">
        <div class="meta-label">System Architecture Level</div>
        <div class="meta-value">Levels 1–4 (Context, Container, Component, Data Flow)</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Primary Target Evaluation</div>
        <div class="meta-value">College Project Review, Technical Jury & Maintenance</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Client Implementation</div>
        <div class="meta-value">Android Native (Kotlin, Retrofit2, WorkManager, SQLite)</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Backend Implementation</div>
        <div class="meta-value">FastAPI, Python 3.14, AsyncIO, Pydantic V2</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Parallel Detection Engines</div>
        <div class="meta-value">7 Active Engines (URL, NLP, Sender, Header, Attachment, Vision, Malware)</div>
      </div>
      <div class="meta-item">
        <div class="meta-label">Automated Verification</div>
        <div class="meta-value">259 Automated Tests Passing (185 backend + 74 Android)</div>
      </div>
    </div>
  </div>

  <div class="cover-footer">
    <div><strong>Repository:</strong> SecureShield-AI</div>
    <div><strong>Classification:</strong> Verified Technical Project Documentation</div>
    <div><strong>Verification Date:</strong> October 2026</div>
  </div>
</div>

<div class="page-break"></div>

<!-- ========================================================================= -->
<!-- 2. SYSTEM OVERVIEW & 3. ARCHITECTURE PRINCIPLES -->
<!-- ========================================================================= -->
<h1>2. System Overview</h1>
<p>
  <strong>SecureShield-AI</strong> is an advanced cybersecurity threat detection platform designed to protect end-users against modern social engineering, multi-stage phishing, weaponized document attachments, deceptive URLs, and visual credential harvesting. Modern adversaries rarely rely on a single obvious attack signature; instead, they blend urgent natural language phrasing, typosquatted hostnames, deceptive display names, disguised file formats, and deceptive visual login elements.
</p>
<p>
  To counter these composite attacks, SecureShield-AI deploys a multi-modal ensemble of <strong>seven specialized detection and behavioral intelligence engines</strong> running concurrently within an asynchronous execution pipeline. Signals across text, URLs, file binaries, image payloads, email headers, and sender historical profiles are synthesized through a <strong>confidence-weighted Bayesian risk fusion layer</strong>, mapped against <strong>declarative risk classification policies</strong>, and interpreted by an <strong>explainability engine</strong> that outputs plain-language explanations and concrete user precautions.
</p>

<h1>3. Architecture Principles</h1>
<p>
  The design and implementation of SecureShield-AI adhere to five foundational architectural principles:
</p>
<table>
  <thead>
    <tr>
      <th style="width: 25%;">Quality Attribute</th>
      <th style="width: 35%;">Architectural Principle</th>
      <th style="width: 40%;">Implementation Evidence</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Zero-Trust Input Normalization</strong></td>
      <td>Treat all incoming inputs as malicious. Strictly bound lengths and sanitize characters before passing data to detection logic.</td>
      <td><span class="filepath">V2Preprocessor</span> caps text at 50,000 chars, URLs at 4,096 chars, files at 10 MB, and email headers at 100 items. Strips ASCII control chars and normalizes Unicode (NFKC).</td>
    </tr>
    <tr>
      <td><strong>Fault-Tolerant Engine Isolation</strong></td>
      <td>One engine's crash, external timeout, or missing API key must never fail the pipeline or distort other engine scores.</td>
      <td><span class="filepath">BaseEngine.safe_analyze()</span> traps all unhandled exceptions into <span class="badge badge-danger">ERROR</span> status. <span class="filepath">EngineRegistry.run_all()</span> sets 30.0s <span class="filepath">asyncio.wait_for()</span>.</td>
    </tr>
    <tr>
      <td><strong>Absence of Proof is Not Proof of Safety</strong></td>
      <td>An engine that fails or times out must contribute zero confidence and be excluded from fusion, rather than scoring as 0/safe.</td>
      <td><span class="filepath">fuse_engine_results()</span> records errored engines in <span class="filepath">ignored_engines</span>. Scores are computed exclusively from usable engines (<span class="badge badge-impl">SUCCESS</span> / <span class="badge badge-ext">PARTIAL</span>).</td>
    </tr>
    <tr>
      <td><strong>Privacy by Design & Edge Redaction</strong></td>
      <td>Do not retain sensitive content on the backend. Redact sensitive secrets from scan history on the client before persisting.</td>
      <td>Backend database (<span class="filepath">feedback.db</span>) retains zero user text/files. Client <span class="filepath">ScanHistorySanitizer</span> redacts passwords, OTPs, and tokens into <code>[redacted]</code>.</td>
    </tr>
    <tr>
      <td><strong>Immutable Security Thresholds</strong></td>
      <td>User feedback (thumbs up/down) must never automatically tune classification boundaries or lower threat detection barriers.</td>
      <td><span class="filepath">apply_feedback_tuning()</span> in <span class="filepath">policy.py</span> explicitly raises <span class="filepath">PermissionError</span>. Feedback is isolated to evaluation telemetry.</td>
    </tr>
  </tbody>
</table>

<div class="page-break"></div>

<!-- ========================================================================= -->
<!-- 4. HIGH-LEVEL ARCHITECTURE DIAGRAM -->
<!-- ========================================================================= -->
<h1>4. High-Level Architecture Diagram</h1>
<p>
  The System Context diagram (Level 1) defines the boundaries of the SecureShield-AI platform, identifying all primary actors, runtime containers, and third-party security cloud services.
</p>

<div class="diagram-box">
  <!-- DIAGRAM 1: HIGH-LEVEL SYSTEM ARCHITECTURE -->
  <svg width="670" height="270" viewBox="0 0 670 270">
    <defs>
      <marker id="arr" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
        <path d="M0,0 L6,3 L0,6 Z" fill="#2563eb" />
      </marker>
      <marker id="arr-gray" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
        <path d="M0,0 L6,3 L0,6 Z" fill="#64748b" />
      </marker>
    </defs>

    <!-- User / External Entity -->
    <rect x="15" y="85" width="130" height="100" rx="8" fill="#f8fafc" stroke="#0f172a" stroke-width="2"/>
    <text x="80" y="118" font-size="11" font-weight="700" fill="#0f172a" text-anchor="middle">End User / OS</text>
    <text x="80" y="138" font-size="8" fill="#475569" text-anchor="middle">• Share Menu (URL/File)</text>
    <text x="80" y="153" font-size="8" fill="#475569" text-anchor="middle">• Gmail OAuth Login</text>
    <text x="80" y="168" font-size="8" fill="#475569" text-anchor="middle">• Views Threat Alerts</text>

    <line x1="145" y1="135" x2="190" y2="135" stroke="#2563eb" stroke-width="2" marker-end="url(#arr)"/>
    <text x="167" y="127" font-size="7.5" font-weight="600" fill="#2563eb" text-anchor="middle">Intents</text>

    <!-- Android Container -->
    <rect x="195" y="25" width="180" height="220" rx="8" fill="#eff6ff" stroke="#2563eb" stroke-width="2"/>
    <text x="285" y="50" font-size="11.5" font-weight="700" fill="#1e3a8a" text-anchor="middle">Android Client App</text>
    <text x="285" y="65" font-size="8" font-weight="600" fill="#2563eb" text-anchor="middle">android/app/src/main/</text>
    
    <rect x="210" y="80" width="150" height="30" rx="4" fill="#ffffff" stroke="#93c5fd"/>
    <text x="285" y="99" font-size="8" font-weight="600" fill="#0f172a" text-anchor="middle">UI &amp; Share Router</text>
    
    <rect x="210" y="118" width="150" height="30" rx="4" fill="#ffffff" stroke="#93c5fd"/>
    <text x="285" y="137" font-size="8" font-weight="600" fill="#0f172a" text-anchor="middle">ThreatAlertWorker</text>

    <rect x="210" y="156" width="150" height="30" rx="4" fill="#ffffff" stroke="#93c5fd"/>
    <text x="285" y="175" font-size="8" font-weight="600" fill="#0f172a" text-anchor="middle">GmailScanner (OAuth)</text>

    <rect x="210" y="194" width="150" height="30" rx="4" fill="#ffffff" stroke="#93c5fd"/>
    <text x="285" y="213" font-size="8" font-weight="600" fill="#0f172a" text-anchor="middle">SQLite History Store</text>

    <!-- Arrow to Backend -->
    <line x1="375" y1="135" x2="420" y2="135" stroke="#2563eb" stroke-width="2" marker-end="url(#arr)"/>
    <text x="397" y="125" font-size="7.5" font-weight="600" fill="#2563eb" text-anchor="middle">HTTPS</text>
    <text x="397" y="147" font-size="7" fill="#64748b" text-anchor="middle">/api/scan</text>

    <!-- Backend Container -->
    <rect x="425" y="25" width="125" height="220" rx="8" fill="#f8fafc" stroke="#0f172a" stroke-width="2"/>
    <text x="487" y="50" font-size="11.5" font-weight="700" fill="#0f172a" text-anchor="middle">FastAPI Backend</text>
    <text x="487" y="65" font-size="8" font-weight="600" fill="#475569" text-anchor="middle">backend/app/</text>

    <rect x="435" y="80" width="105" height="24" rx="4" fill="#ffffff" stroke="#cbd5e1"/>
    <text x="487" y="96" font-size="7.5" font-weight="600" fill="#0f172a" text-anchor="middle">V2 Preprocessor</text>

    <rect x="435" y="110" width="105" height="24" rx="4" fill="#ffffff" stroke="#cbd5e1"/>
    <text x="487" y="126" font-size="7.5" font-weight="600" fill="#0f172a" text-anchor="middle">7 Engines (Parallel)</text>

    <rect x="435" y="140" width="105" height="24" rx="4" fill="#ffffff" stroke="#cbd5e1"/>
    <text x="487" y="156" font-size="7.5" font-weight="600" fill="#0f172a" text-anchor="middle">Bayesian Fusion</text>

    <rect x="435" y="170" width="105" height="24" rx="4" fill="#ffffff" stroke="#cbd5e1"/>
    <text x="487" y="186" font-size="7.5" font-weight="600" fill="#0f172a" text-anchor="middle">Risk Policy</text>

    <rect x="435" y="200" width="105" height="32" rx="4" fill="#ffffff" stroke="#cbd5e1"/>
    <text x="487" y="214" font-size="7.5" font-weight="600" fill="#0f172a" text-anchor="middle">Explainability</text>
    <text x="487" y="226" font-size="6.5" fill="#64748b" text-anchor="middle">&amp; SQLite Stores</text>

    <!-- External Cloud Feeds -->
    <line x1="550" y1="80" x2="580" y2="55" stroke="#64748b" stroke-width="1.5" marker-end="url(#arr-gray)"/>
    <line x1="550" y1="135" x2="580" y2="135" stroke="#64748b" stroke-width="1.5" marker-end="url(#arr-gray)"/>
    <line x1="550" y1="190" x2="580" y2="215" stroke="#64748b" stroke-width="1.5" marker-end="url(#arr-gray)"/>

    <rect x="585" y="25" width="75" height="55" rx="5" fill="#fdf2f8" stroke="#db2777"/>
    <text x="622" y="48" font-size="8" font-weight="700" fill="#9d174d" text-anchor="middle">Google GSB</text>
    <text x="622" y="62" font-size="6.5" fill="#701a75" text-anchor="middle">Threat Matches</text>

    <rect x="585" y="105" width="75" height="55" rx="5" fill="#fdf2f8" stroke="#db2777"/>
    <text x="622" y="128" font-size="8" font-weight="700" fill="#9d174d" text-anchor="middle">VirusTotal</text>
    <text x="622" y="142" font-size="6.5" fill="#701a75" text-anchor="middle">SHA-256 Check</text>

    <rect x="585" y="185" width="75" height="55" rx="5" fill="#fdf2f8" stroke="#db2777"/>
    <text x="622" y="208" font-size="8" font-weight="700" fill="#9d174d" text-anchor="middle">AsyncWHOIS</text>
    <text x="622" y="222" font-size="6.5" fill="#701a75" text-anchor="middle">Domain Age</text>
  </svg>
  <div class="diagram-caption">Figure 1: High-Level System Architecture showing client, backend orchestration, and external cloud intelligence dependencies.</div>
</div>

<!-- ========================================================================= -->
<!-- 5. COMPONENT ARCHITECTURE -->
<!-- ========================================================================= -->
<h1>5. Component Architecture</h1>
<p>
  SecureShield-AI comprises two physical software containers alongside three persistent embedded database storage instances:
</p>
<table>
  <thead>
    <tr>
      <th style="width: 20%;">Container</th>
      <th style="width: 25%;">Runtime Environment</th>
      <th style="width: 25%;">Physical Repository Path</th>
      <th style="width: 30%;">Core Interfaces</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Android Client</strong></td>
      <td>Android OS 8.0+ (ART runtime)</td>
      <td><span class="filepath">android/app/src/main/</span></td>
      <td>Android Share Intent (<code>ACTION_SEND</code>), Android Notification System (<code>SS_ALERTS</code>), WorkManager.</td>
    </tr>
    <tr>
      <td><strong>FastAPI Backend</strong></td>
      <td>Python 3.14 (Uvicorn ASGI)</td>
      <td><span class="filepath">backend/app/</span>, <span class="filepath">backend/main.py</span></td>
      <td>HTTP/JSON REST API (<code>/api/scan</code>, <code>/api/feedback</code>, <code>/api/evaluation/metrics</code>).</td>
    </tr>
    <tr>
      <td><strong>Client History Store</strong></td>
      <td>SQLite3 (<code>SQLiteOpenHelper</code>)</td>
      <td><span class="filepath">secure_scan_history.db</span> (on device)</td>
      <td>Android internal SQL queries managed by <code>ScanHistoryRepository</code>.</td>
    </tr>
    <tr>
      <td><strong>Sender Behavior DB</strong></td>
      <td>SQLite3 (Local file)</td>
      <td><span class="filepath">backend/data/sender_behavior.db</span></td>
      <td><code>senders</code> and <code>sender_name_history</code> tables queried synchronously by <code>SenderEngine</code>.</td>
    </tr>
    <tr>
      <td><strong>Feedback DB</strong></td>
      <td>SQLite3 (Local file)</td>
      <td><span class="filepath">backend/data/feedback.db</span></td>
      <td>Normalized evaluation table <code>feedback</code> queried by <code>/api/evaluation/metrics</code>.</td>
    </tr>
  </tbody>
</table>

<div class="page-break"></div>

<!-- ========================================================================= -->
<!-- 6. ANDROID ARCHITECTURE -->
<!-- ========================================================================= -->
<h1>6. Android Architecture</h1>
<p>
  The native Android mobile client (<span class="filepath">android/app/src/main/java/com/secureshield/ai/</span>) is organized into clean architectural layers covering UI presentation, shared intent routing, network communication, background protection, and sanitized local history persistence:
</p>

<div class="diagram-box">
  <!-- DIAGRAM 5: ANDROID ARCHITECTURE (CLEAN PURE SVG) -->
  <svg width="670" height="320" viewBox="0 0 670 320">
    <!-- UI Layer -->
    <rect x="15" y="15" width="305" height="75" rx="6" fill="#eff6ff" stroke="#2563eb" stroke-width="1.5"/>
    <text x="30" y="37" font-size="9.5" font-weight="700" fill="#1e3a8a">Presentation / UI Layer</text>
    <text x="30" y="55" font-size="7.5" fill="#334155"><tspan font-weight="700">MainActivity.kt:</tspan> Category badge, score, action, feedback thumbs</text>
    <text x="30" y="70" font-size="7.5" fill="#334155"><tspan font-weight="700">ScanHistoryActivity.kt:</tspan> Paginated history, detail modal, deletion</text>

    <!-- Share Intent Router -->
    <rect x="350" y="15" width="305" height="75" rx="6" fill="#f8fafc" stroke="#0f172a" stroke-width="1.5"/>
    <text x="365" y="37" font-size="9.5" font-weight="700" fill="#0f172a">Shared Intent Router (share/)</text>
    <text x="365" y="55" font-size="7.5" fill="#334155"><tspan font-weight="700">SharedIntentRouter.kt:</tspan> Intercepts ACTION_SEND intents</text>
    <text x="365" y="70" font-size="7.5" fill="#334155">Handles text/plain, URLs, streamed files (enforces 10 MB limit)</text>

    <line x1="320" y1="52" x2="350" y2="52" stroke="#2563eb" stroke-width="1.5" marker-end="url(#arr)"/>

    <!-- Network Layer -->
    <rect x="15" y="105" width="305" height="95" rx="6" fill="#f8fafc" stroke="#0f172a" stroke-width="1.5"/>
    <text x="30" y="125" font-size="9.5" font-weight="700" fill="#0f172a">Network &amp; API Layer (network/)</text>
    <text x="30" y="142" font-size="7.5" fill="#334155"><tspan font-weight="700">ApiClient.kt:</tspan> Retrofit2 client pointing to BuildConfig.BASE_URL</text>
    <text x="30" y="156" font-size="7.5" fill="#334155"><tspan font-weight="700">UnifiedScanResponseParser:</tspan> Strict runtime JSON validator</text>
    <text x="30" y="170" font-size="7.5" fill="#334155"><tspan font-weight="700">fileBytesAsBackendJsonValue:</tspan> Safe UTF-8 stream encoder</text>
    <text x="30" y="184" font-size="7.5" fill="#334155">Endpoints: POST /api/scan, POST /api/feedback</text>

    <!-- Background Protection Layer -->
    <rect x="350" y="105" width="305" height="95" rx="6" fill="#f0fdf4" stroke="#16a34a" stroke-width="1.5"/>
    <text x="365" y="125" font-size="9.5" font-weight="700" fill="#166534">Background Protection (background/)</text>
    <text x="365" y="142" font-size="7.5" fill="#334155"><tspan font-weight="700">BackgroundProtectionManager:</tspan> WorkManager 15m periodic job</text>
    <text x="365" y="156" font-size="7.5" fill="#334155"><tspan font-weight="700">ThreatAlertWorker:</tspan> CoroutineWorker orchestrating inbox scan</text>
    <text x="365" y="170" font-size="7.5" fill="#334155"><tspan font-weight="700">ProcessedMessageStore:</tspan> 500-entry ring buffer of scanned IDs</text>
    <text x="365" y="184" font-size="7.5" fill="#334155"><tspan font-weight="700">BackgroundScanner:</tspan> Triggers high-priority alert on threat</text>

    <!-- Gmail Integration Layer -->
    <rect x="15" y="215" width="305" height="90" rx="6" fill="#fdf2f8" stroke="#db2777" stroke-width="1.5"/>
    <text x="30" y="235" font-size="9.5" font-weight="700" fill="#9d174d">Gmail Integration</text>
    <text x="30" y="252" font-size="7.5" fill="#334155"><tspan font-weight="700">GmailScanner:</tspan> Google Sign-In with gmail.readonly OAuth scope</text>
    <text x="30" y="267" font-size="7.5" fill="#334155"><tspan font-weight="700">GmailMessageExtractor:</tspan> Decodes MIME parts &amp; HTML entities</text>
    <text x="30" y="282" font-size="7.5" fill="#334155"><tspan font-weight="700">GmailOAuthOutcome:</tspan> Maps AUTHORIZED, CANCELLED, FAILED</text>

    <!-- Local History & Sanitization -->
    <rect x="350" y="215" width="305" height="90" rx="6" fill="#eff6ff" stroke="#2563eb" stroke-width="1.5"/>
    <text x="365" y="235" font-size="9.5" font-weight="700" fill="#1e3a8a">Sanitized History (history/)</text>
    <text x="365" y="252" font-size="7.5" fill="#334155"><tspan font-weight="700">ScanHistoryDatabase:</tspan> SQLiteOpenHelper (secure_scan_history.db)</text>
    <text x="365" y="267" font-size="7.5" fill="#334155"><tspan font-weight="700">ScanHistorySanitizer:</tspan> Strict regex scrubbing of sensitive tokens</text>
    <text x="365" y="282" font-size="7.5" fill="#334155"><tspan font-weight="700">ScanHistoryRepository:</tspan> Paginated query &amp; delete abstraction</text>
  </svg>
  <div class="diagram-caption">Figure 2: Android Client Architecture illustrating UI, background worker, Gmail extractor, and sanitized history store.</div>
</div>

<div class="page-break"></div>

<!-- ========================================================================= -->
<!-- 7. BACKEND ARCHITECTURE -->
<!-- ========================================================================= -->
<h1>7. Backend Architecture</h1>
<p>
  The backend is structured into modular Python packages with strict boundaries separating normalization, detection, fusion, policy, and explainability:
</p>

<div class="diagram-box">
  <!-- DIAGRAM 2: DETAILED BACKEND ARCHITECTURE -->
  <svg width="670" height="330" viewBox="0 0 670 330">
    <rect x="10" y="10" width="650" height="310" rx="8" fill="#f8fafc" stroke="#0f172a" stroke-width="1.5"/>
    <text x="25" y="32" font-size="11" font-weight="700" fill="#0f172a">FastAPI Backend Module Topology (backend/app/)</text>

    <!-- Entry Point -->
    <rect x="25" y="50" width="130" height="48" rx="6" fill="#eff6ff" stroke="#2563eb"/>
    <text x="90" y="71" font-size="9" font-weight="700" fill="#1e3a8a" text-anchor="middle">backend/main.py</text>
    <text x="90" y="85" font-size="7" fill="#475569" text-anchor="middle">FastAPI Bootstrap &amp; CORS</text>

    <!-- Routes -->
    <rect x="180" y="50" width="140" height="48" rx="6" fill="#eff6ff" stroke="#2563eb"/>
    <text x="250" y="71" font-size="9" font-weight="700" fill="#1e3a8a" text-anchor="middle">app/api/routes.py</text>
    <text x="250" y="85" font-size="7" fill="#475569" text-anchor="middle">/scan, /feedback, /metrics</text>

    <line x1="155" y1="74" x2="180" y2="74" stroke="#2563eb" stroke-width="1.5" marker-end="url(#arr)"/>

    <!-- Pipeline Coordinator -->
    <rect x="345" y="50" width="165" height="48" rx="6" fill="#fef3c7" stroke="#d97706"/>
    <text x="427" y="70" font-size="9" font-weight="700" fill="#92400e" text-anchor="middle">UnifiedScanPipeline</text>
    <text x="427" y="84" font-size="7" fill="#78350f" text-anchor="middle">app/engines/pipeline.py</text>

    <line x1="320" y1="74" x2="345" y2="74" stroke="#2563eb" stroke-width="1.5" marker-end="url(#arr)"/>

    <!-- Models Box -->
    <rect x="530" y="50" width="115" height="110" rx="6" fill="#ffffff" stroke="#cbd5e1"/>
    <text x="587" y="68" font-size="8.5" font-weight="700" fill="#0f172a" text-anchor="middle">app/models/</text>
    <text x="587" y="84" font-size="7" fill="#475569" text-anchor="middle">• scan_input.py</text>
    <text x="587" y="98" font-size="7" fill="#475569" text-anchor="middle">• engine_result.py</text>
    <text x="587" y="112" font-size="7" fill="#475569" text-anchor="middle">• risk_assessment.py</text>
    <text x="587" y="126" font-size="7" fill="#475569" text-anchor="middle">• scan_response.py</text>
    <text x="587" y="140" font-size="7" fill="#475569" text-anchor="middle">• feedback.py</text>

    <!-- Preprocessing Box -->
    <rect x="25" y="120" width="220" height="65" rx="6" fill="#ffffff" stroke="#cbd5e1"/>
    <text x="135" y="138" font-size="8.5" font-weight="700" fill="#0f172a" text-anchor="middle">app/preprocessing/</text>
    <text x="135" y="154" font-size="7" fill="#475569" text-anchor="middle">• v2_preprocessor.py (NFKC, Bounds, Strip)</text>
    <text x="135" y="167" font-size="7" fill="#475569" text-anchor="middle">• safe_url_fetcher.py (Anti-SSRF, IP Pinning)</text>
    <text x="135" y="179" font-size="7" fill="#475569" text-anchor="middle">• data_prep.py (Magic Byte Extension Check)</text>

    <line x1="365" y1="98" x2="215" y2="120" stroke="#d97706" stroke-width="1.5" marker-end="url(#arr)"/>

    <!-- Engine Registry & The 7 Engines -->
    <rect x="265" y="120" width="245" height="110" rx="6" fill="#f0fdf4" stroke="#16a34a"/>
    <text x="387" y="138" font-size="8.5" font-weight="700" fill="#166534" text-anchor="middle">app/engines/ (The 7 Detection Engines)</text>
    
    <g transform="translate(275, 147)" font-size="7" fill="#0f172a">
      <rect x="0" y="0" width="108" height="18" rx="3" fill="#ffffff" stroke="#86efac"/>
      <text x="54" y="12" text-anchor="middle">1. url_engine.py</text>

      <rect x="117" y="0" width="108" height="18" rx="3" fill="#ffffff" stroke="#86efac"/>
      <text x="171" y="12" text-anchor="middle">2. nlp_engine.py</text>

      <rect x="0" y="24" width="108" height="18" rx="3" fill="#ffffff" stroke="#86efac"/>
      <text x="54" y="36" text-anchor="middle">3. sender_engine.py</text>

      <rect x="117" y="24" width="108" height="18" rx="3" fill="#ffffff" stroke="#86efac"/>
      <text x="171" y="36" text-anchor="middle">4. header_analysis.py</text>

      <rect x="0" y="48" width="108" height="18" rx="3" fill="#ffffff" stroke="#86efac"/>
      <text x="54" y="60" text-anchor="middle">5. attachment_behavior.py</text>

      <rect x="117" y="48" width="108" height="18" rx="3" fill="#ffffff" stroke="#86efac"/>
      <text x="171" y="60" text-anchor="middle">6. visual_engine.py</text>

      <rect x="58" y="68" width="108" height="18" rx="3" fill="#ffffff" stroke="#86efac"/>
      <text x="112" y="80" text-anchor="middle">7. malware_engine.py</text>
    </g>

    <line x1="427" y1="98" x2="427" y2="120" stroke="#d97706" stroke-width="1.5" marker-end="url(#arr)"/>

    <!-- Fusion Layer -->
    <rect x="25" y="245" width="180" height="55" rx="6" fill="#eff6ff" stroke="#2563eb"/>
    <text x="115" y="265" font-size="8.5" font-weight="700" fill="#1e3a8a" text-anchor="middle">app/fusion/risk_fusion.py</text>
    <text x="115" y="279" font-size="7" fill="#475569" text-anchor="middle">Bayesian Weighting Formula</text>
    <text x="115" y="291" font-size="6.5" fill="#64748b" text-anchor="middle">Ignores errored/skipped engines</text>

    <!-- Classification Policy -->
    <rect x="225" y="245" width="195" height="55" rx="6" fill="#eff6ff" stroke="#2563eb"/>
    <text x="322" y="265" font-size="8.5" font-weight="700" fill="#1e3a8a" text-anchor="middle">app/classification/policy.py</text>
    <text x="322" y="279" font-size="7" fill="#475569" text-anchor="middle">Profiles: Default / Strict / Enterprise</text>
    <text x="322" y="291" font-size="6.5" fill="#64748b" text-anchor="middle">Malware Safeguard Enforcement</text>

    <!-- Explainability -->
    <rect x="440" y="245" width="205" height="55" rx="6" fill="#eff6ff" stroke="#2563eb"/>
    <text x="542" y="265" font-size="8.5" font-weight="700" fill="#1e3a8a" text-anchor="middle">app/explainability/engine.py</text>
    <text x="542" y="279" font-size="7" fill="#475569" text-anchor="middle">Flag-to-Reason Synthesis</text>
    <text x="542" y="291" font-size="6.5" fill="#64748b" text-anchor="middle">Prescriptive Action Mapping</text>

    <line x1="387" y1="230" x2="115" y2="245" stroke="#16a34a" stroke-width="1.5" marker-end="url(#arr)"/>
    <line x1="205" y1="272" x2="225" y2="272" stroke="#2563eb" stroke-width="1.5" marker-end="url(#arr)"/>
    <line x1="420" y1="272" x2="440" y2="272" stroke="#2563eb" stroke-width="1.5" marker-end="url(#arr)"/>
  </svg>
  <div class="diagram-caption">Figure 3: Detailed Backend Architecture illustrating module separation, model propagation, and engine orchestration.</div>
</div>

<div class="page-break"></div>

<!-- ========================================================================= -->
<!-- 8. DETECTION & INTELLIGENCE LAYER -->
<!-- ========================================================================= -->
<h1>8. Detection & Intelligence Layer</h1>
<p>
  Every implemented detection engine is purpose-built to scrutinize a specific threat surface. The architecture and empirical reliability weight of each engine are detailed below:
</p>

<div class="diagram-box">
  <!-- DIAGRAM 4: DETECTION ENGINE ARCHITECTURE -->
  <svg width="670" height="370" viewBox="0 0 670 370">
    <g transform="translate(5, 10)">
      <!-- URL Engine Box -->
      <rect x="0" y="0" width="205" height="110" rx="6" fill="#f8fafc" stroke="#2563eb" stroke-width="1.5"/>
      <text x="12" y="22" font-size="9" font-weight="700" fill="#1e3a8a">URLEngine (Weight: 0.90)</text>
      <text x="12" y="35" font-size="6.5" font-weight="600" fill="#2563eb">backend/app/engines/url_engine.py</text>
      <text x="12" y="50" font-size="7" fill="#334155">• 17 Lexical Heuristics (entropy, hyphens)</text>
      <text x="12" y="64" font-size="7" fill="#334155">• AsyncWHOIS domain age (&lt;14d flagged)</text>
      <text x="12" y="78" font-size="7" fill="#334155">• Google Safe Browsing ThreatMatches</text>
      <text x="12" y="94" font-size="7" font-weight="600" fill="#dc2626">• GSB hit enforces minimum 90.0 floor</text>

      <!-- NLP Engine Box -->
      <rect x="220" y="0" width="210" height="110" rx="6" fill="#f8fafc" stroke="#2563eb" stroke-width="1.5"/>
      <text x="232" y="22" font-size="9" font-weight="700" fill="#1e3a8a">NLPEngine (Weight: 0.80)</text>
      <text x="232" y="35" font-size="6.5" font-weight="600" fill="#2563eb">backend/app/engines/nlp_engine.py</text>
      <text x="232" y="50" font-size="7" fill="#334155">• 5 Social Engineering Regex Categories</text>
      <text x="232" y="64" font-size="7" fill="#334155">• Full Inflection Support (suspended, lock)</text>
      <text x="232" y="78" font-size="7" fill="#334155">• Dual-Layer OTP False-Positive Shield</text>
      <text x="232" y="94" font-size="7" font-weight="600" fill="#16a34a">• Suppresses legitimate 2FA disclaimers</text>

      <!-- Sender Engine Box -->
      <rect x="445" y="0" width="210" height="110" rx="6" fill="#f8fafc" stroke="#2563eb" stroke-width="1.5"/>
      <text x="457" y="22" font-size="9" font-weight="700" fill="#1e3a8a">SenderEngine (Weight: 0.60)</text>
      <text x="457" y="35" font-size="6.5" font-weight="600" fill="#2563eb">backend/app/engines/sender_engine.py</text>
      <text x="457" y="50" font-size="7" fill="#334155">• SQLite Behavioral DB (sender_behavior.db)</text>
      <text x="457" y="64" font-size="7" fill="#334155">• Detects rapid bursts &lt;60s &amp; high volume</text>
      <text x="457" y="78" font-size="7" fill="#334155">• Tracks unusual arrival hour &amp; domain drift</text>
      <text x="457" y="94" font-size="7" fill="#334155">• Out-of-character links / attachment flags</text>

      <!-- Header Analysis Engine Box -->
      <rect x="0" y="125" width="205" height="110" rx="6" fill="#f8fafc" stroke="#2563eb" stroke-width="1.5"/>
      <text x="12" y="147" font-size="9" font-weight="700" fill="#1e3a8a">HeaderAnalysisEngine (0.75)</text>
      <text x="12" y="160" font-size="6.5" font-weight="600" fill="#2563eb">backend/app/engines/header_analysis_engine.py</text>
      <text x="12" y="175" font-size="7" fill="#334155">• Reply-To vs From address domain mismatch</text>
      <text x="12" y="189" font-size="7" fill="#334155">• SPF, DKIM, DMARC auth failure flags</text>
      <text x="12" y="203" font-size="7" fill="#334155">• Message-ID anomaly &amp; Date skew &gt;7 days</text>
      <text x="12" y="219" font-size="7" font-weight="600" fill="#92400e">• Score capped at 90.0 (prevents false malware)</text>

      <!-- Attachment Behavior Engine Box -->
      <rect x="220" y="125" width="210" height="110" rx="6" fill="#f8fafc" stroke="#2563eb" stroke-width="1.5"/>
      <text x="232" y="147" font-size="9" font-weight="700" fill="#1e3a8a">AttachmentBehavior (0.75)</text>
      <text x="232" y="160" font-size="6.5" font-weight="600" fill="#2563eb">backend/app/engines/attachment_behavior_engine.py</text>
      <text x="232" y="175" font-size="7" fill="#334155">• 100% Safe Static Analysis (Zero Execution)</text>
      <text x="232" y="189" font-size="7" fill="#334155">• Magic bytes &amp; Type Mismatch detection</text>
      <text x="232" y="203" font-size="7" fill="#334155">• Double extension &amp; RTLO evasion detection</text>
      <text x="232" y="219" font-size="7" fill="#334155">• OOXML/OLE2 macros &amp; ZIP bomb detection</text>

      <!-- Visual Engine Box -->
      <rect x="445" y="125" width="210" height="110" rx="6" fill="#f8fafc" stroke="#2563eb" stroke-width="1.5"/>
      <text x="457" y="147" font-size="9" font-weight="700" fill="#1e3a8a">VisualEngine (Weight: 0.90)</text>
      <text x="457" y="160" font-size="6.5" font-weight="600" fill="#2563eb">backend/app/engines/visual_engine.py</text>
      <text x="457" y="175" font-size="7" fill="#334155">• OpenCV QRCodeDetector decodes QR URLs</text>
      <text x="457" y="189" font-size="7" fill="#334155">• EasyOCR text extraction (confidence &gt;0.3)</text>
      <text x="457" y="203" font-size="7" fill="#334155">• Canny edge contour fake login detection</text>
      <text x="457" y="219" font-size="7" font-weight="600" fill="#16a34a">• Feeds extracted URL/text downstream</text>

      <!-- Malware Engine Box -->
      <rect x="145" y="250" width="370" height="105" rx="6" fill="#f8fafc" stroke="#dc2626" stroke-width="1.5"/>
      <text x="160" y="271" font-size="9.5" font-weight="700" fill="#991b1b">MalwareEngine (Weight: 1.00 — Highest Reliability)</text>
      <text x="160" y="285" font-size="6.5" font-weight="600" fill="#dc2626">backend/app/engines/malware_engine.py</text>
      <text x="160" y="300" font-size="7" fill="#334155">• Computes SHA-256 hash of file payload (never uploads full file)</text>
      <text x="160" y="313" font-size="7" fill="#334155">• Queries VirusTotal v3 REST API with local TTLCache (10 min TTL)</text>
      <text x="160" y="327" font-size="7" font-weight="600" fill="#dc2626">• Fault Isolation: API failure sets ERROR status &amp; 0.0 confidence (ignored by fusion)</text>
      <text x="160" y="341" font-size="7" fill="#475569">• Triggers top-level warning in response: "malware scan unavailable"</text>
    </g>
  </svg>
  <div class="diagram-caption">Figure 4: The Seven Detection Engines showing their specialized threat surfaces, heuristics, and reliability weights.</div>
</div>

<div class="page-break"></div>

<!-- ========================================================================= -->
<!-- 9. END-TO-END SCAN PIPELINE -->
<!-- ========================================================================= -->
<h1>9. End-to-End Scan Pipeline</h1>
<p>
  Every scan executed by SecureShield-AI follows a deterministic, ten-stage pipeline. The diagram below documents this complete execution flow from raw input ingestion to final explanation generation:
</p>

<div class="diagram-box">
  <!-- DIAGRAM 3: COMPLETE THREAT-SCANNING PIPELINE -->
  <svg width="670" height="400" viewBox="0 0 670 400">
    <defs>
      <marker id="parr" markerWidth="7" markerHeight="7" refX="5" refY="2.5" orient="auto">
        <path d="M0,0 L5,2.5 L0,5 Z" fill="#0f172a" />
      </marker>
    </defs>

    <!-- Stage 1 -->
    <rect x="15" y="15" width="130" height="45" rx="5" fill="#f8fafc" stroke="#0f172a" stroke-width="1.5"/>
    <text x="80" y="33" font-size="8.5" font-weight="700" fill="#0f172a" text-anchor="middle">1. Input Ingestion</text>
    <text x="80" y="47" font-size="7" fill="#475569" text-anchor="middle">ScanInput Pydantic Model</text>

    <line x1="145" y1="37" x2="175" y2="37" stroke="#0f172a" stroke-width="1.5" marker-end="url(#parr)"/>

    <!-- Stage 2 -->
    <rect x="175" y="15" width="145" height="45" rx="5" fill="#eff6ff" stroke="#2563eb" stroke-width="1.5"/>
    <text x="247" y="33" font-size="8.5" font-weight="700" fill="#1e3a8a" text-anchor="middle">2. V2 Preprocessing</text>
    <text x="247" y="47" font-size="7" fill="#475569" text-anchor="middle">NFKC, 10MB bounds, Strip</text>

    <line x1="320" y1="37" x2="350" y2="37" stroke="#0f172a" stroke-width="1.5" marker-end="url(#parr)"/>

    <!-- Stage 3 -->
    <rect x="350" y="15" width="145" height="45" rx="5" fill="#fef3c7" stroke="#d97706" stroke-width="1.5"/>
    <text x="422" y="33" font-size="8.5" font-weight="700" fill="#92400e" text-anchor="middle">3. Visual Extraction</text>
    <text x="422" y="47" font-size="7" fill="#78350f" text-anchor="middle">QR Decode &amp; EasyOCR</text>

    <line x1="495" y1="37" x2="525" y2="37" stroke="#0f172a" stroke-width="1.5" marker-end="url(#parr)"/>

    <!-- Stage 4 -->
    <rect x="525" y="15" width="130" height="45" rx="5" fill="#eff6ff" stroke="#2563eb" stroke-width="1.5"/>
    <text x="590" y="33" font-size="8.5" font-weight="700" fill="#1e3a8a" text-anchor="middle">4. SSRF-Safe Fetch</text>
    <text x="590" y="47" font-size="7" fill="#475569" text-anchor="middle">DNS Check, Redirects</text>

    <line x1="590" y1="60" x2="590" y2="85" stroke="#0f172a" stroke-width="1.5"/>
    <line x1="590" y1="85" x2="335" y2="85" stroke="#0f172a" stroke-width="1.5"/>
    <line x1="335" y1="85" x2="335" y2="105" stroke="#0f172a" stroke-width="1.5" marker-end="url(#parr)"/>

    <!-- Stage 5: Concurrent Parallel Stage -->
    <rect x="15" y="105" width="640" height="115" rx="8" fill="#f0fdf4" stroke="#16a34a" stroke-width="2"/>
    <text x="335" y="125" font-size="9.5" font-weight="700" fill="#166534" text-anchor="middle">5. Concurrent Engine Execution (asyncio.gather via EngineRegistry)</text>
    <text x="335" y="137" font-size="7" fill="#15803d" text-anchor="middle">Bounded 30.0-second timeout per engine • Fault-tolerant safe_analyze() wrappers</text>

    <g transform="translate(30, 147)" font-size="8">
      <rect x="0" y="0" width="95" height="55" rx="4" fill="#ffffff" stroke="#86efac"/>
      <text x="47" y="18" font-weight="700" fill="#0f172a" text-anchor="middle">URL Engine</text>
      <text x="47" y="32" font-size="6.5" fill="#475569" text-anchor="middle">17 Lexical Rules</text>
      <text x="47" y="43" font-size="6.5" fill="#475569" text-anchor="middle">GSB + WHOIS</text>

      <rect x="103" y="0" width="95" height="55" rx="4" fill="#ffffff" stroke="#86efac"/>
      <text x="150" y="18" font-weight="700" fill="#0f172a" text-anchor="middle">NLP Engine</text>
      <text x="150" y="32" font-size="6.5" fill="#475569" text-anchor="middle">5 Threat Patterns</text>
      <text x="150" y="43" font-size="6.5" fill="#475569" text-anchor="middle">OTP Suppressor</text>

      <rect x="206" y="0" width="95" height="55" rx="4" fill="#ffffff" stroke="#86efac"/>
      <text x="253" y="18" font-weight="700" fill="#0f172a" text-anchor="middle">Sender Engine</text>
      <text x="253" y="32" font-size="6.5" fill="#475569" text-anchor="middle">SQLite Profiling</text>
      <text x="253" y="43" font-size="6.5" fill="#475569" text-anchor="middle">Domain Drift</text>

      <rect x="309" y="0" width="95" height="55" rx="4" fill="#ffffff" stroke="#86efac"/>
      <text x="356" y="18" font-weight="700" fill="#0f172a" text-anchor="middle">Header Engine</text>
      <text x="356" y="32" font-size="6.5" fill="#475569" text-anchor="middle">SPF/DKIM/DMARC</text>
      <text x="356" y="43" font-size="6.5" fill="#475569" text-anchor="middle">Reply-To Mismatch</text>

      <rect x="412" y="0" width="95" height="55" rx="4" fill="#ffffff" stroke="#86efac"/>
      <text x="459" y="18" font-weight="700" fill="#0f172a" text-anchor="middle">Attachment Eng.</text>
      <text x="459" y="32" font-size="6.5" fill="#475569" text-anchor="middle">Static OOXML/PDF</text>
      <text x="459" y="43" font-size="6.5" fill="#475569" text-anchor="middle">Zip Bomb Traversal</text>

      <rect x="515" y="0" width="95" height="55" rx="4" fill="#ffffff" stroke="#86efac"/>
      <text x="562" y="18" font-weight="700" fill="#0f172a" text-anchor="middle">Malware Eng.</text>
      <text x="562" y="32" font-size="6.5" fill="#475569" text-anchor="middle">VirusTotal Hash</text>
      <text x="562" y="43" font-size="6.5" fill="#475569" text-anchor="middle">10m TTL Cache</text>
    </g>

    <line x1="335" y1="220" x2="335" y2="245" stroke="#0f172a" stroke-width="1.5" marker-end="url(#parr)"/>

    <!-- Stages 6, 7, 8, 9, 10 -->
    <rect x="15" y="245" width="115" height="52" rx="5" fill="#f8fafc" stroke="#0f172a" stroke-width="1.5"/>
    <text x="72" y="263" font-size="7.5" font-weight="700" fill="#0f172a" text-anchor="middle">6. Post-Process</text>
    <text x="72" y="276" font-size="6.5" fill="#475569" text-anchor="middle">Extension Mismatch</text>
    <text x="72" y="286" font-size="6.5" fill="#dc2626" text-anchor="middle">+30 Malware Boost</text>

    <line x1="130" y1="271" x2="150" y2="271" stroke="#0f172a" stroke-width="1.5" marker-end="url(#parr)"/>

    <rect x="150" y="245" width="115" height="52" rx="5" fill="#eff6ff" stroke="#2563eb" stroke-width="1.5"/>
    <text x="207" y="263" font-size="7.5" font-weight="700" fill="#1e3a8a" text-anchor="middle">7. Risk Fusion</text>
    <text x="207" y="276" font-size="6.5" fill="#475569" text-anchor="middle">Confidence * Reliability</text>
    <text x="207" y="286" font-size="6.5" fill="#1e3a8a" text-anchor="middle">Score (0–100)</text>

    <line x1="265" y1="271" x2="285" y2="271" stroke="#0f172a" stroke-width="1.5" marker-end="url(#parr)"/>

    <rect x="285" y="245" width="115" height="52" rx="5" fill="#eff6ff" stroke="#2563eb" stroke-width="1.5"/>
    <text x="342" y="263" font-size="7.5" font-weight="700" fill="#1e3a8a" text-anchor="middle">8. Classification</text>
    <text x="342" y="276" font-size="6.5" fill="#475569" text-anchor="middle">Policy Thresholds</text>
    <text x="342" y="286" font-size="6.5" fill="#1e3a8a" text-anchor="middle">Malware Safeguard</text>

    <line x1="400" y1="271" x2="420" y2="271" stroke="#0f172a" stroke-width="1.5" marker-end="url(#parr)"/>

    <rect x="420" y="245" width="115" height="52" rx="5" fill="#eff6ff" stroke="#2563eb" stroke-width="1.5"/>
    <text x="477" y="263" font-size="7.5" font-weight="700" fill="#1e3a8a" text-anchor="middle">9. Explainability</text>
    <text x="477" y="276" font-size="6.5" fill="#475569" text-anchor="middle">Flag-to-Reason Map</text>
    <text x="477" y="286" font-size="6.5" fill="#1e3a8a" text-anchor="middle">Prescriptive Action</text>

    <line x1="535" y1="271" x2="555" y2="271" stroke="#0f172a" stroke-width="1.5" marker-end="url(#parr)"/>

    <rect x="555" y="245" width="100" height="52" rx="5" fill="#f8fafc" stroke="#0f172a" stroke-width="1.5"/>
    <text x="605" y="263" font-size="7.5" font-weight="700" fill="#0f172a" text-anchor="middle">10. Response</text>
    <text x="605" y="276" font-size="6.5" fill="#475569" text-anchor="middle">UnifiedScanResponse</text>
    <text x="605" y="286" font-size="6.5" fill="#15803d" text-anchor="middle">JSON via HTTP 200</text>

    <!-- Bottom summary box -->
    <rect x="15" y="315" width="640" height="50" rx="5" fill="#f8fafc" stroke="#cbd5e1"/>
    <text x="30" y="333" font-size="7.5" font-weight="700" fill="#0f172a">Key Pipeline Guarantee:</text>
    <text x="30" y="347" font-size="7" fill="#475569">Visual context extraction is strictly sequential to feed downstream NLP and URL engines. URL redirect resolution precedes concurrent execution.</text>
    <text x="30" y="358" font-size="7" fill="#475569">All independent engines run concurrently in parallel. Fusion runs exactly once. Errored engines never contribute false safe scores.</text>
  </svg>
  <div class="diagram-caption">Figure 5: Complete Threat-Scanning Pipeline showing deterministic stage progression and visual context propagation.</div>
</div>

<div class="page-break"></div>

<!-- ========================================================================= -->
<!-- 10. RISK FUSION & DYNAMIC CLASSIFICATION -->
<!-- ========================================================================= -->
<h1>10. Risk Fusion & Dynamic Classification</h1>
<p>
  The fusion engine (<span class="filepath">backend/app/fusion/risk_fusion.py</span>) implements confidence-weighted Bayesian aggregation. It ensures that skipped and errored engines are completely excluded from the mathematical calculation, while usable engines contribute proportional to their empirical reliability:
</p>
<div class="callout" style="margin: 10px 0 14px;">
  <div class="callout-title">Mathematical Weighting Formula</div>
  <p style="margin-bottom: 6px; font-size: 13px;">
    <strong>Weight<sub>i</sub></strong> &nbsp;=&nbsp; 
    <strong>Confidence<sub>i</sub></strong> &times; <strong>Reliability<sub>i</sub></strong> &times; <strong>StatusFactor<sub>i</sub></strong>
    &nbsp;&nbsp;&mdash;&nbsp;&nbsp; where <em>StatusFactor</em> = 1.0 for <span class="badge badge-impl">SUCCESS</span> and 0.5 for <span class="badge badge-ext">PARTIAL</span>.
  </p>
  <div style="margin: 8px 0 2px; display: flex; align-items: center; gap: 8px; font-size: 13px;">
    <span style="font-weight: 700; color: var(--navy-900);">Final RiskScore</span> &nbsp;=&nbsp;
    <div style="display: inline-flex; flex-direction: column; align-items: center; vertical-align: middle;">
      <span style="border-bottom: 1.5px solid var(--navy-800); padding-bottom: 2px; padding-left: 8px; padding-right: 8px; font-weight: 600;">&sum; (RiskScore<sub>i</sub> &times; Weight<sub>i</sub>)</span>
      <span style="padding-top: 2px; font-weight: 600;">&sum; Weight<sub>i</sub></span>
    </div>
    <span style="font-size: 11.5px; color: var(--slate-600); margin-left: 10px;">(Bounded to [0.0, 100.0] interval)</span>
  </div>
</div>

<p>
  The classification policy (<span class="filepath">backend/app/classification/policy.py</span>) deterministically maps that score into discrete security tiers:
</p>

<table>
  <thead>
    <tr>
      <th style="width: 18%;">Classification Profile</th>
      <th style="width: 16%;">Safe Boundary</th>
      <th style="width: 16%;">Suspicious</th>
      <th style="width: 16%;">Deceptive</th>
      <th style="width: 16%;">Phishing</th>
      <th style="width: 18%;">Malware Condition</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>default</strong> (Standard)</td>
      <td>&lt; 20.0</td>
      <td>20.0 – 44.9</td>
      <td>45.0 – 69.9</td>
      <td>70.0 – 89.9</td>
      <td>&ge; 90.0 + Malware Signal*</td>
    </tr>
    <tr>
      <td><strong>strict</strong> (Heightened)</td>
      <td>&lt; 15.0</td>
      <td>15.0 – 34.9</td>
      <td>35.0 – 54.9</td>
      <td>55.0 – 79.9</td>
      <td>&ge; 80.0 + Malware Signal*</td>
    </tr>
    <tr>
      <td><strong>enterprise</strong> (Zero-Trust)</td>
      <td>&lt; 10.0</td>
      <td>10.0 – 29.9</td>
      <td>30.0 – 49.9</td>
      <td>50.0 – 74.9</td>
      <td>&ge; 75.0 + Malware Signal*</td>
    </tr>
  </tbody>
</table>
<p style="font-size: 7.5pt; color: #64748b;">
  <em>*Malware Safeguard:</em> A score at or above the upper threshold will classify as <code>Phishing</code> unless a verified malware signal is confirmed (<code>vt_malicious</code>, <code>MALWARE</code>, or <code>malware_engine</code> risk &ge; 90.0 with confidence &ge; 0.5).
</p>

<!-- ========================================================================= -->
<!-- 11. EXPLAINABILITY ARCHITECTURE -->
<!-- ========================================================================= -->
<h1>11. Explainability Architecture</h1>
<p>
  Located at <span class="filepath">backend/app/explainability/explainability_engine.py</span>, the explainability subsystem translates raw machine flags into human-understandable verdicts and concrete user precautions:
</p>
<ul>
  <li><strong>Reason Synthesis:</strong> Translates flags (e.g., <code>high_shannon_entropy</code> &rarr; <em>"The URL looks randomly generated."</em>; <code>ATTACHMENT_TYPE_MISMATCH</code> &rarr; <em>"The attachment extension does not match its true detected file type."</em>).</li>
  <li><strong>Degraded Engine Telemetry Warnings:</strong> Injects explicit top-level warnings when security services fail (e.g., <em>"Malware scan unavailable: Anti-malware engine could not complete analysis."</em>).</li>
  <li><strong>Action Prescriptions:</strong>
    <ul>
      <li><strong>Safe:</strong> <em>"Proceed with normal caution."</em> (or <em>"Proceed with caution. Malware scanning was unavailable for this file."</em>)</li>
      <li><strong>Suspicious:</strong> <em>"Exercise caution. Do not share sensitive information unless you are certain of the source."</em></li>
      <li><strong>Deceptive:</strong> <em>"Do not trust this content. Avoid clicking links or downloading attachments."</em></li>
      <li><strong>Phishing:</strong> <em>"Do not click any links or provide credentials. Report and delete this message."</em></li>
      <li><strong>Malware:</strong> <em>"Do not open or execute file/link. Isolate and permanently delete the content immediately."</em></li>
    </ul>
  </li>
</ul>

<div class="page-break"></div>

<!-- ========================================================================= -->
<!-- 12. GMAIL / BACKGROUND PROTECTION / SCAN HISTORY / FEEDBACK FLOW -->
<!-- ========================================================================= -->
<h1>12. Gmail, Background Protection, Scan History & Feedback</h1>

<h2>12.1 Gmail Integration &amp; OAuth Lifecycle</h2>
<p>
  Users authenticate via Google Sign-In with <code>gmail.readonly</code> scope (<span class="filepath">com.secureshield.ai.GmailScanner</span>). The client inspects unread messages, extracts headers (From, Subject, Date) and MIME body parts (plain text &amp; HTML), extracts embedded URLs, and passes them to the backend without mutating the user's inbox.
</p>

<h2>12.2 Background Threat Protection</h2>
<p>
  Managed by <span class="filepath">BackgroundProtectionManager.kt</span> and registered as a periodic 15-minute background task in Android <code>WorkManager</code> (<span class="filepath">ThreatAlertWorker.kt</span>). It verifies network and battery constraints, checks for unread emails, skips previously scanned messages using <span class="filepath">ProcessedMessageStore</span> (500-entry ring buffer in SharedPreferences), and fires a high-priority push notification (<code>SS_ALERTS</code>) if a threat is classified as <strong>Phishing</strong> or <strong>Malware</strong>.
</p>

<h2>12.3 Client-Side Sanitized Scan History</h2>
<p>
  Managed by <span class="filepath">ScanHistoryDatabase.kt</span> and <span class="filepath">ScanHistoryRepository.kt</span> storing data in on-device SQLite database <code>secure_scan_history.db</code> (Schema Version 3). Before storage, <span class="filepath">ScanHistorySanitizer</span> scrubs all secrets, passwords, OTPs, tokens, URLs, and phone numbers using regex patterns.
</p>

<h2>12.4 Feedback &amp; Evaluation Flow</h2>
<p>
  Users submit thumbs up / thumbs down feedback on scan cards. <span class="filepath">FeedbackSubmissionManager.kt</span> prevents double-voting via thread-safe in-flight locks. The backend persists the vote in <span class="filepath">feedback.db</span>, and <code>/api/evaluation/metrics</code> aggregates model precision metrics.
</p>

<!-- ========================================================================= -->
<!-- 13. DATA & STORAGE ARCHITECTURE (DIAGRAM 6: DATA FLOW) -->
<!-- ========================================================================= -->
<h1>13. Data & Storage Architecture</h1>
<p>
  The data flow diagram below traces an input through processing, evidence collection, confidence fusion, classification, client display, and local storage:
</p>

<div class="diagram-box">
  <!-- DIAGRAM 6: END-TO-END DATA FLOW DIAGRAM -->
  <svg width="670" height="300" viewBox="0 0 670 300">
    <!-- Flow Column 1: Client Ingestion -->
    <rect x="15" y="25" width="125" height="55" rx="6" fill="#f8fafc" stroke="#0f172a" stroke-width="1.5"/>
    <text x="77" y="47" font-size="8.5" font-weight="700" fill="#0f172a" text-anchor="middle">1. User / Share Input</text>
    <text x="77" y="61" font-size="7" fill="#475569" text-anchor="middle">Text, URL, File, Image</text>

    <line x1="77" y1="80" x2="77" y2="105" stroke="#0f172a" stroke-width="1.5" marker-end="url(#parr)"/>

    <rect x="15" y="105" width="125" height="55" rx="6" fill="#eff6ff" stroke="#2563eb" stroke-width="1.5"/>
    <text x="77" y="127" font-size="8.5" font-weight="700" fill="#1e3a8a" text-anchor="middle">2. Client Extraction</text>
    <text x="77" y="141" font-size="7" fill="#475569" text-anchor="middle">SharedIntentRouter</text>
    <text x="77" y="151" font-size="6.5" fill="#2563eb" text-anchor="middle">10 MB Stream Bound</text>

    <line x1="140" y1="132" x2="175" y2="132" stroke="#2563eb" stroke-width="1.5" marker-end="url(#arr)"/>

    <!-- Flow Column 2: Backend Normalization & Execution -->
    <rect x="175" y="105" width="135" height="55" rx="6" fill="#fef3c7" stroke="#d97706" stroke-width="1.5"/>
    <text x="242" y="127" font-size="8.5" font-weight="700" fill="#92400e" text-anchor="middle">3. V2 Normalization</text>
    <text x="242" y="141" font-size="7" fill="#78350f" text-anchor="middle">V2Preprocessor</text>
    <text x="242" y="151" font-size="6.5" fill="#78350f" text-anchor="middle">NFKC, Scheme &amp; Basename</text>

    <line x1="242" y1="160" x2="242" y2="185" stroke="#0f172a" stroke-width="1.5" marker-end="url(#parr)"/>

    <rect x="175" y="185" width="135" height="65" rx="6" fill="#f0fdf4" stroke="#16a34a" stroke-width="1.5"/>
    <text x="242" y="207" font-size="8.5" font-weight="700" fill="#166534" text-anchor="middle">4. Parallel Execution</text>
    <text x="242" y="221" font-size="7" fill="#15803d" text-anchor="middle">Visual sequential stage</text>
    <text x="242" y="233" font-size="6.5" fill="#15803d" text-anchor="middle">then 6 engines gather()</text>

    <line x1="310" y1="217" x2="350" y2="217" stroke="#16a34a" stroke-width="1.5" marker-end="url(#arr)"/>

    <!-- Flow Column 3: Fusion & Classification -->
    <rect x="350" y="185" width="140" height="65" rx="6" fill="#eff6ff" stroke="#2563eb" stroke-width="1.5"/>
    <text x="420" y="207" font-size="8.5" font-weight="700" fill="#1e3a8a" text-anchor="middle">5. Fusion &amp; Policy</text>
    <text x="420" y="221" font-size="7" fill="#475569" text-anchor="middle">Confidence-Weighted Score</text>
    <text x="420" y="233" font-size="6.5" fill="#475569" text-anchor="middle">5-Tier Risk Classification</text>

    <line x1="420" y1="185" x2="420" y2="160" stroke="#0f172a" stroke-width="1.5" marker-end="url(#parr)"/>

    <!-- Flow Column 4: Client Display & Storage -->
    <rect x="350" y="105" width="140" height="55" rx="6" fill="#f8fafc" stroke="#0f172a" stroke-width="1.5"/>
    <text x="420" y="127" font-size="8.5" font-weight="700" fill="#0f172a" text-anchor="middle">6. UnifiedScanResponse</text>
    <text x="420" y="141" font-size="7" fill="#475569" text-anchor="middle">JSON via HTTP 200</text>
    <text x="420" y="151" font-size="6.5" fill="#64748b" text-anchor="middle">Strict parser validation</text>

    <line x1="490" y1="132" x2="530" y2="132" stroke="#2563eb" stroke-width="1.5" marker-end="url(#arr)"/>

    <rect x="530" y="75" width="125" height="50" rx="5" fill="#eff6ff" stroke="#2563eb" stroke-width="1.5"/>
    <text x="592" y="95" font-size="8" font-weight="700" fill="#1e3a8a" text-anchor="middle">7A. UI Verdict</text>
    <text x="592" y="108" font-size="6.5" fill="#475569" text-anchor="middle">Badge, Reasons &amp; Action</text>
    <text x="592" y="118" font-size="6.5" fill="#2563eb" text-anchor="middle">Thumbs Up/Down Card</text>

    <rect x="530" y="135" width="125" height="50" rx="5" fill="#f0fdf4" stroke="#16a34a" stroke-width="1.5"/>
    <text x="592" y="155" font-size="8" font-weight="700" fill="#166534" text-anchor="middle">7B. Sanitized SQLite</text>
    <text x="592" y="168" font-size="6.5" fill="#475569" text-anchor="middle">ScanHistorySanitizer</text>
    <text x="592" y="178" font-size="6.5" fill="#166534" text-anchor="middle">Redacts secrets to DB</text>

    <rect x="530" y="195" width="125" height="50" rx="5" fill="#fdf2f8" stroke="#db2777" stroke-width="1.5"/>
    <text x="592" y="215" font-size="8" font-weight="700" fill="#9d174d" text-anchor="middle">7C. Push Alerts</text>
    <text x="592" y="228" font-size="6.5" fill="#475569" text-anchor="middle">ThreatAlertWorker</text>
    <text x="592" y="238" font-size="6.5" fill="#db2777" text-anchor="middle">Phishing/Malware Alert</text>
  </svg>
  <div class="diagram-caption">Figure 6: End-to-End Data Flow Diagram tracing artifact progression, sanitization, and alert dispatch.</div>
</div>

<div class="page-break"></div>

<!-- ========================================================================= -->
<!-- 14. SECURITY & PRIVACY ARCHITECTURE -->
<!-- ========================================================================= -->
<h1>14. Security & Privacy Architecture</h1>
<p>
  SecureShield-AI maintains strict physical and software boundaries to ensure user privacy, prevent server-side request forgery (SSRF), block code execution, and thwart adversarial data poisoning:
</p>

<div class="diagram-box">
  <!-- DIAGRAM 7: SECURITY & PRIVACY BOUNDARY (CLEAN PURE SVG) -->
  <svg width="670" height="270" viewBox="0 0 670 270">
    <!-- Zone 1: Client Private Sandbox -->
    <rect x="15" y="15" width="150" height="240" rx="8" fill="#eff6ff" stroke="#2563eb" stroke-dasharray="4,4"/>
    <text x="90" y="38" font-size="9" font-weight="700" fill="#1e3a8a" text-anchor="middle">ZONE 1: Client Private</text>
    <text x="90" y="52" font-size="7" fill="#2563eb" text-anchor="middle">(On-Device Only)</text>
    <text x="25" y="75" font-size="7" fill="#334155">• Gmail OAuth Token</text>
    <text x="25" y="90" font-size="7" fill="#334155">• Transient email body</text>
    <text x="25" y="105" font-size="7" fill="#334155">• Sanitized scan history</text>
    <text x="25" y="120" font-size="7" fill="#334155">• Passwords / OTPs</text>
    <text x="25" y="132" font-size="6.5" fill="#64748b">&nbsp;&nbsp;(redacted by regex)</text>
    <text x="25" y="155" font-size="7" font-weight="700" fill="#166534">NEVER SENT TO SERVER</text>
    <text x="25" y="170" font-size="7" fill="#334155">• Account credentials</text>
    <text x="25" y="185" font-size="7" fill="#334155">• Google user token</text>
    <text x="25" y="200" font-size="7" fill="#334155">• Contact address book</text>

    <!-- Zone 2: Transport Boundary -->
    <rect x="175" y="15" width="140" height="240" rx="8" fill="#f8fafc" stroke="#64748b"/>
    <text x="245" y="38" font-size="9" font-weight="700" fill="#0f172a" text-anchor="middle">ZONE 2: Transport</text>
    <text x="245" y="52" font-size="7" fill="#64748b" text-anchor="middle">(TLS 1.3 / Strict Bounded)</text>
    <text x="185" y="75" font-size="7" fill="#334155">• Text (max 50k chars)</text>
    <text x="185" y="90" font-size="7" fill="#334155">• URL (max 4k chars)</text>
    <text x="185" y="105" font-size="7" fill="#334155">• File (max 10 MB)</text>
    <text x="185" y="120" font-size="7" fill="#334155">• Clean email sender</text>
    <text x="185" y="135" font-size="7" fill="#334155">• Headers (max 100)</text>
    <text x="185" y="155" font-size="7" font-weight="700" fill="#92400e">STRICT ENFORCEMENT</text>
    <text x="185" y="170" font-size="7" fill="#334155">• Rejects oversized</text>
    <text x="185" y="185" font-size="7" fill="#334155">• Rejects bad schemes</text>
    <text x="185" y="200" font-size="7" fill="#334155">• Strips control chars</text>

    <!-- Zone 3: Backend Ephemeral Processing -->
    <rect x="325" y="15" width="165" height="240" rx="8" fill="#f0fdf4" stroke="#16a34a"/>
    <text x="407" y="38" font-size="9" font-weight="700" fill="#166534" text-anchor="middle">ZONE 3: Ephemeral Processing</text>
    <text x="407" y="52" font-size="7" fill="#15803d" text-anchor="middle">(RAM-Only • 0 Code Execution)</text>
    <text x="335" y="75" font-size="7" fill="#334155">• Zero script/macro run</text>
    <text x="335" y="90" font-size="7" fill="#334155">• Zero executable launch</text>
    <text x="335" y="105" font-size="7" fill="#334155">• Static binary inspection</text>
    <text x="335" y="120" font-size="7" fill="#334155">• Anti-SSRF DNS pinning</text>
    <text x="335" y="135" font-size="7" fill="#334155">• Blocks private RFC1918</text>
    <text x="335" y="155" font-size="7" font-weight="700" fill="#166534">STORAGE EXCLUSION</text>
    <text x="335" y="170" font-size="7" fill="#334155">• No email bodies stored</text>
    <text x="335" y="185" font-size="7" fill="#334155">• No file contents stored</text>
    <text x="335" y="200" font-size="7" fill="#334155">• No user PII retained</text>

    <!-- Zone 4: External Services Boundary -->
    <rect x="500" y="15" width="155" height="240" rx="8" fill="#fdf2f8" stroke="#db2777"/>
    <text x="577" y="38" font-size="9" font-weight="700" fill="#9d174d" text-anchor="middle">ZONE 4: External APIs</text>
    <text x="577" y="52" font-size="7" fill="#db2777" text-anchor="middle">(Minimal Metadata Only)</text>
    <text x="510" y="75" font-size="7" fill="#334155"><tspan font-weight="700">VirusTotal:</tspan> SHA-256</text>
    <text x="510" y="88" font-size="6.5" fill="#64748b">hash only (0 file data)</text>
    <text x="510" y="105" font-size="7" fill="#334155"><tspan font-weight="700">Google GSB:</tspan> URL</text>
    <text x="510" y="118" font-size="6.5" fill="#64748b">query only (0 user data)</text>
    <text x="510" y="135" font-size="7" fill="#334155"><tspan font-weight="700">WHOIS:</tspan> Root domain</text>
    <text x="510" y="148" font-size="6.5" fill="#64748b">only (2.0s timeout)</text>
    <text x="510" y="170" font-size="7" font-weight="700" fill="#9d174d">FAIL-SAFE DESIGN</text>
    <text x="510" y="185" font-size="7" fill="#334155">• API down &#8800; Safe score</text>
    <text x="510" y="200" font-size="7" fill="#334155">• Isolated from fusion</text>
  </svg>
  <div class="diagram-caption">Figure 7: Security &amp; Privacy Boundary Matrix showing isolation between client, network, execution, and cloud feeds.</div>
</div>

<!-- ========================================================================= -->
<!-- 15. EXTERNAL API INTEGRATION -->
<!-- ========================================================================= -->
<h1>15. External API Integration</h1>
<table>
  <thead>
    <tr>
      <th style="width: 20%;">External Service</th>
      <th style="width: 15%;">Protocol / Auth</th>
      <th style="width: 30%;">Data Transmitted</th>
      <th style="width: 35%;">Degraded / Failure Behavior</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Google Safe Browsing v4</strong></td>
      <td>REST / API Key</td>
      <td>Target URL string (in JSON payload)</td>
      <td>Status set to <span class="badge badge-ext">PARTIAL</span>; relies on 17 lexical rules and domain age.</td>
    </tr>
    <tr>
      <td><strong>VirusTotal v3</strong></td>
      <td>REST / API Key</td>
      <td>SHA-256 binary hash string only</td>
      <td>Returns <span class="badge badge-danger">ERROR</span> + 0.0 confidence; ignored in fusion; surfaces warning.</td>
    </tr>
    <tr>
      <td><strong>AsyncWHOIS RDAP</strong></td>
      <td>Socket Port 43</td>
      <td>Root domain (e.g. <code>example.com</code>)</td>
      <td>Strict 2.0s timeout; treated as unknown domain age without error.</td>
    </tr>
    <tr>
      <td><strong>Google Sign-In &amp; Gmail</strong></td>
      <td>OAuth 2.0</td>
      <td>Client-side read token (<code>gmail.readonly</code>)</td>
      <td>Presents setup dialog; offers simulated demo email scan fallback.</td>
    </tr>
  </tbody>
</table>

<div class="page-break"></div>

<!-- ========================================================================= -->
<!-- 16 TO 22 -->
<!-- ========================================================================= -->
<h1>16. Error Handling & Resource Boundaries</h1>
<table style="margin-bottom: 10px; font-size: 11px;">
  <thead>
    <tr>
      <th style="width: 25%; padding: 6px 8px;">Failure / Boundary Condition</th>
      <th style="width: 35%; padding: 6px 8px;">Protective Architectural Mechanism</th>
      <th style="width: 40%; padding: 6px 8px;">System Behavior &amp; User Experience</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="padding: 5px 8px;"><strong>VirusTotal API Unavailable / Timeout</strong></td>
      <td style="padding: 5px 8px;"><span class="filepath">MalwareEngine</span> catches network errors and returns <span class="badge badge-danger">ERROR</span> status with <code>confidence = 0.0</code>.</td>
      <td style="padding: 5px 8px;">Engine is ignored in risk fusion. Score is computed from other engines. Response injects top-level warning: <em>"malware scan unavailable"</em>.</td>
    </tr>
    <tr>
      <td style="padding: 5px 8px;"><strong>Google Safe Browsing Down</strong></td>
      <td style="padding: 5px 8px;"><span class="filepath">URLEngine</span> records error, marks status as <span class="badge badge-ext">PARTIAL</span> with confidence 0.80.</td>
      <td style="padding: 5px 8px;">Falls back immediately to 17 lexical heuristics and WHOIS domain age. Pipeline continues without blocking.</td>
    </tr>
    <tr>
      <td style="padding: 5px 8px;"><strong>Hanging External WHOIS Server</strong></td>
      <td style="padding: 5px 8px;"><span class="filepath">_get_domain_age_days()</span> wraps socket query with strict <code>asyncio.wait_for(timeout=2.0)</code>.</td>
      <td style="padding: 5px 8px;">Times out in 2 seconds; domain age is treated as unknown; URL engine completes without delay.</td>
    </tr>
    <tr>
      <td style="padding: 5px 8px;"><strong>Oversized Shared File (&gt;10 MB)</strong></td>
      <td style="padding: 5px 8px;">Dual check: Android client buffer enforces 10 MB limit; <span class="filepath">V2Preprocessor</span> rejects any payload &gt; 10,485,760 bytes.</td>
      <td style="padding: 5px 8px;">Immediate rejection with descriptive error: <em>"File exceeds maximum allowed size of 10MB"</em>. Prevents server OOM.</td>
    </tr>
    <tr>
      <td style="padding: 5px 8px;"><strong>SSRF / Private IP Spoofing</strong></td>
      <td style="padding: 5px 8px;"><span class="filepath">SafeURLFetcher</span> validates DNS before connecting, blocking loopback, RFC1918 private, link-local, and multicast ranges.</td>
      <td style="padding: 5px 8px;">Blocks connection immediately. Connects directly to safe IP with Host/SNI headers to eliminate TOCTOU rebinding.</td>
    </tr>
    <tr>
      <td style="padding: 5px 8px;"><strong>Double Feedback Vote Manipulation</strong></td>
      <td style="padding: 5px 8px;"><span class="filepath">FeedbackSubmissionManager</span> enforces local mutex; backend enforces <code>scan_id UNIQUE</code> index in SQLite.</td>
      <td style="padding: 5px 8px;">Second submission returns HTTP 409 Conflict. UI dismisses cleanly without corrupting evaluation metrics.</td>
    </tr>
  </tbody>
</table>

<h1 style="margin-top: 14px; margin-bottom: 6px;">17. Deployment & Runtime Architecture</h1>
<ul style="margin: 4px 0 8px 18px; font-size: 11.5px;">
  <li style="margin-bottom: 3px;"><strong>Backend Server:</strong> Python 3.14 running FastAPI under Uvicorn ASGI server. Local development runs on port 8000; production uses reverse-proxy TLS termination (Nginx).</li>
  <li style="margin-bottom: 3px;"><strong>Android Application:</strong> Minimum SDK 24 (Android 7.0 Nougat), target SDK 34 (Android 14). Configured with AndroidX WorkManager for background threat scans.</li>
  <li style="margin-bottom: 3px;"><strong>Configuration:</strong> Backend environment loaded via Pydantic <code>BaseSettings</code> from <code>.env</code> file (API keys, environment mode, port).</li>
</ul>

<h1 style="margin-top: 14px; margin-bottom: 6px;">18. Technology Stack</h1>
<div class="callout" style="margin: 6px 0 10px; padding: 8px 12px;">
  <div class="callout-title" style="margin-bottom: 4px; font-size: 12px;">Full Production Technology Inventory</div>
  <p style="font-size: 11.5px; margin: 0; line-height: 1.45;">
    <strong>Backend:</strong> Python 3.14.5, FastAPI 0.115, Uvicorn 0.32, Pydantic v2, HTTPX 0.28, OpenCV (`opencv-python-headless`), EasyOCR 1.7, PyTorch, AsyncWHOIS, TLDExtract, Cachetools, Filetype, SQLite3.<br>
    <strong>Android:</strong> Kotlin 2.2.10, Retrofit 2.9.0, OkHttp 4.12, Gson 2.10, AndroidX WorkManager 2.9, AndroidX NotificationCompat, SQLiteOpenHelper, Google Sign-In SDK, Google Play Services Auth, Google APIs Client for Gmail v1.
  </p>
</div>

<h1 style="margin-top: 14px; margin-bottom: 6px;">19. Key Design Decisions</h1>
<ol style="margin: 4px 0 6px 18px; font-size: 11.5px;">
  <li style="margin-bottom: 3px;"><strong>ADR-01: Dual-Layer OTP Defense Mechanism:</strong> Requiring request verbs alone still flagged legitimate notices like <em>"Never share your OTP"</em>. The active architecture requires request verbs AND applies negative disclaimer suppression (<code>do not share</code>), eliminating false positives on 2FA notices.</li>
  <li style="margin-bottom: 3px;"><strong>ADR-02: Synchronous SSRF Pinning with SNI:</strong> To eliminate TOCTOU DNS rebinding, <code>SafeURLFetcher</code> pre-resolves DNS, connects directly to the validated IP, and explicitly passes Host and SNI headers.</li>
  <li style="margin-bottom: 3px;"><strong>ADR-03: Two-Phase Sequential Visual Stage:</strong> Visual extraction (QR/OCR) runs sequentially first so extracted text and URLs dynamically feed downstream engines before parallel execution.</li>
  <li style="margin-bottom: 3px;"><strong>ADR-04: Static-Only Attachment Inspection:</strong> Zero dynamic code execution. All analysis is static inspection of binary headers, OLE streams, and archive structures.</li>
  <li style="margin-bottom: 3px;"><strong>ADR-05: Malware Signal Safeguard:</strong> Scores alone cannot classify as Malware without verified telemetry from VirusTotal or malware flags.</li>
</ol>

<div class="page-break"></div>

<h1>20. Known Limitations</h1>
<ul>
  <li><strong>CPU Vision Inference:</strong> EasyOCR operates on CPU (<code>gpu=False</code>), requiring 2–4 seconds per high-resolution image scan.</li>
  <li><strong>VirusTotal Quotas:</strong> Free API tier permits 4 requests/minute. Mitigated by an in-memory 10-minute TTL cache.</li>
  <li><strong>Encrypted Archives:</strong> Password-protected archives cannot have their internal files inspected statically and are flagged as suspicious.</li>
</ul>

<h1>21. Final Architecture Summary</h1>
<p>
  SecureShield-AI provides a comprehensive, verified threat defense architecture. By synthesizing seven specialized engines through Bayesian fusion, enforcing strict execution boundaries, providing plain-language explainability, and executing background threat scans, the platform delivers enterprise-grade protection for mobile and web users.
</p>

<h1>22. Appendix — Important Repository Components</h1>
<table>
  <thead>
    <tr>
      <th style="width: 30%;">Component Identifier</th>
      <th style="width: 40%;">Repository Location</th>
      <th style="width: 30%;">Responsibility</th>
    </tr>
  </thead>
  <tbody>
    <tr><td><strong>FastAPI Main Entry</strong></td><td><span class="filepath">backend/main.py</span></td><td>Application bootstrap, CORS &amp; exception handlers</td></tr>
    <tr><td><strong>API Endpoints</strong></td><td><span class="filepath">backend/app/api/routes.py</span></td><td><code>/api/scan</code>, <code>/api/feedback</code>, <code>/api/evaluation/metrics</code></td></tr>
    <tr><td><strong>Scan Input Model</strong></td><td><span class="filepath">backend/app/models/scan_input.py</span></td><td>Universal multi-modal data structure</td></tr>
    <tr><td><strong>Unified Response Model</strong></td><td><span class="filepath">backend/app/models/scan_response.py</span></td><td>Composite response with score &amp; classification</td></tr>
    <tr><td><strong>V2 Preprocessor</strong></td><td><span class="filepath">backend/app/preprocessing/v2_preprocessor.py</span></td><td>Sanitization, NFKC, 10MB bounds, anti-traversal</td></tr>
    <tr><td><strong>SSRF Safe Fetcher</strong></td><td><span class="filepath">backend/app/preprocessing/safe_url_fetcher.py</span></td><td>DNS pre-resolution &amp; direct IP socket pinning</td></tr>
    <tr><td><strong>Unified Scan Pipeline</strong></td><td><span class="filepath">backend/app/engines/pipeline.py</span></td><td>Multi-stage pipeline coordinator</td></tr>
    <tr><td><strong>Engine Registry</strong></td><td><span class="filepath">backend/app/engines/registry.py</span></td><td>Concurrent runner with 30s timeout</td></tr>
    <tr><td><strong>Risk Fusion</strong></td><td><span class="filepath">backend/app/fusion/risk_fusion.py</span></td><td>Confidence-weighted Bayesian score calculation</td></tr>
    <tr><td><strong>Classification Policy</strong></td><td><span class="filepath">backend/app/classification/policy.py</span></td><td>5-tier classification profiles &amp; malware safeguard</td></tr>
    <tr><td><strong>Explainability Engine</strong></td><td><span class="filepath">backend/app/explainability/explainability_engine.py</span></td><td>Reason mapping &amp; actionable recommendations</td></tr>
    <tr><td><strong>Android Main UI</strong></td><td><span class="filepath">android/app/src/main/java/.../MainActivity.kt</span></td><td>Card UI, feedback buttons, scan trigger</td></tr>
    <tr><td><strong>Shared Intent Router</strong></td><td><span class="filepath">android/app/src/main/java/.../share/SharedIntentRouter.kt</span></td><td><code>ACTION_SEND</code> stream and MIME extraction</td></tr>
    <tr><td><strong>Threat Alert Worker</strong></td><td><span class="filepath">android/app/src/main/java/.../background/ThreatAlertWorker.kt</span></td><td>WorkManager periodic background inbox check</td></tr>
    <tr><td><strong>Scan History DB</strong></td><td><span class="filepath">android/app/src/main/java/.../history/ScanHistoryDatabase.kt</span></td><td>On-device sanitized SQLite history store</td></tr>
  </tbody>
</table>

</body>
</html>
"""

    with open(html_filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    print(f"Temporary HTML written to {html_filename}")
    
    edge_path = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    if not os.path.exists(edge_path):
        edge_path = r"C:\Program Files\Microsoft\Edge\Application\msedge.exe"
    
    abs_html = os.path.abspath(html_filename)
    abs_pdf = os.path.abspath(pdf_filename)
    file_url = f"file:///{abs_html.replace(os.sep, '/')}"
    
    cmd = [
        edge_path,
        "--headless=new",
        "--disable-gpu",
        "--no-pdf-header-footer",
        f"--print-to-pdf={abs_pdf}",
        file_url
    ]
    
    print("Executing Edge PDF conversion...")
    res = subprocess.run(cmd, capture_output=True, text=True)
    print("Edge return code:", res.returncode)
    
    if os.path.exists(abs_pdf):
        print(f"SUCCESS: {pdf_filename} created successfully!")
        doc = pymupdf.open(abs_pdf)
        page_count = len(doc)
        print(f"Total Pages in PDF: {page_count}")
        doc.close()
        
        # Remove temporary HTML
        if os.path.exists(html_filename):
            os.remove(html_filename)
        return abs_pdf, page_count
    else:
        print("ERROR: PDF was not generated.")
        return None, 0

if __name__ == "__main__":
    build_pdf()
