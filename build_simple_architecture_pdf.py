#!/usr/bin/env python3
"""
build_simple_architecture_pdf.py
Generates a clean, simple, professional 2-PAGE System Architecture PDF for SecureShield-AI.
Page 1: Complete High-Level Architecture Diagram on ONE Page.
Page 2: Component Explanations, Technology Stack, Security Summary, and How It Works Flow.
"""

import os
import subprocess
import fitz  # PyMuPDF

def build_pdf():
    html_filename = "SecureShield_AI_Simple_System_Architecture_temp.html"
    pdf_filename = "SecureShield_AI_Simple_System_Architecture.pdf"

    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SecureShield-AI — System Architecture</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;600;700&display=swap');

  @page {
    size: A4 portrait;
    margin: 8mm 12mm 8mm 12mm;
  }

  * {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
  }

  body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    color: #1e293b;
    background-color: #ffffff;
    line-height: 1.35;
    -webkit-print-color-adjust: exact;
    print-color-adjust: exact;
  }

  .page {
    width: 100%;
    height: 100%;
    page-break-after: always;
    position: relative;
    padding-bottom: 22px;
  }

  .page:last-child {
    page-break-after: avoid;
  }

  /* Header styles */
  .doc-header {
    border-bottom: 2px solid #0f172a;
    padding-bottom: 5px;
    margin-bottom: 8px;
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
  }

  .header-left h1 {
    font-size: 19px;
    font-weight: 800;
    color: #0f172a;
    letter-spacing: -0.5px;
  }

  .header-left .subtitle {
    font-size: 10px;
    font-weight: 600;
    color: #2563eb;
    margin-top: 1px;
  }

  .header-right {
    text-align: right;
    font-size: 8px;
    color: #64748b;
    font-weight: 500;
    line-height: 1.35;
    white-space: nowrap;
  }

  .header-right strong {
    color: #0f172a;
  }

  /* Diagram container */
  .diagram-container {
    width: 100%;
    text-align: center;
  }

  /* Footer on both pages */
  .doc-footer {
    position: absolute;
    bottom: 0px;
    left: 0;
    right: 0;
    border-top: 1px solid #cbd5e1;
    padding-top: 4px;
    display: flex;
    justify-content: space-between;
    font-size: 8px;
    color: #64748b;
  }

  /* Page 2 Styles */
  .section-title {
    font-size: 12px;
    font-weight: 800;
    color: #0f172a;
    margin-top: 7px;
    margin-bottom: 4px;
    display: flex;
    align-items: center;
    gap: 5px;
  }

  .section-title .badge-num {
    background: #2563eb;
    color: #ffffff;
    font-size: 8.5px;
    padding: 1px 5px;
    border-radius: 3px;
    font-weight: 700;
  }

  /* Grid layouts for cards */
  .grid-2col {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 7px;
    margin-bottom: 2px;
  }

  .grid-3col {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 7px;
    margin-bottom: 2px;
  }

  .card {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 5px;
    padding: 5px 8px;
  }

  .card-title {
    font-size: 9.5px;
    font-weight: 700;
    color: #0f172a;
    margin-bottom: 2px;
    display: flex;
    align-items: center;
    gap: 4px;
  }

  .card-desc {
    font-size: 8.2px;
    color: #475569;
    line-height: 1.3;
  }

  .tech-category {
    background: #ffffff;
    border: 1px solid #cbd5e1;
    border-left: 3px solid #2563eb;
    border-radius: 4px;
    padding: 4px 7px;
  }

  .tech-cat-title {
    font-size: 9px;
    font-weight: 700;
    color: #1e3a8a;
    margin-bottom: 2px;
  }

  .tech-items {
    font-size: 8px;
    color: #334155;
    font-weight: 500;
    line-height: 1.3;
  }

  /* Workflow Steps */
  .flow-container {
    display: flex;
    gap: 5px;
    align-items: stretch;
    margin-top: 3px;
  }

  .flow-step {
    flex: 1;
    background: #eff6ff;
    border: 1px solid #bfdbfe;
    border-radius: 4px;
    padding: 5px 6px;
    text-align: center;
    position: relative;
  }

  .step-num {
    font-size: 7.5px;
    font-weight: 800;
    color: #1d4ed8;
    background: #dbeafe;
    display: inline-block;
    padding: 1px 4px;
    border-radius: 2px;
    margin-bottom: 2px;
  }

  .step-title {
    font-size: 8.5px;
    font-weight: 700;
    color: #0f172a;
    margin-bottom: 1px;
  }

  .step-desc {
    font-size: 7.5px;
    color: #475569;
    line-height: 1.2;
  }

  .flow-arrow {
    display: flex;
    align-items: center;
    color: #94a3b8;
    font-size: 11px;
    font-weight: 700;
  }

  /* Security Cards */
  .sec-card {
    background: #f0fdf4;
    border: 1px solid #bbf7d0;
    border-left: 3px solid #16a34a;
    border-radius: 4px;
    padding: 5px 8px;
  }

  .sec-title {
    font-size: 9px;
    font-weight: 700;
    color: #166534;
    margin-bottom: 2px;
  }

  .sec-desc {
    font-size: 8px;
    color: #334155;
    line-height: 1.25;
  }
</style>
</head>
<body>

<!-- ========================================================================= -->
<!-- PAGE 1: THE MAIN SYSTEM ARCHITECTURE DIAGRAM -->
<!-- ========================================================================= -->
<div class="page">
  <div class="doc-header">
    <div class="header-left">
      <h1>SecureShield-AI &mdash; System Architecture</h1>
      <div class="subtitle">Multi-Tier Cognitive Threat Defense &bull; High-Level Architecture &amp; Data Flow</div>
    </div>
    <div class="header-right">
      <strong>College Project Evaluation &bull; System Specification</strong><br>
      Status: Verified Against Implementation &bull; Page 1 of 2
    </div>
  </div>

  <div class="diagram-container">
    <svg width="680" height="925" viewBox="0 0 680 925" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <!-- Gradients -->
        <linearGradient id="headerGrad" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stop-color="#1e3a8a"/>
          <stop offset="100%" stop-color="#2563eb"/>
        </linearGradient>
        <linearGradient id="engineGrad" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stop-color="#0f172a"/>
          <stop offset="100%" stop-color="#1e293b"/>
        </linearGradient>
        <!-- Arrowhead Marker -->
        <marker id="arr" markerWidth="8" markerHeight="8" refX="4" refY="4" orient="auto">
          <path d="M0,1 L7,4 L0,7 Z" fill="#2563eb" />
        </marker>
        <marker id="arrDark" markerWidth="8" markerHeight="8" refX="4" refY="4" orient="auto">
          <path d="M0,1 L7,4 L0,7 Z" fill="#0f172a" />
        </marker>
        <marker id="arrExt" markerWidth="8" markerHeight="8" refX="4" refY="4" orient="auto">
          <path d="M0,1 L7,4 L0,7 Z" fill="#7c3aed" />
        </marker>
      </defs>

      <!-- ================================================================ -->
      <!-- 1. USER / INPUT BLOCK -->
      <!-- ================================================================ -->
      <rect x="20" y="5" width="480" height="60" rx="8" fill="#f8fafc" stroke="#3b82f6" stroke-width="1.8"/>
      <rect x="20" y="5" width="480" height="22" rx="8" fill="#eff6ff"/>
      <rect x="20" y="20" width="480" height="7" fill="#eff6ff"/>
      <text x="260" y="19" font-size="10" font-weight="800" fill="#1e3a8a" text-anchor="middle">1. USER &amp; MULTI-MODAL INPUT SOURCES</text>
      
      <!-- Input Source Pills -->
      <g transform="translate(30, 34)">
        <rect x="0" y="0" width="75" height="22" rx="4" fill="#ffffff" stroke="#93c5fd" stroke-width="1"/>
        <text x="37.5" y="14" font-size="8.5" font-weight="700" fill="#1e40af" text-anchor="middle">&#128279; URL Link</text>

        <rect x="85" y="0" width="85" height="22" rx="4" fill="#ffffff" stroke="#93c5fd" stroke-width="1"/>
        <text x="127.5" y="14" font-size="8.5" font-weight="700" fill="#1e40af" text-anchor="middle">&#128221; Text Message</text>

        <rect x="180" y="0" width="85" height="22" rx="4" fill="#ffffff" stroke="#93c5fd" stroke-width="1"/>
        <text x="222.5" y="14" font-size="8.5" font-weight="700" fill="#1e40af" text-anchor="middle">&#128206; File / Attachment</text>

        <rect x="275" y="0" width="85" height="22" rx="4" fill="#ffffff" stroke="#93c5fd" stroke-width="1"/>
        <text x="317.5" y="14" font-size="8.5" font-weight="700" fill="#1e40af" text-anchor="middle">&#128444;&#65039; Image / QR Code</text>

        <rect x="370" y="0" width="85" height="22" rx="4" fill="#ffffff" stroke="#93c5fd" stroke-width="1"/>
        <text x="412.5" y="14" font-size="8.5" font-weight="700" fill="#1e40af" text-anchor="middle">&#9993;&#65039; Email / Gmail</text>
      </g>

      <!-- Arrow: 1 -> 2 -->
      <line x1="260" y1="65" x2="260" y2="82" stroke="#2563eb" stroke-width="2" marker-end="url(#arr)"/>

      <!-- ================================================================ -->
      <!-- 2. ANDROID APPLICATION -->
      <!-- ================================================================ -->
      <rect x="20" y="82" width="480" height="74" rx="8" fill="#f0fdf4" stroke="#16a34a" stroke-width="1.8"/>
      <rect x="20" y="82" width="480" height="22" rx="8" fill="#dcfce7"/>
      <rect x="20" y="97" width="480" height="7" fill="#dcfce7"/>
      <text x="260" y="96" font-size="10" font-weight="800" fill="#166534" text-anchor="middle">2. ANDROID APPLICATION (Client Layer)</text>
      
      <!-- Sub-features of Android App -->
      <g transform="translate(30, 111)">
        <rect x="0" y="0" width="84" height="36" rx="4" fill="#ffffff" stroke="#86efac" stroke-width="1"/>
        <text x="42" y="14" font-size="8" font-weight="700" fill="#14532d" text-anchor="middle">Manual Scan</text>
        <text x="42" y="27" font-size="7" fill="#475569" text-anchor="middle">Instant Check UI</text>

        <rect x="92" y="0" width="84" height="36" rx="4" fill="#ffffff" stroke="#86efac" stroke-width="1"/>
        <text x="134" y="14" font-size="8" font-weight="700" fill="#14532d" text-anchor="middle">Share Menu</text>
        <text x="134" y="27" font-size="7" fill="#475569" text-anchor="middle">ACTION_SEND Hook</text>

        <rect x="184" y="0" width="84" height="36" rx="4" fill="#ffffff" stroke="#86efac" stroke-width="1"/>
        <text x="226" y="14" font-size="8" font-weight="700" fill="#14532d" text-anchor="middle">Gmail Sync</text>
        <text x="226" y="27" font-size="7" fill="#475569" text-anchor="middle">OAuth 2.0 Read-Only</text>

        <rect x="276" y="0" width="94" height="36" rx="4" fill="#ffffff" stroke="#86efac" stroke-width="1"/>
        <text x="323" y="14" font-size="8" font-weight="700" fill="#14532d" text-anchor="middle">Background Shield</text>
        <text x="323" y="27" font-size="7" fill="#475569" text-anchor="middle">15m WorkManager</text>

        <rect x="378" y="0" width="82" height="36" rx="4" fill="#ffffff" stroke="#86efac" stroke-width="1"/>
        <text x="419" y="14" font-size="8" font-weight="700" fill="#14532d" text-anchor="middle">Scan History</text>
        <text x="419" y="27" font-size="7" fill="#475569" text-anchor="middle">Sanitized SQLite</text>
      </g>

      <!-- Arrow: 2 -> 3 -->
      <line x1="260" y1="156" x2="260" y2="173" stroke="#2563eb" stroke-width="2" marker-end="url(#arr)"/>

      <!-- ================================================================ -->
      <!-- 3. FASTAPI BACKEND & PREPROCESSING -->
      <!-- ================================================================ -->
      <rect x="20" y="173" width="480" height="60" rx="8" fill="#fefce8" stroke="#ca8a04" stroke-width="1.8"/>
      <rect x="20" y="173" width="480" height="22" rx="8" fill="#fef9c3"/>
      <rect x="20" y="188" width="480" height="7" fill="#fef9c3"/>
      <text x="260" y="187" font-size="10" font-weight="800" fill="#854d0e" text-anchor="middle">3. FASTAPI BACKEND (API Gateway &amp; Preprocessing)</text>
      
      <!-- Sub-features of Backend -->
      <g transform="translate(30, 202)">
        <rect x="0" y="0" width="220" height="23" rx="4" fill="#ffffff" stroke="#fde047" stroke-width="1"/>
        <text x="110" y="15" font-size="8" font-weight="700" fill="#713f12" text-anchor="middle">Unified REST API Gateway (/api/scan)</text>

        <rect x="235" y="0" width="225" height="23" rx="4" fill="#ffffff" stroke="#fde047" stroke-width="1"/>
        <text x="347" y="15" font-size="8" font-weight="700" fill="#713f12" text-anchor="middle">V2 Preprocessing &bull; NFKC &bull; Anti-SSRF DNS Pinning</text>
      </g>

      <!-- Arrow: 3 -> 4 -->
      <line x1="260" y1="233" x2="260" y2="250" stroke="#2563eb" stroke-width="2" marker-end="url(#arr)"/>

      <!-- ================================================================ -->
      <!-- 4. THREAT DETECTION ENGINES (ONE BIG CONTAINER) -->
      <!-- ================================================================ -->
      <rect x="20" y="250" width="480" height="230" rx="8" fill="#f8fafc" stroke="#0f172a" stroke-width="2"/>
      <rect x="20" y="250" width="480" height="26" rx="8" fill="#0f172a"/>
      <rect x="20" y="268" width="480" height="8" fill="#0f172a"/>
      <text x="260" y="267" font-size="10.5" font-weight="800" fill="#ffffff" text-anchor="middle">4. THREAT DETECTION ENGINES (Parallel Analysis Layer)</text>

      <!-- 7 Engines Grid Inside Box 4 -->
      <!-- Row 1 -->
      <g transform="translate(32, 284)">
        <!-- Engine 1: URL -->
        <rect x="0" y="0" width="220" height="40" rx="5" fill="#ffffff" stroke="#cbd5e1" stroke-width="1.2"/>
        <rect x="0" y="0" width="4" height="40" rx="2" fill="#2563eb"/>
        <text x="12" y="15" font-size="8.5" font-weight="700" fill="#0f172a">&#127760; URL Detection Engine</text>
        <text x="12" y="27" font-size="7" fill="#64748b">17 lexical rules &bull; Domain age &bull; Redirect tracking</text>

        <!-- Engine 2: Attachment -->
        <rect x="235" y="0" width="220" height="40" rx="5" fill="#ffffff" stroke="#cbd5e1" stroke-width="1.2"/>
        <rect x="235" y="0" width="4" height="40" rx="2" fill="#d97706"/>
        <text x="247" y="15" font-size="8.5" font-weight="700" fill="#0f172a">&#128193; Attachment Behavior Engine</text>
        <text x="247" y="27" font-size="7" fill="#64748b">Magic byte checks &bull; Macro analysis &bull; Zero execution</text>
      </g>

      <!-- Row 2 -->
      <g transform="translate(32, 330)">
        <!-- Engine 3: NLP -->
        <rect x="0" y="0" width="220" height="40" rx="5" fill="#ffffff" stroke="#cbd5e1" stroke-width="1.2"/>
        <rect x="0" y="0" width="4" height="40" rx="2" fill="#059669"/>
        <text x="12" y="15" font-size="8.5" font-weight="700" fill="#0f172a">&#128172; NLP Message Engine</text>
        <text x="12" y="27" font-size="7" fill="#64748b">Urgency &amp; fear cues &bull; Dual-layer OTP 2FA shield</text>

        <!-- Engine 4: Visual/OCR -->
        <rect x="235" y="0" width="220" height="40" rx="5" fill="#ffffff" stroke="#cbd5e1" stroke-width="1.2"/>
        <rect x="235" y="0" width="4" height="40" rx="2" fill="#7c3aed"/>
        <text x="247" y="15" font-size="8.5" font-weight="700" fill="#0f172a">&#128065;&#65039; Visual / QR / OCR Engine</text>
        <text x="247" y="27" font-size="7" fill="#64748b">OpenCV QR decoding &bull; EasyOCR text extraction</text>
      </g>

      <!-- Row 3 -->
      <g transform="translate(32, 376)">
        <!-- Engine 5: Sender -->
        <rect x="0" y="0" width="220" height="40" rx="5" fill="#ffffff" stroke="#cbd5e1" stroke-width="1.2"/>
        <rect x="0" y="0" width="4" height="40" rx="2" fill="#0891b2"/>
        <text x="12" y="15" font-size="8.5" font-weight="700" fill="#0f172a">&#128100; Sender Behavior Engine</text>
        <text x="12" y="27" font-size="7" fill="#64748b">Historical profiling &bull; Burst activity &bull; Anomaly score</text>

        <!-- Engine 6: Malware -->
        <rect x="235" y="0" width="220" height="40" rx="5" fill="#ffffff" stroke="#cbd5e1" stroke-width="1.2"/>
        <rect x="235" y="0" width="4" height="40" rx="2" fill="#dc2626"/>
        <text x="247" y="15" font-size="8.5" font-weight="700" fill="#0f172a">&#128737;&#65039; Malware Detection Engine</text>
        <text x="247" y="27" font-size="7" fill="#64748b">SHA-256 cloud hash lookup &bull; Fault-isolated status</text>
      </g>

      <!-- Row 4 -->
      <g transform="translate(32, 422)">
        <!-- Engine 7: Header -->
        <rect x="0" y="0" width="220" height="42" rx="5" fill="#ffffff" stroke="#cbd5e1" stroke-width="1.2"/>
        <rect x="0" y="0" width="4" height="42" rx="2" fill="#4f46e5"/>
        <text x="12" y="15" font-size="8.5" font-weight="700" fill="#0f172a">&#128236; Email Header Engine</text>
        <text x="12" y="27" font-size="7" fill="#64748b">Reply-To mismatch &bull; SPF/DKIM flags &bull; Time skew</text>

        <!-- Note Banner inside Box 4 -->
        <rect x="235" y="0" width="220" height="42" rx="5" fill="#f1f5f9" stroke="#94a3b8" stroke-width="1" stroke-dasharray="3,2"/>
        <text x="345" y="16" font-size="7.5" font-weight="700" fill="#334155" text-anchor="middle">&#9889; Concurrent Execution</text>
        <text x="345" y="28" font-size="7" fill="#64748b" text-anchor="middle">asyncio.gather() runs all engines in parallel</text>
      </g>

      <!-- ================================================================ -->
      <!-- SIDE BOX: EXTERNAL SECURITY SERVICES -->
      <!-- ================================================================ -->
      <rect x="520" y="250" width="145" height="230" rx="8" fill="#faf5ff" stroke="#7c3aed" stroke-width="1.8"/>
      <rect x="520" y="250" width="145" height="26" rx="8" fill="#7c3aed"/>
      <rect x="520" y="268" width="145" height="8" fill="#7c3aed"/>
      <text x="592.5" y="267" font-size="9" font-weight="800" fill="#ffffff" text-anchor="middle">EXTERNAL SERVICES</text>
      <text x="592.5" y="290" font-size="7.5" font-weight="600" fill="#6b21a8" text-anchor="middle">(Cloud Intelligence)</text>

      <g transform="translate(528, 305)">
        <rect x="0" y="0" width="129" height="45" rx="5" fill="#ffffff" stroke="#d8b4fe" stroke-width="1"/>
        <text x="64.5" y="16" font-size="7.5" font-weight="700" fill="#581c87" text-anchor="middle">Google Safe Browsing</text>
        <text x="64.5" y="28" font-size="6.5" fill="#64748b" text-anchor="middle">Known malicious link check</text>
        <text x="64.5" y="38" font-size="6.5" fill="#7c3aed" text-anchor="middle">Enforces 90.0 risk floor</text>

        <rect x="0" y="52" width="129" height="45" rx="5" fill="#ffffff" stroke="#d8b4fe" stroke-width="1"/>
        <text x="64.5" y="68" font-size="7.5" font-weight="700" fill="#581c87" text-anchor="middle">VirusTotal API v3</text>
        <text x="64.5" y="80" font-size="6.5" fill="#64748b" text-anchor="middle">Multi-scanner binary lookup</text>
        <text x="64.5" y="90" font-size="6.5" fill="#7c3aed" text-anchor="middle">SHA-256 hash query only</text>

        <rect x="0" y="104" width="129" height="45" rx="5" fill="#ffffff" stroke="#d8b4fe" stroke-width="1"/>
        <text x="64.5" y="120" font-size="7.5" font-weight="700" fill="#581c87" text-anchor="middle">AsyncWHOIS / RDAP</text>
        <text x="64.5" y="132" font-size="6.5" fill="#64748b" text-anchor="middle">Domain age &amp; registration</text>
        <text x="64.5" y="142" font-size="6.5" fill="#7c3aed" text-anchor="middle">2-second timeout bound</text>
      </g>

      <!-- Connecting Arrow: Detection to External -->
      <line x1="500" y1="365" x2="520" y2="365" stroke="#7c3aed" stroke-width="2" marker-end="url(#arrExt)"/>

      <!-- Arrow: 4 -> 5 -->
      <line x1="260" y1="480" x2="260" y2="498" stroke="#2563eb" stroke-width="2" marker-end="url(#arr)"/>

      <!-- ================================================================ -->
      <!-- 5. RISK ANALYSIS & FUSION -->
      <!-- ================================================================ -->
      <rect x="20" y="498" width="480" height="64" rx="8" fill="#eff6ff" stroke="#2563eb" stroke-width="1.8"/>
      <rect x="20" y="498" width="480" height="22" rx="8" fill="#dbeafe"/>
      <rect x="20" y="513" width="480" height="7" fill="#dbeafe"/>
      <text x="260" y="513" font-size="10" font-weight="800" fill="#1e3a8a" text-anchor="middle">5. RISK ANALYSIS &amp; FUSION</text>
      
      <g transform="translate(30, 528)">
        <rect x="0" y="0" width="220" height="25" rx="4" fill="#ffffff" stroke="#93c5fd" stroke-width="1"/>
        <text x="110" y="16" font-size="8" font-weight="700" fill="#1e40af" text-anchor="middle">Confidence-Weighted Risk Fusion</text>

        <rect x="235" y="0" width="225" height="25" rx="4" fill="#ffffff" stroke="#93c5fd" stroke-width="1"/>
        <text x="347" y="16" font-size="8" font-weight="700" fill="#1e40af" text-anchor="middle">Dynamic Multi-Tier Security Classification</text>
      </g>

      <!-- Arrow: 5 -> 6 -->
      <line x1="260" y1="562" x2="260" y2="580" stroke="#2563eb" stroke-width="2" marker-end="url(#arr)"/>

      <!-- ================================================================ -->
      <!-- 6. EXPLAINABILITY ENGINE -->
      <!-- ================================================================ -->
      <rect x="20" y="580" width="480" height="64" rx="8" fill="#fdf2f8" stroke="#db2777" stroke-width="1.8"/>
      <rect x="20" y="580" width="480" height="22" rx="8" fill="#fce7f3"/>
      <rect x="20" y="595" width="480" height="7" fill="#fce7f3"/>
      <text x="260" y="595" font-size="10" font-weight="800" fill="#9d174d" text-anchor="middle">6. EXPLAINABILITY ENGINE</text>
      
      <g transform="translate(30, 610)">
        <rect x="0" y="0" width="140" height="26" rx="4" fill="#ffffff" stroke="#f472b6" stroke-width="1"/>
        <text x="70" y="12" font-size="7.5" font-weight="700" fill="#831843" text-anchor="middle">Transparent Reasons</text>
        <text x="70" y="21" font-size="6.5" fill="#64748b" text-anchor="middle">Plain English explanations</text>

        <rect x="150" y="0" width="155" height="26" rx="4" fill="#ffffff" stroke="#f472b6" stroke-width="1"/>
        <text x="227.5" y="12" font-size="7.5" font-weight="700" fill="#831843" text-anchor="middle">Unified Risk Score</text>
        <text x="227.5" y="21" font-size="6.5" fill="#64748b" text-anchor="middle">Normalized 0 to 100 metric</text>

        <rect x="315" y="0" width="145" height="26" rx="4" fill="#ffffff" stroke="#f472b6" stroke-width="1"/>
        <text x="387.5" y="12" font-size="7.5" font-weight="700" fill="#831843" text-anchor="middle">Recommended Action</text>
        <text x="387.5" y="21" font-size="6.5" fill="#64748b" text-anchor="middle">Concrete advice for user</text>
      </g>

      <!-- Arrow: 6 -> 7 -->
      <line x1="260" y1="644" x2="260" y2="662" stroke="#2563eb" stroke-width="2" marker-end="url(#arr)"/>

      <!-- ================================================================ -->
      <!-- 7. FINAL RESULT (5-TIER VERDICT) -->
      <!-- ================================================================ -->
      <rect x="20" y="662" width="645" height="74" rx="8" fill="#f8fafc" stroke="#0f172a" stroke-width="1.8"/>
      <rect x="20" y="662" width="645" height="22" rx="8" fill="#e2e8f0"/>
      <rect x="20" y="677" width="645" height="7" fill="#e2e8f0"/>
      <text x="342.5" y="676" font-size="10" font-weight="800" fill="#0f172a" text-anchor="middle">7. FINAL RESULT &bull; DYNAMIC THREAT CLASSIFICATION</text>

      <g transform="translate(30, 692)">
        <!-- Safe -->
        <rect x="0" y="0" width="115" height="36" rx="5" fill="#ecfdf5" stroke="#10b981" stroke-width="1.5"/>
        <text x="57.5" y="15" font-size="9" font-weight="800" fill="#047857" text-anchor="middle">&#10004; SAFE</text>
        <text x="57.5" y="28" font-size="7" fill="#065f46" text-anchor="middle">Score &lt; 20</text>

        <!-- Suspicious -->
        <rect x="127" y="0" width="115" height="36" rx="5" fill="#fefce8" stroke="#eab308" stroke-width="1.5"/>
        <text x="184.5" y="15" font-size="9" font-weight="800" fill="#a16207" text-anchor="middle">&#9888; SUSPICIOUS</text>
        <text x="184.5" y="28" font-size="7" fill="#854d0e" text-anchor="middle">Score 20 &ndash; 44</text>

        <!-- Deceptive -->
        <rect x="254" y="0" width="115" height="36" rx="5" fill="#fff7ed" stroke="#f97316" stroke-width="1.5"/>
        <text x="311.5" y="15" font-size="9" font-weight="800" fill="#c2410c" text-anchor="middle">&#9888; DECEPTIVE</text>
        <text x="311.5" y="28" font-size="7" fill="#9a3412" text-anchor="middle">Score 45 &ndash; 69</text>

        <!-- Phishing -->
        <rect x="381" y="0" width="115" height="36" rx="5" fill="#fef2f2" stroke="#ef4444" stroke-width="1.5"/>
        <text x="438.5" y="15" font-size="9" font-weight="800" fill="#b91c1c" text-anchor="middle">&#9760; PHISHING</text>
        <text x="438.5" y="28" font-size="7" fill="#991b1b" text-anchor="middle">Score 70 &ndash; 89</text>

        <!-- Malware -->
        <rect x="508" y="0" width="117" height="36" rx="5" fill="#faf5ff" stroke="#a855f7" stroke-width="1.5"/>
        <text x="566.5" y="15" font-size="9" font-weight="800" fill="#7e22ce" text-anchor="middle">&#9889; MALWARE</text>
        <text x="566.5" y="28" font-size="7" fill="#6b21a8" text-anchor="middle">Score &ge; 90 / Hash Match</text>
      </g>

      <!-- Arrow: 7 -> 8 -->
      <line x1="342.5" y1="736" x2="342.5" y2="754" stroke="#2563eb" stroke-width="2" marker-end="url(#arr)"/>

      <!-- ================================================================ -->
      <!-- 8. USER FEATURES & CLIENT ACTIONS -->
      <!-- ================================================================ -->
      <rect x="20" y="754" width="645" height="74" rx="8" fill="#f8fafc" stroke="#0f172a" stroke-width="1.8"/>
      <rect x="20" y="754" width="645" height="22" rx="8" fill="#0f172a"/>
      <rect x="20" y="769" width="645" height="7" fill="#0f172a"/>
      <text x="342.5" y="768" font-size="10" font-weight="800" fill="#ffffff" text-anchor="middle">8. USER FEATURES &amp; CLIENT-SIDE DEFENSE ACTIONS</text>

      <g transform="translate(30, 784)">
        <rect x="0" y="0" width="145" height="36" rx="5" fill="#ffffff" stroke="#cbd5e1" stroke-width="1"/>
        <text x="72.5" y="14" font-size="8.5" font-weight="700" fill="#0f172a" text-anchor="middle">&#128220; Scan History</text>
        <text x="72.5" y="27" font-size="7" fill="#64748b" text-anchor="middle">Local encrypted SQLite records</text>

        <rect x="157" y="0" width="145" height="36" rx="5" fill="#ffffff" stroke="#cbd5e1" stroke-width="1"/>
        <text x="229.5" y="14" font-size="8.5" font-weight="700" fill="#0f172a" text-anchor="middle">&#128077; User Feedback</text>
        <text x="229.5" y="27" font-size="7" fill="#64748b" text-anchor="middle">Thumbs up / down evaluation</text>

        <rect x="314" y="0" width="150" height="36" rx="5" fill="#ffffff" stroke="#cbd5e1" stroke-width="1"/>
        <text x="389" y="14" font-size="8.5" font-weight="700" fill="#0f172a" text-anchor="middle">&#128276; Threat Alerts</text>
        <text x="389" y="27" font-size="7" fill="#64748b" text-anchor="middle">High-priority push notifications</text>

        <rect x="476" y="0" width="149" height="36" rx="5" fill="#ffffff" stroke="#cbd5e1" stroke-width="1"/>
        <text x="550.5" y="14" font-size="8.5" font-weight="700" fill="#0f172a" text-anchor="middle">&#128737;&#65039; Background Shield</text>
        <text x="550.5" y="27" font-size="7" fill="#64748b" text-anchor="middle">Periodic inbox threat scanning</text>
      </g>

      <!-- Bottom Status Banner inside SVG -->
      <g transform="translate(20, 840)">
        <rect x="0" y="0" width="645" height="28" rx="5" fill="#eff6ff" stroke="#bfdbfe" stroke-width="1"/>
        <text x="322.5" y="17" font-size="8" font-weight="600" fill="#1e40af" text-anchor="middle">
          &#10004; Verified Implementation Flow: Input &rarr; Android &rarr; FastAPI &rarr; 7 Engines &rarr; Fusion &rarr; Classification &rarr; Explainability &rarr; Result &rarr; Actions
        </text>
      </g>
    </svg>
  </div>

  <div class="doc-footer">
    <div>SecureShield-AI &bull; Architecture Specification Document</div>
    <div>Page 1 of 2</div>
  </div>
</div>

<!-- ========================================================================= -->
<!-- PAGE 2: COMPONENT EXPLANATIONS, TECH STACK, SECURITY & HOW IT WORKS -->
<!-- ========================================================================= -->
<div class="page">
  <div class="doc-header">
    <div class="header-left">
      <h1>SecureShield-AI &mdash; Technical Overview &amp; Specifications</h1>
      <div class="subtitle">Component Architecture, Technology Stack, Security Boundaries &amp; Workflow</div>
    </div>
    <div class="header-right">
      <strong>College Project Evaluation &bull; System Specification</strong><br>
      Status: Verified Against Implementation &bull; Page 2 of 2
    </div>
  </div>

  <!-- 1. CORE COMPONENT EXPLANATION -->
  <div class="section-title">
    <span class="badge-num">1</span>
    <span>Core Architecture Components</span>
  </div>
  <div class="grid-2col">
    <div class="card">
      <div class="card-title">&#128241; Android Client Application</div>
      <div class="card-desc">
        Native mobile app providing interactive threat scanning, Android <code>ACTION_SEND</code> Share Menu integration to inspect text and files from any third-party app, OAuth 2.0 Gmail inbox synchronization, and periodic background threat monitoring via <code>WorkManager</code>.
      </div>
    </div>
    <div class="card">
      <div class="card-title">&#9881;&#65039; FastAPI Backend &amp; Preprocessing</div>
      <div class="card-desc">
        High-performance asynchronous REST microservice running FastAPI. Sanitizes all incoming inputs, bounds payloads to 10 MB, normalizes Unicode (NFKC), and safely resolves web links using DNS pre-resolution and IP-pinning to prevent SSRF attacks.
      </div>
    </div>
    <div class="card">
      <div class="card-title">&#128737;&#65039; Seven Parallel Detection Engines</div>
      <div class="card-desc">
        Modular intelligence engines analyzing threats concurrently: <strong>URL</strong> (17 lexical rules), <strong>NLP</strong> (urgency/fear cues with 2FA shield), <strong>Sender Behavior</strong> (bursts/domain drift), <strong>Header</strong> (Reply-To mismatch), <strong>Attachment</strong> (magic bytes, macros), <strong>Visual</strong> (QR/OCR), and <strong>Malware</strong> (hash lookup).
      </div>
    </div>
    <div class="card">
      <div class="card-title">&#128202; Fusion, Explainability &amp; Results</div>
      <div class="card-desc">
        Weighed Bayesian risk fusion calculates a composite risk score (0&ndash;100), mapped into 5 security tiers (Safe, Suspicious, Deceptive, Phishing, Malware). The explainability engine translates detection flags into plain-English reasons and clear user precautions.
      </div>
    </div>
  </div>

  <!-- 2. TECHNOLOGY STACK -->
  <div class="section-title">
    <span class="badge-num">2</span>
    <span>Technology Stack</span>
  </div>
  <div class="grid-3col">
    <div class="tech-category">
      <div class="tech-cat-title">Android Client</div>
      <div class="tech-items">
        &bull; <strong>Kotlin 2.2:</strong> Modern native client<br>
        &bull; <strong>Retrofit 2 &amp; OkHttp 4:</strong> REST API<br>
        &bull; <strong>WorkManager:</strong> 15m background scans<br>
        &bull; <strong>SQLite:</strong> Sanitized history store<br>
        &bull; <strong>Google Sign-In:</strong> Gmail OAuth
      </div>
    </div>
    <div class="tech-category">
      <div class="tech-cat-title">Backend &amp; Detection</div>
      <div class="tech-items">
        &bull; <strong>Python 3.14 &amp; FastAPI:</strong> Async API<br>
        &bull; <strong>Pydantic v2:</strong> Strict validation<br>
        &bull; <strong>OpenCV:</strong> QR code detector<br>
        &bull; <strong>EasyOCR &amp; PyTorch:</strong> Text OCR<br>
        &bull; <strong>Regex:</strong> NLP &amp; heuristic patterns
      </div>
    </div>
    <div class="tech-category">
      <div class="tech-cat-title">Storage &amp; Cloud Services</div>
      <div class="tech-items">
        &bull; <strong>SQLite:</strong> Client history &amp; sender baselines<br>
        &bull; <strong>Google Safe Browsing:</strong> URL feed<br>
        &bull; <strong>VirusTotal v3:</strong> Cloud hash analysis<br>
        &bull; <strong>AsyncWHOIS:</strong> Domain registration<br>
        &bull; <strong>TTL Cache:</strong> API quota preservation
      </div>
    </div>
  </div>

  <!-- 3. HOW SECURESHIELD-AI WORKS -->
  <div class="section-title">
    <span class="badge-num">3</span>
    <span>How SecureShield-AI Works (End-to-End Threat Scan Flow)</span>
  </div>
  <div class="flow-container">
    <div class="flow-step">
      <div class="step-num">Step 1</div>
      <div class="step-title">Input &amp; Clean</div>
      <div class="step-desc">User shares link, text, image, file, or email. Backend strips control chars and validates size bounds.</div>
    </div>
    <div class="flow-arrow">&rarr;</div>
    <div class="flow-step">
      <div class="step-num">Step 2</div>
      <div class="step-title">Parallel Scan</div>
      <div class="step-desc">7 detection engines analyze the input simultaneously for links, words, headers, and code macros.</div>
    </div>
    <div class="flow-arrow">&rarr;</div>
    <div class="flow-step">
      <div class="step-num">Step 3</div>
      <div class="step-title">Risk Fusion</div>
      <div class="step-desc">Combines engine confidence and empirical reliability weights into one normalized score (0&ndash;100).</div>
    </div>
    <div class="flow-arrow">&rarr;</div>
    <div class="flow-step">
      <div class="step-num">Step 4</div>
      <div class="step-title">Classification</div>
      <div class="step-desc">Evaluates score against policy tiers and translates machine flags into plain-English reasons.</div>
    </div>
    <div class="flow-arrow">&rarr;</div>
    <div class="flow-step">
      <div class="step-num">Step 5</div>
      <div class="step-title">User Verdict</div>
      <div class="step-desc">Displays verdict and action advice; fires push notification if phishing or malware is detected.</div>
    </div>
  </div>

  <!-- 4. SECURITY & PRIVACY HIGHLIGHTS -->
  <div class="section-title">
    <span class="badge-num">4</span>
    <span>Security &amp; Privacy Summary</span>
  </div>
  <div class="grid-2col">
    <div class="sec-card">
      <div class="sec-title">&#128272; Privacy-First Architecture</div>
      <div class="sec-desc">
        <strong>Zero Server Storage:</strong> User email bodies, submitted messages, and uploaded files exist only in RAM during the active scan and are NEVER written to a database or stored on disk.<br>
        <strong>Local Secret Redaction:</strong> The Android history database automatically redacts passwords, OTPs, and authentication tokens before persisting records on the device.
      </div>
    </div>
    <div class="sec-card">
      <div class="sec-title">&#128737;&#65039; Safe Inspection &amp; Isolated Cloud Calls</div>
      <div class="sec-desc">
        <strong>Zero Code Execution:</strong> All files and attachments are inspected strictly through static analysis (magic bytes, macro detection, RTLO evasion). Files are never executed.<br>
        <strong>Safe External Queries:</strong> Only cryptographic SHA-256 file hashes and public URLs are queried against external APIs. Private user files are never sent to third parties.
      </div>
    </div>
  </div>

  <div class="doc-footer">
    <div>SecureShield-AI &bull; Architecture Specification Document</div>
    <div>Page 2 of 2</div>
  </div>
</div>

</body>
</html>
"""

    with open(html_filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    print(f"Temporary HTML written to {html_filename}")
    
    edge_path = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
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
    print(f"Edge return code: {res.returncode}")
    
    if os.path.exists(abs_pdf):
        doc = fitz.open(abs_pdf)
        page_count = len(doc)
        print(f"SUCCESS: {pdf_filename} created successfully!")
        print(f"Total Pages in PDF: {page_count}")
        doc.close()
    else:
        print("ERROR: PDF was not generated.")

if __name__ == "__main__":
    build_pdf()
