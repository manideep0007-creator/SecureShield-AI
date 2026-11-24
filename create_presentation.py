import os
import sys
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE

def create_deck():
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    # Colors
    BG_DARK = RGBColor(10, 17, 40)        # #0A1128
    BG_CARD_DARK = RGBColor(21, 32, 64)   # #152040
    BG_LIGHT = RGBColor(248, 250, 252)    # #F8FAFC
    CARD_LIGHT = RGBColor(255, 255, 255)  # #FFFFFF
    BORDER_LIGHT = RGBColor(226, 232, 240)# #E2E8F0
    PRIMARY_BLUE = RGBColor(14, 116, 144) # #0E7490
    ACCENT_CYAN = RGBColor(14, 165, 233)  # #0EA5E9
    ACCENT_BLUE = RGBColor(37, 99, 235)   # #2563EB
    TEXT_DARK = RGBColor(15, 23, 42)      # #0F172A
    TEXT_MUTED = RGBColor(100, 116, 139)  # #64748B
    TEXT_LIGHT = RGBColor(241, 245, 249)  # #F1F5F9
    TEXT_LIGHT_MUTED = RGBColor(148, 163, 184) # #94A3B8
    GREEN_ALERT = RGBColor(16, 185, 129)  # #10B981
    RED_ALERT = RGBColor(239, 68, 68)     # #EF4444
    AMBER_ALERT = RGBColor(245, 158, 11)  # #F59E0B

    LOGO_PATH = r"D:\Secure Shield AI\android\app\src\main\res\drawable\img_secureshield_logo.png"
    ARCH_IMG_PATH = r"D:\Secure Shield AI\documentation\images\system_architecture_diagram.jpg"

    def set_slide_background(slide, color):
        bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0), Inches(0), Inches(13.333), Inches(7.5))
        bg.fill.solid()
        bg.fill.fore_color.rgb = color
        bg.line.fill.background()
        return bg

    def add_header(slide, title_text, category_text, dark_mode=False):
        # Category / Kicker
        tb_cat = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(11.7), Inches(0.35))
        p_cat = tb_cat.text_frame.paragraphs[0]
        p_cat.text = category_text.upper()
        p_cat.font.name = "Calibri"
        p_cat.font.size = Pt(11)
        p_cat.font.bold = True
        p_cat.font.color.rgb = ACCENT_CYAN if dark_mode else ACCENT_BLUE

        # Title
        tb_title = slide.shapes.add_textbox(Inches(0.8), Inches(0.72), Inches(11.7), Inches(0.65))
        p_title = tb_title.text_frame.paragraphs[0]
        p_title.text = title_text
        p_title.font.name = "Calibri"
        p_title.font.size = Pt(24)
        p_title.font.bold = True
        p_title.font.color.rgb = TEXT_LIGHT if dark_mode else TEXT_DARK

    def add_card(slide, left, top, width, height, bg_color=CARD_LIGHT, border_color=BORDER_LIGHT):
        card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
        card.fill.solid()
        card.fill.fore_color.rgb = bg_color
        if border_color:
            card.line.color.rgb = border_color
            card.line.width = Pt(1.2)
        else:
            card.line.fill.background()
        return card

    # ==========================================================
    # SLIDE 1: Title Slide (Dark Theme)
    # ==========================================================
    s1 = prs.slides.add_slide(blank_layout)
    set_slide_background(s1, BG_DARK)

    # Accent decorative bar
    bar = s1.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.8), Inches(1.2), Inches(0.12), Inches(4.5))
    bar.fill.solid()
    bar.fill.fore_color.rgb = ACCENT_CYAN
    bar.line.fill.background()

    # Logo if available
    if os.path.exists(LOGO_PATH):
        s1.shapes.add_picture(LOGO_PATH, Inches(10.5), Inches(1.2), width=Inches(1.8))

    # Badge
    badge = add_card(s1, Inches(1.2), Inches(1.2), Inches(3.6), Inches(0.4), bg_color=BG_CARD_DARK, border_color=ACCENT_CYAN)
    p_b = badge.text_frame.paragraphs[0]
    p_b.text = "AI-POWERED CYBERSECURITY PLATFORM"
    p_b.font.name = "Calibri"
    p_b.font.size = Pt(11)
    p_b.font.bold = True
    p_b.font.color.rgb = ACCENT_CYAN
    p_b.alignment = PP_ALIGN.CENTER

    # Main Title
    tb_t = s1.shapes.add_textbox(Inches(1.15), Inches(1.8), Inches(9.0), Inches(1.8))
    tf_t = tb_t.text_frame
    tf_t.word_wrap = True
    p1 = tf_t.paragraphs[0]
    p1.text = "SecureShield AI"
    p1.font.name = "Calibri"
    p1.font.size = Pt(44)
    p1.font.bold = True
    p1.font.color.rgb = TEXT_LIGHT

    p2 = tf_t.add_paragraph()
    p2.text = "A Multimodal Phishing, Social Engineering & Malware Detection System"
    p2.font.name = "Calibri"
    p2.font.size = Pt(20)
    p2.font.bold = False
    p2.font.color.rgb = TEXT_LIGHT_MUTED
    p2.space_before = Pt(8)

    # Subtitle / Tagline
    tb_tag = s1.shapes.add_textbox(Inches(1.15), Inches(3.6), Inches(8.8), Inches(0.8))
    p_tag = tb_tag.text_frame.paragraphs[0]
    p_tag.text = "An end-to-end security defense integrating a high-performance Kotlin Android client with a concurrent multi-engine FastAPI threat intelligence backend."
    p_tag.font.name = "Calibri"
    p_tag.font.size = Pt(13)
    p_tag.font.color.rgb = RGBColor(186, 205, 230)

    # Team Members Card
    team_card = add_card(s1, Inches(1.2), Inches(4.7), Inches(10.9), Inches(1.8), bg_color=BG_CARD_DARK, border_color=RGBColor(38, 55, 95))
    tf_team = team_card.text_frame
    tf_team.word_wrap = True
    p_th = tf_team.paragraphs[0]
    p_th.text = "PROJECT TEAM MEMBERS"
    p_th.font.name = "Calibri"
    p_th.font.size = Pt(12)
    p_th.font.bold = True
    p_th.font.color.rgb = ACCENT_CYAN
    p_th.space_before = Pt(4)

    # Members columns
    team_members = [
        "N JAYANTH (5P2)",
        "N MANIDEEP (5O2)",
        "M HEMALATHA (5L2)",
        "P ANILKUMAR (5Q3)",
        "M RAMCHARAN (5L9)"
    ]
    p_tm = tf_team.add_paragraph()
    p_tm.text = "   •   ".join(team_members)
    p_tm.font.name = "Calibri"
    p_tm.font.size = Pt(13)
    p_tm.font.bold = True
    p_tm.font.color.rgb = TEXT_LIGHT
    p_tm.space_before = Pt(10)

    p_dep = tf_team.add_paragraph()
    p_dep.text = "Department of Computer Science & Engineering | Major Project Implementation Defense"
    p_dep.font.name = "Calibri"
    p_dep.font.size = Pt(11)
    p_dep.font.color.rgb = TEXT_LIGHT_MUTED
    p_dep.space_before = Pt(8)

    # ==========================================================
    # SLIDE 2: Executive Summary & Problem Landscape (Light Theme)
    # ==========================================================
    s2 = prs.slides.add_slide(blank_layout)
    set_slide_background(s2, BG_LIGHT)
    add_header(s2, "The Modern Cybersecurity Threat Landscape", "EXECUTIVE SUMMARY & MOTIVATION")

    cards_data_s2 = [
        ("Multi-Channel Attack Vectors",
         "Threat actors no longer confine phishing to standard email. Malicious payloads and lures exploit WhatsApp, Telegram, SMS (smishing), QR codes (quishing), and social media DMs.",
         "High Risk Vector"),
        ("Evasion & Zero-Day Phishing",
         "Static blacklists and domain reputation feeds fail against short-lived fast-flux domains, randomized URL shorteners, and zero-day hosting infrastructure created minutes before campaigns.",
         "Blind Spot in Legacy Tools"),
        ("Visual & Identity Impersonation",
         "Adversaries build pixel-perfect clones of legitimate corporate and banking portals using homograph domains and hosted CDNs, completely bypassing keyword and regex filters.",
         "Deceptive Experience"),
        ("Siloed & Opaque Protections",
         "Operating systems and mobile AV provide isolated, binary verdicts without explainable forensic rationales, leading to warning fatigue and inadvertent user compromise.",
         "Critical Gap")
    ]

    for idx, (title, desc, badge_txt) in enumerate(cards_data_s2):
        col = idx % 2
        row = idx // 2
        l = Inches(0.8 + col * 5.95)
        t = Inches(1.6 + row * 2.65)
        w = Inches(5.75)
        h = Inches(2.45)
        c = add_card(s2, l, t, w, h)
        tf = c.text_frame
        tf.word_wrap = True

        p_b = tf.paragraphs[0]
        p_b.text = badge_txt.upper()
        p_b.font.name = "Calibri"
        p_b.font.size = Pt(10)
        p_b.font.bold = True
        p_b.font.color.rgb = ACCENT_BLUE

        p_t = tf.add_paragraph()
        p_t.text = title
        p_t.font.name = "Calibri"
        p_t.font.size = Pt(16)
        p_t.font.bold = True
        p_t.font.color.rgb = TEXT_DARK
        p_t.space_before = Pt(4)

        p_d = tf.add_paragraph()
        p_d.text = desc
        p_d.font.name = "Calibri"
        p_d.font.size = Pt(12)
        p_d.font.color.rgb = TEXT_MUTED
        p_d.space_before = Pt(8)

    # Bottom summary callout
    bot_card = add_card(s2, Inches(0.8), Inches(6.8), Inches(11.7), Inches(0.5), bg_color=RGBColor(238, 242, 255), border_color=ACCENT_BLUE)
    p_bc = bot_card.text_frame.paragraphs[0]
    p_bc.text = "Core Takeaway: Protection cannot rely on a single defensive gate; cybersecurity demands a unified, multimodal, explainable framework."
    p_bc.font.name = "Calibri"
    p_bc.font.size = Pt(11)
    p_bc.font.bold = True
    p_bc.font.color.rgb = ACCENT_BLUE
    p_bc.alignment = PP_ALIGN.CENTER

    # ==========================================================
    # SLIDE 3: Existing Protections vs Critical Vulnerabilities
    # ==========================================================
    s3 = prs.slides.add_slide(blank_layout)
    set_slide_background(s3, BG_LIGHT)
    add_header(s3, "Limitations of Current Defensive Countermeasures", "LITERATURE SURVEY & DEFENSE GAPS")

    headers = ["Protection Type", "Typical Implementation", "Key Strengths", "Critical Gaps & Failure Modes"]
    rows = [
        ("Browser & OS Level", "Google Safe Browsing, Windows Defender SmartScreen", "Fast lookup against large-scale blacklists and known malicious hashes.", "Fails against newly registered zero-hour URLs, quishing, and rendered in-app webviews."),
        ("Mobile Antivirus (AV)", "Traditional Play Store security scanners, Knox/Play Protect", "Scans installed APK package signatures and device-level permissions.", "Completely blind to social engineering text, real-time chat links, and QR payloads inside active apps."),
        ("Platform-Native Email", "Gmail built-in filters, Outlook Safe Links, DMARC parsers", "Effective header-based spam/phishing classification for inbound mail.", "Platform-siloed; offers zero protection when threats transit via WhatsApp, Telegram, or SMS."),
        ("Single-Signal Heuristics", "Keyword regexes, lexical URL tokenizers, static Yara rules", "Extremely lightweight and fast execution on commodity hardware.", "Easily evaded via URL obfuscation, homograph punycode, obfuscated PDFs, and adversarial text rephrasing.")
    ]

    t_top = Inches(1.6)
    t_left = Inches(0.8)
    t_width = Inches(11.7)
    t_height = Inches(5.1)

    table_shape = s3.shapes.add_table(5, 4, t_left, t_top, t_width, t_height)
    table = table_shape.table
    table.columns[0].width = Inches(2.2)
    table.columns[1].width = Inches(2.6)
    table.columns[2].width = Inches(3.1)
    table.columns[3].width = Inches(3.8)

    # Style Header
    for c_idx, title in enumerate(headers):
        cell = table.cell(0, c_idx)
        cell.fill.solid()
        cell.fill.fore_color.rgb = RGBColor(30, 41, 59)
        p = cell.text_frame.paragraphs[0]
        p.text = title
        p.font.name = "Calibri"
        p.font.size = Pt(12)
        p.font.bold = True
        p.font.color.rgb = RGBColor(255, 255, 255)

    # Style Data Rows
    for r_idx, row_data in enumerate(rows):
        for c_idx, val in enumerate(row_data):
            cell = table.cell(r_idx + 1, c_idx)
            cell.fill.solid()
            cell.fill.fore_color.rgb = RGBColor(255, 255, 255) if r_idx % 2 == 0 else RGBColor(241, 245, 249)
            p = cell.text_frame.paragraphs[0]
            p.text = val
            p.font.name = "Calibri"
            p.font.size = Pt(11)
            p.font.color.rgb = TEXT_DARK if c_idx < 3 else RED_ALERT if "Completely blind" in val or "Fails" in val else TEXT_DARK
            if c_idx == 0:
                p.font.bold = True

    # ==========================================================
    # SLIDE 4: SecureShield AI Solution & Proposed Architecture
    # ==========================================================
    s4 = prs.slides.add_slide(blank_layout)
    set_slide_background(s4, BG_LIGHT)
    add_header(s4, "SecureShield AI: Unified System Architecture", "END-TO-END TECHNICAL ARCHITECTURE")

    # Left: Architecture Diagram if exists, or diagram card
    has_img = os.path.exists(ARCH_IMG_PATH)
    left_w = Inches(6.0) if has_img else Inches(5.6)
    
    if has_img:
        s4.shapes.add_picture(ARCH_IMG_PATH, Inches(0.8), Inches(1.5), width=left_w)
    else:
        c_diag = add_card(s4, Inches(0.8), Inches(1.5), left_w, Inches(5.3))
        p = c_diag.text_frame.paragraphs[0]
        p.text = "High-Level Architecture Pipeline"
        p.font.bold = True

    # Right: Pipeline Breakdown
    right_x = Inches(7.1)
    right_w = Inches(5.4)

    steps = [
        ("1. Multi-Channel Ingestion Layer",
         "Captures threats via Native Android Guardian Accessibility Service (on-screen), Global Share Target (ShareActivity), and Background Gmail WorkManager."),
        ("2. Normalization & Preprocessing",
         "Sanitizes input, performs Unicode NFKC normalization, resolves obfuscated/shortened redirects, and enforces strict memory payload boundaries."),
        ("3. 7 Concurrent Detection Engines",
         "Executes asynchronous parallel feature extraction across URLs, Binaries, NLP Phishing Semantics, Sender Baseline, Headers, Attachments, and Visual Brand similarity."),
        ("4. Confidence-Weighted Risk Fusion",
         "Combines independent engine risk metrics into a mathematical composite score (0–100) factoring engine reliability and signal confidence."),
        ("5. Dynamic Classification & Explainability",
         "Applies configurable security profiles (Default, Strict, Enterprise) and generates human-readable forensic evidence with remediation steps.")
    ]

    for idx, (title, desc) in enumerate(steps):
        sy = Inches(1.5 + idx * 1.05)
        c_step = add_card(s4, right_x, sy, right_w, Inches(0.95), bg_color=CARD_LIGHT, border_color=BORDER_LIGHT)
        tf = c_step.text_frame
        tf.word_wrap = True
        pt = tf.paragraphs[0]
        pt.text = title
        pt.font.name = "Calibri"
        pt.font.size = Pt(13)
        pt.font.bold = True
        pt.font.color.rgb = ACCENT_BLUE
        
        pd = tf.add_paragraph()
        pd.text = desc
        pd.font.name = "Calibri"
        pd.font.size = Pt(10.5)
        pd.font.color.rgb = TEXT_MUTED

    # ==========================================================
    # SLIDE 5: The 7 Concurrent Threat Detection Engines
    # ==========================================================
    s5 = prs.slides.add_slide(blank_layout)
    set_slide_background(s5, BG_LIGHT)
    add_header(s5, "Deep Dive: The 7 Concurrent Detection Engines", "MULTI-ENGINE THREAT INTELLIGENCE")

    engines = [
        ("1. Lexical & URL Engine", "Analyzes URI structure, Shannon entropy, homograph punycode, TLD reputation, IP hosts, and follows redirect chains.", "URL / Links"),
        ("2. Malware Payload Engine", "Performs static byte header analysis, PE/ELF/APK magic bytes, suspicious entropy, and heuristic binary scanning.", "Files & Binaries"),
        ("3. NLP Social Engineering", "Detects urgency cues, fear manipulation, credential requests, authority impersonation, and payment coercion.", "Text & Messages"),
        ("4. Sender Behavior Engine", "Evaluates historical sending baselines, anomaly patterns, and frequency bursts in local SQLite metadata.", "Sender Trust"),
        ("5. Email Header Engine", "Validates cryptographic SPF, DKIM, and DMARC alignments, hop tracing, and detects spoofed Display Name tricks.", "Email Auth"),
        ("6. Attachment Inspector", "Inspects nested archives, double-extension deceit (.pdf.exe), office macro payloads, and MIME-type discrepancies.", "Attachments"),
        ("7. Visual Brand Spoofing", "Uses OCR and visual layout comparisons against known brand login templates to identify pixel-level clone attacks.", "Screenshots / UI")
    ]

    # Layout in 2 columns (4 in col 1, 3 in col 2 with a highlight card)
    for idx in range(4):
        title, desc, badge = engines[idx]
        c = add_card(s5, Inches(0.8), Inches(1.5 + idx * 1.35), Inches(5.7), Inches(1.22))
        tf = c.text_frame
        tf.word_wrap = True
        p0 = tf.paragraphs[0]
        p0.text = f"{title}  [{badge}]"
        p0.font.name = "Calibri"
        p0.font.size = Pt(13)
        p0.font.bold = True
        p0.font.color.rgb = TEXT_DARK
        p1 = tf.add_paragraph()
        p1.text = desc
        p1.font.name = "Calibri"
        p1.font.size = Pt(11)
        p1.font.color.rgb = TEXT_MUTED

    for idx in range(3):
        title, desc, badge = engines[4 + idx]
        c = add_card(s5, Inches(6.8), Inches(1.5 + idx * 1.35), Inches(5.7), Inches(1.22))
        tf = c.text_frame
        tf.word_wrap = True
        p0 = tf.paragraphs[0]
        p0.text = f"{title}  [{badge}]"
        p0.font.name = "Calibri"
        p0.font.size = Pt(13)
        p0.font.bold = True
        p0.font.color.rgb = TEXT_DARK
        p1 = tf.add_paragraph()
        p1.text = desc
        p1.font.name = "Calibri"
        p1.font.size = Pt(11)
        p1.font.color.rgb = TEXT_MUTED

    # Highlights card bottom right
    c_hl = add_card(s5, Inches(6.8), Inches(1.5 + 3 * 1.35), Inches(5.7), Inches(1.22), bg_color=RGBColor(240, 253, 250), border_color=GREEN_ALERT)
    tf_hl = c_hl.text_frame
    tf_hl.word_wrap = True
    ph0 = tf_hl.paragraphs[0]
    ph0.text = "Concurrence & Fault Isolation"
    ph0.font.name = "Calibri"
    ph0.font.size = Pt(13)
    ph0.font.bold = True
    ph0.font.color.rgb = GREEN_ALERT
    ph1 = tf_hl.add_paragraph()
    ph1.text = "Engines run concurrently via Python asyncio. Failure or timeout in any single engine does not compromise the pipeline; partial signals are dynamically aggregated."
    ph1.font.name = "Calibri"
    ph1.font.size = Pt(11)
    ph1.font.color.rgb = TEXT_DARK

    # ==========================================================
    # SLIDE 6: Confidence-Weighted Fusion & Dynamic Profiles
    # ==========================================================
    s6 = prs.slides.add_slide(blank_layout)
    set_slide_background(s6, BG_LIGHT)
    add_header(s6, "Confidence-Weighted Risk Fusion & Policy Classification", "DECISION ENGINE & SCORING")

    # Card 1: Mathematical Formula & Aggregation
    c1 = add_card(s6, Inches(0.8), Inches(1.5), Inches(5.7), Inches(5.3))
    tf1 = c1.text_frame
    tf1.word_wrap = True
    
    p = tf1.paragraphs[0]
    p.text = "Risk Fusion Engine"
    p.font.name = "Calibri"
    p.font.size = Pt(18)
    p.font.bold = True
    p.font.color.rgb = ACCENT_BLUE

    items_c1 = [
        ("Independent Probabilistic Signals", "Rather than naive majority voting, each active engine computes an individual threat risk r_i in [0, 100] alongside an empirical confidence c_i in [0, 1]."),
        ("Confidence-Weighted Fusion Formula", "Composite Risk Score R = (Sum of w_i * c_i * r_i) / (Sum of w_i * c_i), where w_i represents the calibrated engine domain weight."),
        ("Elimination of Single-Point Blind Spots", "Corroborating indicators exponentially escalate alert priority, while isolated weak signals are downweighted to prevent false-positive alert fatigue."),
        ("Decision Provenance", "Every fused score retains an auditable trace of which engines fired, their contributing weights, and raw feature metrics.")
    ]
    for sub_title, text in items_c1:
        p_t = tf1.add_paragraph()
        p_t.text = sub_title
        p_t.font.name = "Calibri"
        p_t.font.size = Pt(13)
        p_t.font.bold = True
        p_t.font.color.rgb = TEXT_DARK
        p_t.space_before = Pt(10)

        p_d = tf1.add_paragraph()
        p_d.text = text
        p_d.font.name = "Calibri"
        p_d.font.size = Pt(11)
        p_d.font.color.rgb = TEXT_MUTED

    # Card 2: Dynamic Profiles & Classification Tiers
    c2 = add_card(s6, Inches(6.8), Inches(1.5), Inches(5.7), Inches(5.3))
    tf2 = c2.text_frame
    tf2.word_wrap = True

    p_c2 = tf2.paragraphs[0]
    p_c2.text = "Classification Categories & Profiles"
    p_c2.font.name = "Calibri"
    p_c2.font.size = Pt(18)
    p_c2.font.bold = True
    p_c2.font.color.rgb = TEXT_DARK

    tiers = [
        ("SAFE (Score: 0 – 24)", "Payload verified clean; all reputable indicators normal.", GREEN_ALERT),
        ("SUSPICIOUS (Score: 25 – 49)", "Anomalous indicators present (e.g., new domain, unverified sender). Caution advisory.", AMBER_ALERT),
        ("DECEPTIVE (Score: 50 – 69)", "High probability of social engineering or misleading content.", AMBER_ALERT),
        ("PHISHING (Score: 70 – 89)", "Confirmed brand spoofing, credential harvesting, or fake login portals.", RED_ALERT),
        ("MALWARE (Score: 90 – 100)", "Directly weaponized payload, exploit shellcode, or malicious executable.", RED_ALERT)
    ]

    for label, desc, color in tiers:
        p_l = tf2.add_paragraph()
        p_l.text = label
        p_l.font.name = "Calibri"
        p_l.font.size = Pt(12)
        p_l.font.bold = True
        p_l.font.color.rgb = color
        p_l.space_before = Pt(8)

        p_td = tf2.add_paragraph()
        p_td.text = desc
        p_td.font.name = "Calibri"
        p_td.font.size = Pt(10.5)
        p_td.font.color.rgb = TEXT_MUTED

    p_prof = tf2.add_paragraph()
    p_prof.text = "Configurable Policy Profiles: Supports 'Default', 'Strict' (zero-trust high sensitivity), and 'Enterprise' (custom threshold overrides) based on corporate threat tolerance."
    p_prof.font.name = "Calibri"
    p_prof.font.size = Pt(11)
    p_prof.font.bold = True
    p_prof.font.color.rgb = ACCENT_BLUE
    p_prof.space_before = Pt(12)

    # ==========================================================
    # SLIDE 7: Native Android Client & Guardian Mode
    # ==========================================================
    s7 = prs.slides.add_slide(blank_layout)
    set_slide_background(s7, BG_LIGHT)
    add_header(s7, "Native Android Client & Proactive Protection", "MOBILE CLIENT IMPLEMENTATION")

    cards_android = [
        ("Guardian Mode (Accessibility Service)",
         "Real-time background service monitoring active apps (WhatsApp, Telegram, Messenger). Automatically detects surfaced malicious URLs and presents non-intrusive floating overlay warnings before the user clicks.",
         "Core Android Innovation"),
        ("Global System Share Target (ShareActivity)",
         "Integrated into the standard Android OS share sheet (android.intent.action.SEND). Users can share suspicious links, text clips, or files from any third-party app directly into SecureShield with one tap.",
         "Frictionless UX"),
        ("Gmail Background Intelligence",
         "Powered by Android WorkManager and read-only Google OAuth 2.0 scopes. Periodically polls unread inbox messages in the background, submitting headers and content for threat analysis with push notifications.",
         "Automated Defense"),
        ("Offline History & Local SQLite Storage",
         "Maintains an on-device encrypted scan log (secure_scan_history.db). Users can review historical verdicts, filter by risk severity, inspect forensic reasons, and delete entries anytime.",
         "User Autonomy")
    ]

    for idx, (title, desc, badge) in enumerate(cards_android):
        col = idx % 2
        row = idx // 2
        l = Inches(0.8 + col * 5.95)
        t = Inches(1.6 + row * 2.65)
        w = Inches(5.75)
        h = Inches(2.45)
        c = add_card(s7, l, t, w, h)
        tf = c.text_frame
        tf.word_wrap = True

        p_b = tf.paragraphs[0]
        p_b.text = badge.upper()
        p_b.font.name = "Calibri"
        p_b.font.size = Pt(10)
        p_b.font.bold = True
        p_b.font.color.rgb = ACCENT_BLUE

        p_t = tf.add_paragraph()
        p_t.text = title
        p_t.font.name = "Calibri"
        p_t.font.size = Pt(15)
        p_t.font.bold = True
        p_t.font.color.rgb = TEXT_DARK
        p_t.space_before = Pt(4)

        p_d = tf.add_paragraph()
        p_d.text = desc
        p_d.font.name = "Calibri"
        p_d.font.size = Pt(11.5)
        p_d.font.color.rgb = TEXT_MUTED
        p_d.space_before = Pt(8)

    # Bottom specs
    bot_android = add_card(s7, Inches(0.8), Inches(6.8), Inches(11.7), Inches(0.5), bg_color=RGBColor(241, 245, 249), border_color=BORDER_LIGHT)
    p_ba = bot_android.text_frame.paragraphs[0]
    p_ba.text = "Target SDK: Android 14 (API 34) | Minimum SDK: Android 7.0 (API 24) | Architecture: Modern MVVM + Coroutines + Jetpack Navigation"
    p_ba.font.name = "Calibri"
    p_ba.font.size = Pt(11)
    p_ba.font.bold = True
    p_ba.font.color.rgb = TEXT_DARK
    p_ba.alignment = PP_ALIGN.CENTER

    # ==========================================================
    # SLIDE 8: Privacy-First & Zero-Disk Storage Architecture
    # ==========================================================
    s8 = prs.slides.add_slide(blank_layout)
    set_slide_background(s8, BG_LIGHT)
    add_header(s8, "Privacy-Preserving & Zero-Disk Data Architecture", "DATA PRIVACY & COMPLIANCE")

    # Table of privacy boundaries
    t_top = Inches(1.5)
    t_left = Inches(0.8)
    t_width = Inches(11.7)
    t_height = Inches(3.6)

    table_shape_p = s8.shapes.add_table(5, 4, t_left, t_top, t_width, t_height)
    tbl = table_shape_p.table
    tbl.columns[0].width = Inches(2.5)
    tbl.columns[1].width = Inches(2.0)
    tbl.columns[2].width = Inches(2.0)
    tbl.columns[3].width = Inches(5.2)

    headers_p = ["Data Category", "In-Memory Inspection", "Written to Disk?", "Privacy Policy & Retention Lifecycle"]
    rows_p = [
        ("Message Text & URLs", "YES (Normalized & Scanned)", "NEVER (0 Byte Disk Retention)", "Processed strictly in volatile RAM; destroyed immediately following unified score generation."),
        ("Uploaded Files & Binaries", "YES (Up to 10 MB limit)", "NEVER", "Static and heuristic byte analysis performed in RAM; raw binaries are immediately discarded."),
        ("Sender Behavioral Signals", "YES (Metadata aggregation)", "SCOPED METADATA ONLY", "Stores only anonymized sender reputation metrics (sender_behavior.db) keyed by (client_id, sender_id)."),
        ("User Feedback & Evaluation", "YES (Telemetry recording)", "AGGREGATE DB ONLY", "Stores anonymous user rating reports (feedback.db) for false positive/negative tuning.")
    ]

    for c_idx, title in enumerate(headers_p):
        cell = tbl.cell(0, c_idx)
        cell.fill.solid()
        cell.fill.fore_color.rgb = RGBColor(15, 23, 42)
        p = cell.text_frame.paragraphs[0]
        p.text = title
        p.font.name = "Calibri"
        p.font.size = Pt(12)
        p.font.bold = True
        p.font.color.rgb = RGBColor(255, 255, 255)

    for r_idx, row_data in enumerate(rows_p):
        for c_idx, val in enumerate(row_data):
            cell = tbl.cell(r_idx + 1, c_idx)
            cell.fill.solid()
            cell.fill.fore_color.rgb = RGBColor(255, 255, 255) if r_idx % 2 == 0 else RGBColor(248, 250, 252)
            p = cell.text_frame.paragraphs[0]
            p.text = val
            p.font.name = "Calibri"
            p.font.size = Pt(11)
            p.font.color.rgb = TEXT_DARK
            if c_idx == 2 and "NEVER" in val:
                p.font.bold = True
                p.font.color.rgb = GREEN_ALERT
            elif c_idx == 0:
                p.font.bold = True

    # 3 Privacy pillars below
    pillars = [
        ("No PII Storage", "Zero retention of names, credentials, phone numbers, or unredacted email bodies on backend servers."),
        ("Read-Only OAuth", "Google OAuth scopes are strictly restricted to read-only metadata; cannot modify or delete user email."),
        ("Strict Payload Caps", "10 MB file ceiling and rate-limiting prevents memory exhaustion and denial-of-service abuse.")
    ]
    for idx, (title, desc) in enumerate(pillars):
        c = add_card(s8, Inches(0.8 + idx * 3.97), Inches(5.3), Inches(3.76), Inches(1.8), bg_color=CARD_LIGHT, border_color=BORDER_LIGHT)
        tf = c.text_frame
        tf.word_wrap = True
        pt = tf.paragraphs[0]
        pt.text = title
        pt.font.name = "Calibri"
        pt.font.size = Pt(13)
        pt.font.bold = True
        pt.font.color.rgb = ACCENT_BLUE
        pd = tf.add_paragraph()
        pd.text = desc
        pd.font.name = "Calibri"
        pd.font.size = Pt(11)
        pd.font.color.rgb = TEXT_MUTED
        pd.space_before = Pt(6)

    # ==========================================================
    # SLIDE 9: Explainable Security & Live Alert Simulation
    # ==========================================================
    s9 = prs.slides.add_slide(blank_layout)
    set_slide_background(s9, BG_LIGHT)
    add_header(s9, "Explainable Security: Anatomy of an Incident Alert", "USER INTERFACE & EXPLAINABILITY")

    # Left Card: Live Alert Simulation (Phone style UI)
    phone_card = add_card(s9, Inches(0.8), Inches(1.5), Inches(4.5), Inches(5.4), bg_color=RGBColor(24, 24, 27), border_color=RGBColor(63, 63, 70))
    tf_p = phone_card.text_frame
    tf_p.word_wrap = True

    p0 = tf_p.paragraphs[0]
    p0.text = "🚨 SECURESHIELD ALERT"
    p0.font.name = "Calibri"
    p0.font.size = Pt(14)
    p0.font.bold = True
    p0.font.color.rgb = RED_ALERT

    p_badge = tf_p.add_paragraph()
    p_badge.text = "THREAT LEVEL: PHISHING (Score: 88/100)"
    p_badge.font.name = "Calibri"
    p_badge.font.size = Pt(12)
    p_badge.font.bold = True
    p_badge.font.color.rgb = RGBColor(255, 255, 255)
    p_badge.space_before = Pt(8)

    p_ev_h = tf_p.add_paragraph()
    p_ev_h.text = "Forensic Evidence Detected:"
    p_ev_h.font.name = "Calibri"
    p_ev_h.font.size = Pt(11)
    p_ev_h.font.bold = True
    p_ev_h.font.color.rgb = ACCENT_CYAN
    p_ev_h.space_before = Pt(10)

    evidence_items = [
        "• URL Engine: Punycode homograph domain masquerading as 'microsoft-verify.top'.",
        "• NLP Engine: High urgency phrasing ('Account suspended in 2 hours').",
        "• Header Engine: SPF fail; sender IP not authorized by origin domain.",
        "• Visual Engine: Login form matched 94% visual similarity to Office365."
    ]
    for ev in evidence_items:
        pev = tf_p.add_paragraph()
        pev.text = ev
        pev.font.name = "Calibri"
        pev.font.size = Pt(10)
        pev.font.color.rgb = RGBColor(228, 228, 231)
        pev.space_before = Pt(4)

    p_act_h = tf_p.add_paragraph()
    p_act_h.text = "Recommended Action:"
    p_act_h.font.name = "Calibri"
    p_act_h.font.size = Pt(11)
    p_act_h.font.bold = True
    p_act_h.font.color.rgb = AMBER_ALERT
    p_act_h.space_before = Pt(10)

    p_act = tf_p.add_paragraph()
    p_act.text = "DO NOT CLICK LINK. Do not enter credentials. Sender address has been flagged as compromised."
    p_act.font.name = "Calibri"
    p_act.font.size = Pt(10)
    p_act.font.bold = True
    p_act.font.color.rgb = RGBColor(255, 255, 255)

    # Right Card: The 4-Step Explainability Pipeline
    pipe_card = add_card(s9, Inches(5.6), Inches(1.5), Inches(6.9), Inches(5.4))
    tf_pipe = pipe_card.text_frame
    tf_pipe.word_wrap = True

    pt_h = tf_pipe.paragraphs[0]
    pt_h.text = "Why Explainability Matters in Modern Security"
    pt_h.font.name = "Calibri"
    pt_h.font.size = Pt(18)
    pt_h.font.bold = True
    pt_h.font.color.rgb = TEXT_DARK

    pipe_steps = [
        ("1. Provenance Tracking", "Rather than emitting an unexplained 'Blocked' warning, SecureShield details exactly which engines triggered and their respective severity scores."),
        ("2. Plain-Language Human Explanations", "Technical indicators (e.g., 'DKIM align fail', 'Entropy > 7.2') are translated dynamically into clear, non-technical threat narratives."),
        ("3. Actionable Remediation Guidance", "Every alert delivers context-specific guidance (e.g., 'Contact sender via verified phone call', 'Disconnect Wi-Fi', 'Do not open attachment')."),
        ("4. Enterprise SOC Triage Acceleration", "When used in institutional environments, detailed forensic output significantly slashes incident response triage time for security analysts.")
    ]

    for title, desc in pipe_steps:
        p_st = tf_pipe.add_paragraph()
        p_st.text = title
        p_st.font.name = "Calibri"
        p_st.font.size = Pt(13)
        p_st.font.bold = True
        p_st.font.color.rgb = ACCENT_BLUE
        p_st.space_before = Pt(10)

        p_sd = tf_pipe.add_paragraph()
        p_sd.text = desc
        p_sd.font.name = "Calibri"
        p_sd.font.size = Pt(11)
        p_sd.font.color.rgb = TEXT_MUTED

    # ==========================================================
    # SLIDE 10: Comparative Advantage & System Benchmark
    # ==========================================================
    s10 = prs.slides.add_slide(blank_layout)
    set_slide_background(s10, BG_LIGHT)
    add_header(s10, "Feature Matrix: SecureShield AI vs Traditional Defenses", "COMPARATIVE ANALYSIS")

    comp_headers = ["Key Capability", "Google Safe Browsing", "Standard Mobile AV", "Email Native Filter", "SecureShield AI"]
    comp_rows = [
        ("Multi-Engine Threat Fusion", "❌ Single-signal", "❌ Binary / Hashes", "❌ Email-only heuristics", "✅ 7 Concurrent Engines"),
        ("Real-Time In-App Protection", "❌ Browser only", "❌ App install time only", "❌ Not applicable", "✅ Guardian Mode Overlay"),
        ("QR Code Threat (Quishing)", "❌ Not supported", "❌ Limited", "❌ Often ignored", "✅ Decodes & Feeds Pipeline"),
        ("Visual Brand Impersonation", "❌ No visual analysis", "❌ No OCR/Vision", "❌ Limited", "✅ Visual & Logo Matching"),
        ("Sender Behavioral Baseline", "❌ Static domain check", "❌ Not supported", "⚠️ Basic SPF/DKIM only", "✅ Per-Sender SQLite History"),
        ("Explainable Forensics & Advice", "⚠️ Generic warning", "⚠️ Binary virus name", "⚠️ Opaque spam score", "✅ Full Evidence & Action Steps"),
        ("Zero-Disk Privacy Policy", "⚠️ Logs queries to cloud", "⚠️ Device telemetry", "⚠️ Scanned on cloud", "✅ Zero Server Disk Retention")
    ]

    t_top = Inches(1.5)
    t_left = Inches(0.8)
    t_width = Inches(11.7)
    t_height = Inches(5.2)

    table_shape_c = s10.shapes.add_table(8, 5, t_left, t_top, t_width, t_height)
    tc = table_shape_c.table
    tc.columns[0].width = Inches(2.9)
    tc.columns[1].width = Inches(2.2)
    tc.columns[2].width = Inches(2.2)
    tc.columns[3].width = Inches(2.2)
    tc.columns[4].width = Inches(2.2)

    for c_idx, title in enumerate(comp_headers):
        cell = tc.cell(0, c_idx)
        cell.fill.solid()
        cell.fill.fore_color.rgb = RGBColor(14, 116, 144) if c_idx == 4 else RGBColor(15, 23, 42)
        p = cell.text_frame.paragraphs[0]
        p.text = title
        p.font.name = "Calibri"
        p.font.size = Pt(12)
        p.font.bold = True
        p.font.color.rgb = RGBColor(255, 255, 255)

    for r_idx, row_data in enumerate(comp_rows):
        for c_idx, val in enumerate(row_data):
            cell = tc.cell(r_idx + 1, c_idx)
            cell.fill.solid()
            if c_idx == 4:
                cell.fill.fore_color.rgb = RGBColor(240, 253, 250)
            else:
                cell.fill.fore_color.rgb = RGBColor(255, 255, 255) if r_idx % 2 == 0 else RGBColor(248, 250, 252)
            p = cell.text_frame.paragraphs[0]
            p.text = val
            p.font.name = "Calibri"
            p.font.size = Pt(11)
            p.font.color.rgb = GREEN_ALERT if "✅" in val else RED_ALERT if "❌" in val else TEXT_DARK
            if c_idx == 0:
                p.font.bold = True
                p.font.color.rgb = TEXT_DARK
            elif c_idx == 4:
                p.font.bold = True

    # ==========================================================
    # SLIDE 11: Deployment, Testing & Performance Validation
    # ==========================================================
    s11 = prs.slides.add_slide(blank_layout)
    set_slide_background(s11, BG_LIGHT)
    add_header(s11, "Implementation Highlights & System Verification", "DEPLOYMENT & PERFORMANCE")

    cards_perf = [
        ("FastAPI Asynchronous Gateway",
         "Built with Python 3.10+ and Uvicorn. Designed with non-blocking async routes and ThreadPoolExecutor concurrency, enabling near-instant response times for multi-engine pipelines.",
         "High Throughput"),
        ("CI/CD Pipeline & Automated Testing",
         "GitHub Actions workflows ('backend-ci-cd.yml' and 'android-ci-cd.yml') execute automated unit tests, engine verification suites, and Gradle Android builds on every commit.",
         "Reliability & QA"),
        ("Zero-Impact Battery Efficiency",
         "The Android client offloads heavy feature extraction and OCR/vision computation to the backend, ensuring zero noticeable battery drain during background Guardian and WorkManager tasks.",
         "Optimized Client"),
        ("Telemetry & User Feedback Loop",
         "Includes live /api/feedback and /api/evaluation/metrics endpoints, recording user accuracy confirmations and enabling continuous threshold fine-tuning.",
         "Continuous Learning")
    ]

    for idx, (title, desc, badge) in enumerate(cards_perf):
        col = idx % 2
        row = idx // 2
        l = Inches(0.8 + col * 5.95)
        t = Inches(1.6 + row * 2.65)
        w = Inches(5.75)
        h = Inches(2.45)
        c = add_card(s11, l, t, w, h)
        tf = c.text_frame
        tf.word_wrap = True

        p_b = tf.paragraphs[0]
        p_b.text = badge.upper()
        p_b.font.name = "Calibri"
        p_b.font.size = Pt(10)
        p_b.font.bold = True
        p_b.font.color.rgb = ACCENT_BLUE

        p_t = tf.add_paragraph()
        p_t.text = title
        p_t.font.name = "Calibri"
        p_t.font.size = Pt(15)
        p_t.font.bold = True
        p_t.font.color.rgb = TEXT_DARK
        p_t.space_before = Pt(4)

        p_d = tf.add_paragraph()
        p_d.text = desc
        p_d.font.name = "Calibri"
        p_d.font.size = Pt(11.5)
        p_d.font.color.rgb = TEXT_MUTED
        p_d.space_before = Pt(8)

    # Bottom metric bar
    bot_perf = add_card(s11, Inches(0.8), Inches(6.8), Inches(11.7), Inches(0.5), bg_color=RGBColor(241, 245, 249), border_color=BORDER_LIGHT)
    p_bp = bot_perf.text_frame.paragraphs[0]
    p_bp.text = "Sub-Second In-Flight Latency (< 850 ms average) | Modular Microservices Ready | 100% In-Memory Privacy Compliant"
    p_bp.font.name = "Calibri"
    p_bp.font.size = Pt(11)
    p_bp.font.bold = True
    p_bp.font.color.rgb = TEXT_DARK
    p_bp.alignment = PP_ALIGN.CENTER

    # ==========================================================
    # SLIDE 12: Conclusion, Future Scope & References (Dark Theme)
    # ==========================================================
    s12 = prs.slides.add_slide(blank_layout)
    set_slide_background(s12, BG_DARK)

    # Title
    tb_c_title = s12.shapes.add_textbox(Inches(0.8), Inches(0.5), Inches(11.7), Inches(0.8))
    p_ct = tb_c_title.text_frame.paragraphs[0]
    p_ct.text = "Conclusion, Future Horizons & Key References"
    p_ct.font.name = "Calibri"
    p_ct.font.size = Pt(24)
    p_ct.font.bold = True
    p_ct.font.color.rgb = TEXT_LIGHT

    # Left: Conclusion & Future Scope
    c_fut = add_card(s12, Inches(0.8), Inches(1.4), Inches(5.7), Inches(5.4), bg_color=BG_CARD_DARK, border_color=RGBColor(38, 55, 95))
    tf_fut = c_fut.text_frame
    tf_fut.word_wrap = True

    p_fh = tf_fut.paragraphs[0]
    p_fh.text = "Summary & Future Roadmap"
    p_fh.font.name = "Calibri"
    p_fh.font.size = Pt(17)
    p_fh.font.bold = True
    p_fh.font.color.rgb = ACCENT_CYAN

    fut_items = [
        ("Working Solution Achieved", "Successfully transitioned from initial conceptual designs to a fully implemented, working multimodal cybersecurity platform uniting Android and FastAPI."),
        ("On-Device Edge ML Inference", "Future optimization will port lightweight quantized TFLite / ONNX models directly into Android for zero-latency offline lexical and visual scanning."),
        ("Enterprise SIEM Integrations", "Development of Webhook adapters for Splunk, Microsoft Sentinel, and Elastic SIEM to support enterprise-wide automated threat intelligence."),
        ("Zero-Trust Privacy Standard", "Proven that proactive threat defense does not require sacrificing personal privacy, using strict in-memory execution and zero disk retention.")
    ]

    for title, text in fut_items:
        p_t = tf_fut.add_paragraph()
        p_t.text = title
        p_t.font.name = "Calibri"
        p_t.font.size = Pt(12)
        p_t.font.bold = True
        p_t.font.color.rgb = TEXT_LIGHT
        p_t.space_before = Pt(8)

        p_d = tf_fut.add_paragraph()
        p_d.text = text
        p_d.font.name = "Calibri"
        p_d.font.size = Pt(10.5)
        p_d.font.color.rgb = TEXT_LIGHT_MUTED

    # Right: References & Standards
    c_ref = add_card(s12, Inches(6.8), Inches(1.4), Inches(5.7), Inches(5.4), bg_color=BG_CARD_DARK, border_color=RGBColor(38, 55, 95))
    tf_ref = c_ref.text_frame
    tf_ref.word_wrap = True

    p_rh = tf_ref.paragraphs[0]
    p_rh.text = "Key Academic & Technical References"
    p_rh.font.name = "Calibri"
    p_rh.font.size = Pt(17)
    p_rh.font.bold = True
    p_rh.font.color.rgb = ACCENT_CYAN

    refs = [
        "[1] APWG (Anti-Phishing Working Group). Phishing Activity Trends Reports (Q1-Q4 2024/2025).",
        "[2] Khonji, M., Iraqi, Y., & Jones, A. Phishing detection: A literature survey. IEEE Communications Surveys & Tutorials, 15(4), 2091–2121.",
        "[3] Alkhalil, Z., et al. Phishing attacks: A recent comprehensive study and a new anatomy. Frontiers in Computer Science, 3, 563060.",
        "[4] RFC 7208 & RFC 6376: Sender Policy Framework (SPF) & DomainKeys Identified Mail (DKIM).",
        "[5] MITRE ATT&CK Matrix for Mobile: T1476 (Phishing) & T1437 (Application Layer Protocol).",
        "[6] Android Developer Guide: AccessibilityService API & Jetpack WorkManager architecture.",
        "[7] Shafer, G. A Mathematical Theory of Evidence. Princeton University Press."
    ]

    for ref in refs:
        p_r = tf_ref.add_paragraph()
        p_r.text = ref
        p_r.font.name = "Calibri"
        p_r.font.size = Pt(10)
        p_r.font.color.rgb = TEXT_LIGHT_MUTED
        p_r.space_before = Pt(6)

    # Save presentation
    output_path = r"D:\Secure Shield AI\SecureShield_AI_Presentation.pptx"
    prs.save(output_path)
    print(f"Presentation saved successfully to {output_path}")

if __name__ == "__main__":
    create_deck()

