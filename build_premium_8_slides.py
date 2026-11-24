import os
import sys
import shutil
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE
from pptx.oxml import parse_xml

def create_deck():
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    # --- PREMIUM CYBERSECURITY PALETTE ---
    BG_AMOLED = RGBColor(2, 4, 10)         # #02040A Ultra-dark AMOLED
    PANEL_NAVY = RGBColor(11, 19, 43)      # #0B132B Deep cybersecurity slate navy
    PANEL_SUBTLE = RGBColor(18, 27, 54)    # #121B36 Secondary card
    BORDER_CYBER = RGBColor(30, 41, 59)    # #1E293B Clean slate border
    BORDER_CYAN = RGBColor(56, 189, 248)   # #38BDF8 Subtle cyan highlight border
    BORDER_RED = RGBColor(239, 68, 68)     # #EF4444 Controlled crimson border
    
    ACCENT_CYAN = RGBColor(56, 189, 248)   # #38BDF8 Electric Cyan
    ACCENT_BLUE = RGBColor(14, 165, 233)   # #0EA5E9 Cyber Blue
    ACCENT_RED = RGBColor(239, 68, 68)     # #EF4444 Crimson Alert
    ACCENT_AMBER = RGBColor(245, 158, 11)  # #F59E0B Warning Amber
    ACCENT_GREEN = RGBColor(16, 185, 129)  # #10B981 Verified Emerald

    TEXT_WHITE = RGBColor(248, 250, 252)   # #F8FAFC Heading White
    TEXT_BODY = RGBColor(203, 213, 225)    # #CBD5E1 Slate-300 Readable Body
    TEXT_MUTED = RGBColor(148, 163, 184)   # #94A3B8 Secondary Explanations
    TEXT_CODE = RGBColor(125, 211, 252)    # #7DD3FC Formula & Monospace

    LOGO_PATH = r"D:\Secure Shield AI\android\app\src\main\res\drawable\img_secureshield_logo.png"
    ARCH_IMG_PATH = r"D:\Secure Shield AI\documentation\images\system_architecture_diagram.jpg"

    def apply_transition(slide):
        try:
            trans = parse_xml('<p:transition xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:fade/></p:transition>')
            slide._element.append(trans)
        except Exception:
            pass

    def set_bg(slide):
        bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0), Inches(0), Inches(13.333), Inches(7.5))
        bg.fill.solid()
        bg.fill.fore_color.rgb = BG_AMOLED
        bg.line.fill.background()
        apply_transition(slide)
        return bg

    def add_header(slide, title_text, category_text, slide_num):
        # Category Kicker
        tb_cat = slide.shapes.add_textbox(Inches(0.8), Inches(0.4), Inches(10.5), Inches(0.3))
        p_cat = tb_cat.text_frame.paragraphs[0]
        p_cat.text = category_text.upper()
        p_cat.font.name = "Calibri"
        p_cat.font.size = Pt(10)
        p_cat.font.bold = True
        p_cat.font.color.rgb = ACCENT_CYAN

        # Title
        tb_title = slide.shapes.add_textbox(Inches(0.8), Inches(0.68), Inches(10.5), Inches(0.55))
        p_title = tb_title.text_frame.paragraphs[0]
        p_title.text = title_text
        p_title.font.name = "Calibri"
        p_title.font.size = Pt(21)
        p_title.font.bold = True
        p_title.font.color.rgb = TEXT_WHITE

        # Slide Number Badge
        tb_num = slide.shapes.add_textbox(Inches(11.8), Inches(0.4), Inches(0.8), Inches(0.35))
        p_num = tb_num.text_frame.paragraphs[0]
        p_num.text = f"{slide_num:02d} / 08"
        p_num.font.name = "Calibri"
        p_num.font.size = Pt(10)
        p_num.font.bold = True
        p_num.font.color.rgb = TEXT_MUTED
        p_num.alignment = PP_ALIGN.RIGHT

        # Subtle divider
        rule = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.8), Inches(1.3), Inches(11.733), Inches(0.02))
        rule.fill.solid()
        rule.fill.fore_color.rgb = BORDER_CYBER
        rule.line.fill.background()

    def add_card(slide, left, top, width, height, bg_color=PANEL_NAVY, border_color=BORDER_CYBER, border_width=1.0):
        card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
        card.fill.solid()
        card.fill.fore_color.rgb = bg_color
        if border_color:
            card.line.color.rgb = border_color
            card.line.width = Pt(border_width)
        else:
            card.line.fill.background()
        return card

    def add_notes(slide, text):
        slide.notes_slide.notes_text_frame.text = text

    # =========================================================================
    # SLIDE 1: Cinematic Title (SecureShield AI)
    # =========================================================================
    s1 = prs.slides.add_slide(blank_layout)
    set_bg(s1)

    # Accent decorative glow bar
    bar = s1.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.8), Inches(1.3), Inches(0.08), Inches(4.7))
    bar.fill.solid()
    bar.fill.fore_color.rgb = ACCENT_CYAN
    bar.line.fill.background()

    # Logo
    if os.path.exists(LOGO_PATH):
        s1.shapes.add_picture(LOGO_PATH, Inches(10.5), Inches(1.3), width=Inches(1.95))

    # Kicker
    tb_k = s1.shapes.add_textbox(Inches(1.1), Inches(1.25), Inches(9.0), Inches(0.35))
    pk = tb_k.text_frame.paragraphs[0]
    pk.text = "B.TECH MAJOR PROJECT PRESENTATION & DEFENSE  |  COMPUTER SCIENCE & ENGINEERING"
    pk.font.name = "Calibri"
    pk.font.size = Pt(10.5)
    pk.font.bold = True
    pk.font.color.rgb = ACCENT_CYAN

    # Main Title
    tb_main = s1.shapes.add_textbox(Inches(1.1), Inches(1.65), Inches(9.2), Inches(1.6))
    tf_m = tb_main.text_frame
    tf_m.word_wrap = True
    p1 = tf_m.paragraphs[0]
    p1.text = "SecureShield AI"
    p1.font.name = "Calibri"
    p1.font.size = Pt(44)
    p1.font.bold = True
    p1.font.color.rgb = TEXT_WHITE

    p2 = tf_m.add_paragraph()
    p2.text = "A Multimodal Phishing, Social Engineering & Malware Detection System"
    p2.font.name = "Calibri"
    p2.font.size = Pt(19)
    p2.font.bold = True
    p2.font.color.rgb = ACCENT_BLUE
    p2.space_before = Pt(4)

    # Subtitle
    tb_sub = s1.shapes.add_textbox(Inches(1.1), Inches(3.45), Inches(9.0), Inches(0.8))
    ps = tb_sub.text_frame.paragraphs[0]
    ps.text = "An end-to-end cybersecurity platform uniting a native Kotlin Android client (Guardian Mode) with a high-concurrency FastAPI backend deploying 7 concurrent threat detection engines."
    ps.font.name = "Calibri"
    ps.font.size = Pt(12.5)
    ps.font.color.rgb = TEXT_BODY

    # Team Members Card
    c_team = add_card(s1, Inches(1.1), Inches(4.55), Inches(11.35), Inches(2.2), bg_color=PANEL_NAVY, border_color=BORDER_CYBER)
    tf_t = c_team.text_frame
    tf_t.word_wrap = True

    pt0 = tf_t.paragraphs[0]
    pt0.text = "PROJECT TEAM MEMBERS"
    pt0.font.name = "Calibri"
    pt0.font.size = Pt(11)
    pt0.font.bold = True
    pt0.font.color.rgb = ACCENT_CYAN

    members = [
        ("N JAYANTH", "5P2"),
        ("N MANIDEEP", "5O2"),
        ("M HEMALATHA", "5L2"),
        ("P ANILKUMAR", "5Q3"),
        ("M RAMCHARAN", "5L9")
    ]
    pt1 = tf_t.add_paragraph()
    pt1.text = "    •    ".join([f"{name} ({roll})" for name, roll in members])
    pt1.font.name = "Calibri"
    pt1.font.size = Pt(13)
    pt1.font.bold = True
    pt1.font.color.rgb = TEXT_WHITE
    pt1.space_before = Pt(8)

    pt2 = tf_t.add_paragraph()
    pt2.text = "Department of Computer Science & Engineering | Major Project Defense"
    pt2.font.name = "Calibri"
    pt2.font.size = Pt(11)
    pt2.font.color.rgb = TEXT_MUTED
    pt2.space_before = Pt(10)

    pt3 = tf_t.add_paragraph()
    pt3.text = "Architecture: Kotlin 1.9 (Android 14)  |  FastAPI (Python 3.10+)  |  Confidence-Weighted Risk Fusion  |  Zero Server Disk Retention"
    pt3.font.name = "Calibri"
    pt3.font.size = Pt(10.5)
    pt3.font.bold = True
    pt3.font.color.rgb = ACCENT_CYAN
    pt3.space_before = Pt(4)

    add_notes(s1, (
        "Good morning respected evaluators. Today we present SecureShield AI, our B.Tech major project. "
        "SecureShield AI is an intelligent, multimodal cybersecurity platform that protects mobile users against "
        "phishing, social engineering, and malware across SMS, messaging apps, and email. "
        "We combine a native Android client operating with an Accessibility-powered Guardian Mode and a high-concurrency "
        "FastAPI backend deploying 7 concurrent detection engines."
    ))

    # =========================================================================
    # SLIDE 2: The Problem and Our Solution (The Mobile Threat Gap)
    # =========================================================================
    s2 = prs.slides.add_slide(blank_layout)
    set_bg(s2)
    add_header(s2, "The Mobile Threat Gap: 3 Vectors & 1 Unified Defense", "THE PROBLEM & OUR SOLUTION", 2)

    # 3 Threat Cards on Left
    threats = [
        ("Vector 1: Multi-Channel Ingress",
         "Adversaries bypass corporate email filters by distributing phishing lures through consumer channels: SMS (smishing), WhatsApp, Telegram, and physical QR codes (quishing).",
         ACCENT_RED),
        ("Vector 2: Fast-Flux & Evasion",
         "Short-lived domains and URL shorteners evade static blacklists (which suffer a 24–48h lag), while homographs and cloned login pages deceive user perception.",
         ACCENT_AMBER),
        ("Vector 3: Opaque Binary Warnings",
         "Existing security tools emit generic 'Dangerous Site' alerts without forensic root-cause reasoning, causing severe warning fatigue and accidental compromise.",
         ACCENT_RED)
    ]

    for idx, (title, desc, col_t) in enumerate(threats):
        sy = Inches(1.5 + idx * 1.7)
        c_th = add_card(s2, Inches(0.8), sy, Inches(5.6), Inches(1.55), bg_color=PANEL_NAVY, border_color=BORDER_CYBER)
        tf = c_th.text_frame
        tf.word_wrap = True

        p0 = tf.paragraphs[0]
        p0.text = title
        p0.font.name = "Calibri"
        p0.font.size = Pt(12)
        p0.font.bold = True
        p0.font.color.rgb = col_t

        p1 = tf.add_paragraph()
        p1.text = desc
        p1.font.name = "Calibri"
        p1.font.size = Pt(10)
        p1.font.color.rgb = TEXT_BODY
        p1.space_before = Pt(4)

    # Big Solution Card on Right
    c_sol = add_card(s2, Inches(6.8), Inches(1.5), Inches(5.733), Inches(4.95), bg_color=PANEL_SUBTLE, border_color=BORDER_CYAN, border_width=1.5)
    tfs = c_sol.text_frame
    tfs.word_wrap = True

    ps0 = tfs.paragraphs[0]
    ps0.text = "THE PROPOSED UNIFIED SOLUTION"
    ps0.font.name = "Calibri"
    ps0.font.size = Pt(11)
    ps0.font.bold = True
    ps0.font.color.rgb = ACCENT_CYAN

    ps1 = tfs.add_paragraph()
    ps1.text = "SecureShield AI Platform"
    ps1.font.name = "Calibri"
    ps1.font.size = Pt(18)
    ps1.font.bold = True
    ps1.font.color.rgb = TEXT_WHITE
    ps1.space_before = Pt(2)

    sol_points = [
        ("Unified Mobile Ingress", "Guardian Accessibility Mode intercepts on-screen links across WhatsApp and Telegram before click, backed by system Share Sheet and background Gmail scanning."),
        ("7 Concurrent Detection Engines", "Asynchronous parallel feature extraction covering URL lexical structure, file payload hashes, NLP social engineering, sender trust, headers, attachments, and OCR vision."),
        ("Confidence-Weighted Risk Fusion", "Mathematical evidence aggregation mapping diverse engine risk signals and empirical confidence into a normalized 0–100 composite threat score."),
        ("Explainable Forensics & Advice", "Delivers plain-language root-cause rationales and context-specific mitigation guidance, eliminating opaque warning fatigue.")
    ]

    for stitle, sdesc in sol_points:
        p = tfs.add_paragraph()
        p.text = f"✔  {stitle}"
        p.font.name = "Calibri"
        p.font.size = Pt(11)
        p.font.bold = True
        p.font.color.rgb = ACCENT_GREEN
        p.space_before = Pt(6)

        pd = tfs.add_paragraph()
        pd.text = sdesc
        pd.font.name = "Calibri"
        pd.font.size = Pt(9.5)
        pd.font.color.rgb = TEXT_BODY

    # Bottom Takeaway Card
    c_bot2 = add_card(s2, Inches(0.8), Inches(6.6), Inches(11.733), Inches(0.55), bg_color=BG_AMOLED, border_color=BORDER_CYBER)
    pb = c_bot2.text_frame.paragraphs[0]
    pb.text = "Core Takeaway: Effective mobile defense requires intercepting threats where they appear and fusing multimodal signals into an explainable decision."
    pb.font.name = "Calibri"
    pb.font.size = Pt(10.5)
    pb.font.bold = True
    pb.font.color.rgb = ACCENT_CYAN
    pb.alignment = PP_ALIGN.CENTER

    add_notes(s2, (
        "Explain the motivation: Mobile devices have become the #1 attack vector. Traditional antivirus only scans installed APKs, "
        "and browser blacklists suffer from a 24-48 hour lag. When an attacker sends a zero-day phishing link via WhatsApp, "
        "existing tools do nothing. SecureShield AI solves this by intercepting the threat on-screen, running it through 7 concurrent "
        "engines, and giving the user an explainable warning before they fall victim."
    ))

    # =========================================================================
    # SLIDE 3: System Architecture (How SecureShield AI Works)
    # =========================================================================
    s3 = prs.slides.add_slide(blank_layout)
    set_bg(s3)
    add_header(s3, "End-to-End System Architecture & Data Flow", "SYSTEM ARCHITECTURE", 3)

    # Left: Architecture Diagram if available
    has_arch_img = os.path.exists(ARCH_IMG_PATH)
    left_w = Inches(6.1)
    if has_arch_img:
        s3.shapes.add_picture(ARCH_IMG_PATH, Inches(0.8), Inches(1.5), width=left_w)
    else:
        c_diag = add_card(s3, Inches(0.8), Inches(1.5), left_w, Inches(5.3))
        p = c_diag.text_frame.paragraphs[0]
        p.text = "[HIGH-RESOLUTION ARCHITECTURE PIPELINE]"

    # Right: 5 Visual Pipeline Stages
    stages = [
        ("Stage 1: Multi-Channel Ingress (Android Client)",
         "Guardian Accessibility Service monitors active chat screens; Global Share Target handles user-submitted files/links; Gmail Worker monitors unread mail via read-only OAuth.",
         ACCENT_CYAN),
        ("Stage 2: Preprocessing & Anti-SSRF (FastAPI)",
         "Enforces 10MB memory boundaries, applies Unicode NFKC normalization, unshortens redirects, and performs DNS pinning to prevent Server-Side Request Forgery.",
         ACCENT_BLUE),
        ("Stage 3: 7 Concurrent Detection Engines",
         "Dispatches tasks asynchronously across 7 specialized engines (URL, Malware, NLP, Sender, Header, Attachment, Vision) using Python asyncio.gather().",
         ACCENT_CYAN),
        ("Stage 4: Confidence-Weighted Risk Fusion",
         "Fuses heterogeneous engine outputs into a composite 0–100 risk score, factoring domain reliability and engine confidence without penalizing unavailable engines.",
         ACCENT_BLUE),
        ("Stage 5: Policy Classification & Explainability",
         "Applies policy thresholds ('Default', 'Strict', 'Enterprise'), builds plain-language forensic reasons, and dispatches a floating warning overlay to Android.",
         ACCENT_GREEN)
    ]

    for idx, (title, desc, col_s) in enumerate(stages):
        sy = Inches(1.5 + idx * 1.05)
        c_st = add_card(s3, Inches(7.15), sy, Inches(5.383), Inches(0.95), bg_color=PANEL_NAVY, border_color=BORDER_CYBER)
        tf = c_st.text_frame
        tf.word_wrap = True

        p0 = tf.paragraphs[0]
        p0.text = title
        p0.font.name = "Calibri"
        p0.font.size = Pt(11.5)
        p0.font.bold = True
        p0.font.color.rgb = col_s

        p1 = tf.add_paragraph()
        p1.text = desc
        p1.font.name = "Calibri"
        p1.font.size = Pt(9.5)
        p1.font.color.rgb = TEXT_BODY
        p1.space_before = Pt(2)

    # Bottom Implemented vs External Banner
    c_leg = add_card(s3, Inches(0.8), Inches(6.8), Inches(11.733), Inches(0.4), bg_color=BG_AMOLED, border_color=BORDER_CYBER)
    pl = c_leg.text_frame.paragraphs[0]
    pl.text = "Implemented Components: Android Client (Kotlin)  •  FastAPI Gateway  •  7 Engines  •  Risk Fusion  |  External Feeds: Google Safe Browsing, VirusTotal v3, MalwareBazaar"
    pl.font.name = "Calibri"
    pl.font.size = Pt(9.5)
    pl.font.bold = True
    pl.font.color.rgb = TEXT_MUTED
    pl.alignment = PP_ALIGN.CENTER

    add_notes(s3, (
        "Trace the architecture sequentially: "
        "1. Ingestion: Android client extracts the URL or file. "
        "2. Preprocessing: Fast input validation, Anti-SSRF, and 10MB memory safety. "
        "3. Concurrency: All 7 engines execute in parallel via asyncio. If one external API is slow, the others are not blocked. "
        "4. Risk Fusion: Weighted aggregation based on engine reliability. "
        "5. Classification & UX: The score maps to Safe, Suspicious, Deceptive, Phishing, or Malware, and the user receives a floating alert."
    ))

    # =========================================================================
    # SLIDE 4: Seven Detection Engines (Multimodal Threat Intelligence)
    # =========================================================================
    s4 = prs.slides.add_slide(blank_layout)
    set_bg(s4)
    add_header(s4, "Multimodal Threat Intelligence: 7 Concurrent Engines", "DETECTION ENGINES", 4)

    engines = [
        ("1. URL & Lexical Engine",
         "Shannon entropy, punycode homograph check, TLD reputation (.xyz, .top), IP hosts, @ credential injection, unshortening, and Google Safe Browsing API v4.",
         "Heuristic & Threat Feed", ACCENT_CYAN),
        ("2. Malware Payload Engine",
         "SHA-256 hash lookup against local verified MalwareBazaar signature store; fallback to cloud VirusTotal v3 API with 10-minute TTL cache.",
         "Hash & Feed Intelligence", ACCENT_BLUE),
        ("3. NLP Social Engineering",
         "Rule-based semantic pattern matching for urgency, credential extraction, account suspension, and prize lures; features 2FA disclaimer context filtering.",
         "Rule-Based Semantic Heuristics", ACCENT_CYAN),
        ("4. Sender Behavior Engine",
         "Per-client SQLite baselines; evaluates historical message frequency, link density, and flags out-of-character sender domain shifts.",
         "Statistical Baseline Anomaly", ACCENT_BLUE),
        ("5. Email Header Analysis",
         "MIME header parser verifying cryptographic SPF, DKIM, and DMARC alignments; detects Display Name spoofing and Reply-To domain discrepancies.",
         "Protocol Authentication", ACCENT_CYAN),
        ("6. Attachment Inspector",
         "Static byte analysis for magic byte / extension mismatches, RTLO overrides, double extensions (.pdf.exe), Office macros (vbaProject.bin), and zip-bombs.",
         "Static Byte & Archive Inspector", ACCENT_BLUE),
        ("7. Visual & QR Analysis",
         "cv2.QRCodeDetector for quishing; EasyOCR for on-screen text extraction; geometric contour analysis (cv2.Canny, approxPolyDP) for fake login forms.",
         "Computer Vision & OCR", ACCENT_CYAN)
    ]

    for idx, (title, desc, cat, col_c) in enumerate(engines):
        col = idx % 2
        row = idx // 2
        l = Inches(0.8 + col * 5.95)
        t = Inches(1.5 + row * 1.35)
        w = Inches(5.75)
        h = Inches(1.23)
        c = add_card(s4, l, t, w, h)
        tf = c.text_frame
        tf.word_wrap = True

        p0 = tf.paragraphs[0]
        p0.text = f"{title}  [{cat}]"
        p0.font.name = "Calibri"
        p0.font.size = Pt(11)
        p0.font.bold = True
        p0.font.color.rgb = col_c

        p1 = tf.add_paragraph()
        p1.text = desc
        p1.font.name = "Calibri"
        p1.font.size = Pt(9.5)
        p1.font.color.rgb = TEXT_BODY
        p1.space_before = Pt(2)

    # Concurrency Callout in 8th slot
    c_f4 = add_card(s4, Inches(6.75), Inches(5.55), Inches(5.75), Inches(1.23), bg_color=PANEL_SUBTLE, border_color=BORDER_CYAN)
    tff = c_f4.text_frame
    tff.word_wrap = True
    pf0 = tff.paragraphs[0]
    pf0.text = "ACADEMIC HONESTY & FAULT ISOLATION"
    pf0.font.name = "Calibri"
    pf0.font.size = Pt(11)
    pf0.font.bold = True
    pf0.font.color.rgb = ACCENT_GREEN

    pf1 = tff.add_paragraph()
    pf1.text = "Transparent Technical Classification: NLP uses rule-based semantic regex matching (not deep learning LLMs); Malware analysis is static hash/header lookup (not dynamic VM emulation). Concurrency via asyncio guarantees partial engine failures never crash the pipeline."
    pf1.font.name = "Calibri"
    pf1.font.size = Pt(9.5)
    pf1.font.color.rgb = TEXT_WHITE
    pf1.space_before = Pt(2)

    add_notes(s4, (
        "During viva evaluation, faculty often ask: 'Does your NLP engine use a Transformer model like BERT?' "
        "Answer honestly: 'No, our NLP engine uses verified rule-based semantic regex patterns with 2FA disclaimer context suppression. "
        "This keeps execution ultra-fast and lightweight without requiring a GPU, while porting to distilled MobileBERT is part of our future roadmap.' "
        "Evaluators highly respect this academic honesty."
    ))

    # =========================================================================
    # SLIDE 5: Guardian Mode and Application Workflow (Protection Where Threats Appear)
    # =========================================================================
    s5 = prs.slides.add_slide(blank_layout)
    set_bg(s5)
    add_header(s5, "Guardian Mode & 3-Stage Application Workflow", "MOBILE CLIENT WORKFLOW", 5)

    # 3 Sequential Stages: Capture -> Analyze -> Warn
    steps_s5 = [
        ("STAGE 1: CAPTURE",
         "Universal Ingress Tier",
         "• Guardian Accessibility Service: Passively parses on-screen URLs in active messaging apps (WhatsApp, Telegram, SMS) without root.\n"
         "• Global Share Target (ShareActivity): Accepts shared links, text, and files directly via Android's native share sheet.\n"
         "• Gmail Background Intelligence: Periodic 15-minute background sync via WorkManager using read-only Google OAuth scopes.",
         ACCENT_CYAN),
        ("STAGE 2: ANALYZE",
         "In-Memory Threat Evaluation",
         "• Strict 10MB memory upload ceiling prevents Out-Of-Memory and DoS attacks.\n"
         "• Preprocessor sanitizes Unicode and validates IP boundaries before redirect following.\n"
         "• 7 concurrent engines execute in parallel via FastAPI async event loop.\n"
         "• Zero Server Disk Retention: Raw payloads are destroyed immediately after scan.",
         ACCENT_BLUE),
        ("STAGE 3: WARN",
         "Explainable User Remediation",
         "• Floating Overlay Alert: GuardianInterceptActivity renders immediate warning dialog over the active app before user navigation.\n"
         "• Plain-Language Evidence: Displays fired engine reasons and actionable advice (e.g. 'Block sender', 'Do not enter credentials').\n"
         "• Sandboxed SQLite History: Stores sanitized scan metadata in secure_scan_history.db.",
         ACCENT_RED)
    ]

    for idx, (stage_hdr, sub_hdr, desc, col_s) in enumerate(steps_s5):
        l = Inches(0.8 + idx * 3.97)
        c = add_card(s5, l, Inches(1.5), Inches(3.76), Inches(4.3), bg_color=PANEL_NAVY, border_color=BORDER_CYBER)
        tf = c.text_frame
        tf.word_wrap = True

        p0 = tf.paragraphs[0]
        p0.text = stage_hdr
        p0.font.name = "Calibri"
        p0.font.size = Pt(11)
        p0.font.bold = True
        p0.font.color.rgb = col_s

        p1 = tf.add_paragraph()
        p1.text = sub_hdr
        p1.font.name = "Calibri"
        p1.font.size = Pt(13)
        p1.font.bold = True
        p1.font.color.rgb = TEXT_WHITE
        p1.space_before = Pt(2)

        p2 = tf.add_paragraph()
        p2.text = desc
        p2.font.name = "Calibri"
        p2.font.size = Pt(9.5)
        p2.font.color.rgb = TEXT_BODY
        p2.space_before = Pt(8)

    # Screenshot Verification Bar at bottom
    c_sc = add_card(s5, Inches(0.8), Inches(6.0), Inches(11.733), Inches(1.15), bg_color=PANEL_SUBTLE, border_color=BORDER_CYAN)
    tfc = c_sc.text_frame
    tfc.word_wrap = True
    pc0 = tfc.paragraphs[0]
    pc0.text = "VERIFIED DEMO WORKFLOW (From DEMO_SCRIPT.md):"
    pc0.font.name = "Calibri"
    pc0.font.size = Pt(10.5)
    pc0.font.bold = True
    pc0.font.color.rgb = ACCENT_CYAN

    sc_text = (
        "• E-Commerce Smishing Demo: SMS lure with IP host and @ symbol -> Intercepted -> Scored 85/100 -> Flagged as 'PHISHING'.\n"
        "• Trojan Invoice Demo: Shared invoice.exe -> Scanned via MalwareBazaar / VT -> Scored 100/100 -> Flagged as 'MALWARE'.\n"
        "• Screenshot Slots: [INSERT ACTUAL SCAN SCREENSHOT: MAIN DASHBOARD, VERDICT OVERLAY, SCAN HISTORY LOG]"
    )
    pc1 = tfc.add_paragraph()
    pc1.text = sc_text
    pc1.font.name = "Calibri"
    pc1.font.size = Pt(9.5)
    pc1.font.color.rgb = TEXT_WHITE
    pc1.space_before = Pt(2)

    add_notes(s5, (
        "Explain the 3-stage user journey: Capture, Analyze, Warn. "
        "Highlight that Guardian Mode uses the Android Accessibility Service to read rendered text nodes. "
        "Our ScanRateLimiter ensures that scrolling through a chat does not spam the backend. "
        "The floating dialog warns the user before they tap, directly stopping the attack before credentials are lost."
    ))

    # =========================================================================
    # SLIDE 6: Risk Scoring and Explainability (From Signals to a Threat Verdict)
    # =========================================================================
    s6 = prs.slides.add_slide(blank_layout)
    set_bg(s6)
    add_header(s6, "Risk Scoring Algorithm & Explainable Threat Verdicts", "FUSION ALGORITHM & SCORING", 6)

    # Left: Formula & Step-by-Step Calculation
    c_m6 = add_card(s6, Inches(0.8), Inches(1.5), Inches(5.75), Inches(5.35))
    tfm = c_m6.text_frame
    tfm.word_wrap = True

    pm0 = tfm.paragraphs[0]
    pm0.text = "CONFIDENCE-WEIGHTED FUSION FORMULA"
    pm0.font.name = "Calibri"
    pm0.font.size = Pt(12)
    pm0.font.bold = True
    pm0.font.color.rgb = ACCENT_CYAN

    pm_f = tfm.add_paragraph()
    pm_f.text = "R = [ Σ (w_i × c_i × s_i × r_i) ] / [ Σ (w_i × c_i × s_i) ]"
    pm_f.font.name = "Consolas"
    pm_f.font.size = Pt(12.5)
    pm_f.font.bold = True
    pm_f.font.color.rgb = TEXT_CODE
    pm_f.space_before = Pt(6)

    f_defs = [
        ("r_i in [0, 100]", "Threat risk score computed by engine i."),
        ("c_i in (0, 1.0]", "Empirical confidence reported by engine i."),
        ("w_i (Reliability)", "Domain weight (Malware: 1.0, URL: 0.9, Visual: 0.9, NLP: 0.8, Sender: 0.6, Headers: 0.75)."),
        ("s_i (Status Factor)", "1.0 for SUCCESS, 0.5 for PARTIAL (incomplete), 0.0 for SKIPPED/ERROR.")
    ]
    for var, vdesc in f_defs:
        p = tfm.add_paragraph()
        p.text = f"• {var}: {vdesc}"
        p.font.name = "Calibri"
        p.font.size = Pt(10)
        p.font.color.rgb = TEXT_BODY
        p.space_before = Pt(3)

    pm_ex = tfm.add_paragraph()
    pm_ex.text = "Numerical Calculation Example (Phishing Attack):"
    pm_ex.font.name = "Calibri"
    pm_ex.font.size = Pt(10.5)
    pm_ex.font.bold = True
    pm_ex.font.color.rgb = ACCENT_CYAN
    pm_ex.space_before = Pt(8)

    ex_calc = (
        "• URL Engine: r=85, c=0.9, w=0.9  -> Weight=0.81, Prod=68.85\n"
        "• NLP Engine: r=75, c=0.8, w=0.8  -> Weight=0.64, Prod=48.00\n"
        "• Sender Engine: r=60, c=0.5, w=0.6 -> Weight=0.30, Prod=18.00\n"
        "Total Effective Weight = 1.75 | Total Prod = 134.85\n"
        "Composite Threat Score R = 134.85 / 1.75 = 77.06"
    )
    p_ce = tfm.add_paragraph()
    p_ce.text = ex_calc
    p_ce.font.name = "Consolas"
    p_ce.font.size = Pt(9.5)
    p_ce.font.color.rgb = TEXT_CODE
    p_ce.space_before = Pt(2)

    # Right: Classification Thresholds & Simulated Alert
    c_p6 = add_card(s6, Inches(6.8), Inches(1.5), Inches(5.733), Inches(5.35))
    tfp = c_p6.text_frame
    tfp.word_wrap = True

    pp0 = tfp.paragraphs[0]
    pp0.text = "CLASSIFICATION THRESHOLDS & POLICY"
    pp0.font.name = "Calibri"
    pp0.font.size = Pt(12)
    pp0.font.bold = True
    pp0.font.color.rgb = ACCENT_BLUE

    tiers = [
        ("SAFE (< 20.0)", "Verified legitimate; all technical indicators clear.", ACCENT_GREEN),
        ("SUSPICIOUS [20.0 – 45.0)", "Anomalous attributes detected (e.g. newly registered TLD).", ACCENT_AMBER),
        ("DECEPTIVE [45.0 – 70.0)", "High probability of social engineering or misleading intent.", ACCENT_AMBER),
        ("PHISHING [70.0 – 90.0)", "Active credential harvesting, homograph domain, or fake login portal.", ACCENT_RED),
        ("MALWARE (Score >= 90.0)", "Exploit shellcode, trojanized binary, or confirmed signature match.", ACCENT_RED)
    ]
    for lbl, desc, col_tier in tiers:
        p = tfp.add_paragraph()
        p.text = lbl
        p.font.name = "Calibri"
        p.font.size = Pt(10.5)
        p.font.bold = True
        p.font.color.rgb = col_tier
        p.space_before = Pt(4)

        p2 = tfp.add_paragraph()
        p2.text = desc
        p2.font.name = "Calibri"
        p2.font.size = Pt(9.5)
        p2.font.color.rgb = TEXT_BODY

    # Simulated Alert Box
    c_al = add_card(s6, Inches(7.0), Inches(5.0), Inches(5.333), Inches(1.7), bg_color=PANEL_SUBTLE, border_color=BORDER_RED)
    tfa = c_al.text_frame
    tfa.word_wrap = True
    pa0 = tfa.paragraphs[0]
    pa0.text = "🚨 EXPLAINABLE INCIDENT ALERT SIMULATION"
    pa0.font.name = "Calibri"
    pa0.font.size = Pt(10.5)
    pa0.font.bold = True
    pa0.font.color.rgb = ACCENT_RED

    alert_txt = (
        "• Classification: PHISHING (Composite Score: 77.06 / 100)\n"
        "• Evidence: Punycode homograph host; high urgency cue ('account locked'); first-time sender.\n"
        "• Action Advice: DO NOT CLICK LINK. Verify sender independently. Block contact.\n"
        "• Malware Safeguard: High score alone never triggers 'Malware' without verified signature."
    )
    pa1 = tfa.add_paragraph()
    pa1.text = alert_txt
    pa1.font.name = "Calibri"
    pa1.font.size = Pt(9)
    pa1.font.color.rgb = TEXT_WHITE
    pa1.space_before = Pt(2)

    add_notes(s6, (
        "This is a key technical slide. Walk evaluators through the math: "
        "1. We multiply risk by engine confidence and reliability weight. "
        "2. We divide by the sum of weights, which normalizes the output strictly between 0 and 100. "
        "3. Emphasize the Malware Safeguard in policy.py: Even if an email has a phishing score of 95, "
        "it will be classified as PHISHING, not MALWARE, unless an actual malicious binary or hash was confirmed."
    ))

    # =========================================================================
    # SLIDE 7: Testing, Results, and Limitations (Engineering Validation)
    # =========================================================================
    s7 = prs.slides.add_slide(blank_layout)
    set_bg(s7)
    add_header(s7, "Engineering Validation: Test Results & System Limitations", "TESTING & LIMITATIONS", 7)

    # Left: Real PyTest Verification Suite
    c_test = add_card(s7, Inches(0.8), Inches(1.5), Inches(4.3), Inches(5.35))
    tft = c_test.text_frame
    tft.word_wrap = True

    pt0 = tft.paragraphs[0]
    pt0.text = "AUTOMATED TEST SUITE (pytest 9.1.1)"
    pt0.font.name = "Calibri"
    pt0.font.size = Pt(12)
    pt0.font.bold = True
    pt0.font.color.rgb = ACCENT_GREEN

    stats_s7 = [
        ("Total Tests Passed", "211 PASSED (100% Software Pass Rate)"),
        ("Subtests Passed", "55 Subtests Passed"),
        ("Test Execution Time", "46.90 Seconds"),
        ("Regression / Failures", "0 Regressions / 0 Failures")
    ]
    for lbl, val in stats_s7:
        p = tft.add_paragraph()
        p.text = f"{lbl}:"
        p.font.name = "Calibri"
        p.font.size = Pt(10)
        p.font.bold = True
        p.font.color.rgb = ACCENT_CYAN
        p.space_before = Pt(5)

        p2 = tft.add_paragraph()
        p2.text = val
        p2.font.name = "Calibri"
        p2.font.size = Pt(11)
        p2.font.bold = True
        p2.font.color.rgb = TEXT_WHITE

    pt_bench = tft.add_paragraph()
    pt_bench.text = "Measured In-Flight Latency:"
    pt_bench.font.name = "Calibri"
    pt_bench.font.size = Pt(10)
    pt_bench.font.bold = True
    pt_bench.font.color.rgb = ACCENT_AMBER
    pt_bench.space_before = Pt(8)

    pt_bench_d = tft.add_paragraph()
    pt_bench_d.text = "[MEASURED BENCHMARK: Latency ranges between 350ms – 1100ms when external APIs and EasyOCR execute; on-device heuristic fallback executes in < 45ms.]"
    pt_bench_d.font.name = "Calibri"
    pt_bench_d.font.size = Pt(9)
    pt_bench_d.font.color.rgb = TEXT_BODY

    pt_disc = tft.add_paragraph()
    pt_disc.text = "Academic Reality Check:"
    pt_disc.font.name = "Calibri"
    pt_disc.font.size = Pt(10)
    pt_disc.font.bold = True
    pt_disc.font.color.rgb = ACCENT_RED
    pt_disc.space_before = Pt(8)

    pt_disc_d = tft.add_paragraph()
    pt_disc_d.text = "A 100% passing automated test suite verifies code integrity, input boundaries, and formula consistency—it does NOT claim 100% real-world zero-day phishing detection accuracy."
    pt_disc_d.font.name = "Calibri"
    pt_disc_d.font.size = Pt(9)
    pt_disc_d.font.color.rgb = TEXT_MUTED

    # Right: Limitations & Constraints
    c_lim = add_card(s7, Inches(5.3), Inches(1.5), Inches(7.233), Inches(5.35))
    tfl = c_lim.text_frame
    tfl.word_wrap = True

    pl0 = tfl.paragraphs[0]
    pl0.text = "HONEST TECHNICAL LIMITATIONS & RESEARCH BOUNDARIES"
    pl0.font.name = "Calibri"
    pl0.font.size = Pt(12)
    pl0.font.bold = True
    pl0.font.color.rgb = ACCENT_AMBER

    limits_s7 = [
        ("1. Heuristic NLP Adversarial Evasion",
         "Regex and semantic patterns can be bypassed by creative adversarial paraphrasing or novel slang without fine-tuned contextual language models."),
        ("2. Static Payload Scope (No Dynamic Sandbox)",
         "The malware engine performs static signature, magic byte, and hash verification; it does not execute files inside a dynamic VM sandbox (e.g. Cuckoo Sandbox)."),
        ("3. Visual Engine Compute Latency",
         "EasyOCR on CPU incurs higher memory usage and latency (~1.5–2.5 seconds per screenshot) compared to pure regex lexical parsing."),
        ("4. External API Quota Boundaries",
         "VirusTotal and Google Safe Browsing enforce rate limits; prolonged offline use requires reliance on on-device heuristics and local cache."),
        ("5. Android Accessibility Limitations",
         "Custom-rendered canvases (Flutter/Unity) that do not expose standard accessibility nodes cannot be inspected by UniversalLinkGuardService.")
    ]

    for ltitle, ldesc in limits_s7:
        p = tfl.add_paragraph()
        p.text = f"⚠  {ltitle}"
        p.font.name = "Calibri"
        p.font.size = Pt(10.5)
        p.font.bold = True
        p.font.color.rgb = ACCENT_RED
        p.space_before = Pt(6)

        pd = tfl.add_paragraph()
        pd.text = ldesc
        pd.font.name = "Calibri"
        pd.font.size = Pt(9.5)
        pd.font.color.rgb = TEXT_BODY

    add_notes(s7, (
        "Evaluators appreciate engineering maturity. Present the numbers with confidence: "
        "211 unit and integration tests passed in 46.9 seconds across all 7 engines and API routes. "
        "Then walk through the limitations honestly: Explain that our malware analysis is static hash checking, not a full dynamic VM sandbox, "
        "and our NLP uses regex heuristics rather than a heavy transformer LLM. This builds immediate credibility."
    ))

    # =========================================================================
    # SLIDE 8: Conclusion and Future Scope (Explainable Protection Across Mobile Threat Channels)
    # =========================================================================
    s8 = prs.slides.add_slide(blank_layout)
    set_bg(s8)
    add_header(s8, "Explainable Protection: Summary, Roadmap & References", "CONCLUSION & ROADMAP", 8)

    # Left: 3 Core Contributions & Roadmap
    c_c8 = add_card(s8, Inches(0.8), Inches(1.5), Inches(5.75), Inches(5.35))
    tfc = c_c8.text_frame
    tfc.word_wrap = True

    p0 = tfc.paragraphs[0]
    p0.text = "CORE PROJECT CONTRIBUTIONS"
    p0.font.name = "Calibri"
    p0.font.size = Pt(12)
    p0.font.bold = True
    p0.font.color.rgb = ACCENT_CYAN

    contribs = [
        ("Unified Mobile Ingress", "Bridged Android Accessibility Service (Guardian Mode) with system Share Sheet and background Gmail synchronization."),
        ("Multimodal Signal Fusion", "Engineered a confidence-weighted risk fusion engine aggregating 7 concurrent detection engines to eliminate single-point blind spots."),
        ("Explainable Cyber Defense", "Replaced opaque binary warnings with clear evidence summaries, actionable user advice, and zero server disk retention.")
    ]
    for ctitle, cdesc in contribs:
        p = tfc.add_paragraph()
        p.text = f"✔  {ctitle}: {cdesc}"
        p.font.name = "Calibri"
        p.font.size = Pt(10)
        p.font.color.rgb = TEXT_BODY
        p.space_before = Pt(5)

    p_rd = tfc.add_paragraph()
    p_rd.text = "FUTURE ENGINEERING ROADMAP"
    p_rd.font.name = "Calibri"
    p_rd.font.size = Pt(12)
    p_rd.font.bold = True
    p_rd.font.color.rgb = ACCENT_BLUE
    p_rd.space_before = Pt(10)

    roadmap = [
        ("On-Device Quantized ML", "Port lightweight MobileBERT / TFLite models to Android for zero-latency offline NLP inference."),
        ("Dynamic Sandbox Detonation", "Integrate isolated container microservices for live binary behavioral telemetry."),
        ("Enterprise SIEM Connectors", "Standardized webhooks for Splunk and Microsoft Sentinel enterprise SOC pipelines.")
    ]
    for rtitle, rdesc in roadmap:
        p = tfc.add_paragraph()
        p.text = f"➔  {rtitle}: {rdesc}"
        p.font.name = "Calibri"
        p.font.size = Pt(10)
        p.font.color.rgb = TEXT_BODY
        p.space_before = Pt(4)

    # Right: References & Thank You
    c_r8 = add_card(s8, Inches(6.8), Inches(1.5), Inches(5.733), Inches(5.35))
    tfr = c_r8.text_frame
    tfr.word_wrap = True

    pr0 = tfr.paragraphs[0]
    pr0.text = "KEY ACADEMIC & TECHNICAL REFERENCES"
    pr0.font.name = "Calibri"
    pr0.font.size = Pt(12)
    pr0.font.bold = True
    pr0.font.color.rgb = ACCENT_CYAN

    refs_s8 = [
        "[1] Khonji, M., Iraqi, Y., & Jones, A. (2013). Phishing detection: A literature survey. IEEE Communications Surveys & Tutorials, 15(4), 2091–2121.",
        "[2] Alkhalil, Z., et al. (2021). Phishing attacks: A recent comprehensive study and a new anatomy. Frontiers in Computer Science, 3, 563060.",
        "[3] IETF RFC 7208 (SPF) & RFC 6376 (DKIM): Sender Authentication Standards.",
        "[4] MITRE ATT&CK Matrix for Mobile: Techniques T1476 (Phishing) & T1437.",
        "[5] Anti-Phishing Working Group (APWG). Phishing Activity Trends Reports."
    ]
    for ref in refs_s8:
        p = tfr.add_paragraph()
        p.text = ref
        p.font.name = "Calibri"
        p.font.size = Pt(9.5)
        p.font.color.rgb = TEXT_MUTED
        p.space_before = Pt(4)

    # Thank you card
    c_ty = add_card(s8, Inches(7.0), Inches(5.1), Inches(5.333), Inches(1.6), bg_color=PANEL_SUBTLE, border_color=BORDER_CYAN)
    tfty = c_ty.text_frame
    tfty.word_wrap = True
    pty0 = tfty.paragraphs[0]
    pty0.text = "THANK YOU!"
    pty0.font.name = "Calibri"
    pty0.font.size = Pt(16)
    pty0.font.bold = True
    pty0.font.color.rgb = ACCENT_GREEN
    pty0.alignment = PP_ALIGN.CENTER

    pty1 = tfty.add_paragraph()
    pty1.text = "We are open for evaluation questions and technical cross-examination."
    pty1.font.name = "Calibri"
    pty1.font.size = Pt(11)
    pty1.font.bold = True
    pty1.font.color.rgb = TEXT_WHITE
    pty1.alignment = PP_ALIGN.CENTER
    pty1.space_before = Pt(4)

    add_notes(s8, (
        "Concluding statement: "
        "'Thank you esteemed evaluators. SecureShield AI demonstrates an end-to-end working defense that combines "
        "native Android accessibility monitoring with concurrent threat intelligence, confidence-weighted risk fusion, "
        "and zero-disk privacy. We have substantiated our work with 211 passing tests and clear limitations. "
        "We are now ready for your questions and live demonstration.'"
    ))

    # Save to both target locations
    output_path = r"D:\Secure Shield AI\SecureShield_AI_Presentation.pptx"
    prs.save(output_path)
    
    # Also save a copy to SecureShield_AI_Final_8_Slides.pptx as requested
    copy_path = r"D:\Secure Shield AI\SecureShield_AI_Final_8_Slides.pptx"
    shutil.copyfile(output_path, copy_path)
    print(f"Presentation saved successfully to:\n1) {output_path}\n2) {copy_path}")

if __name__ == "__main__":
    create_deck()

