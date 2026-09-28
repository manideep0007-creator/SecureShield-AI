# Editable thresholds mapped to a 0-100 scale
CATEGORY_THRESHOLDS = {
    "Safe": 20,         # 0-19
    "Suspicious": 45,   # 20-44
    "Deceptive": 70,    # 45-69
    "Phishing": 90      # 70-89, >= 90 is Malware
}

# Plain-language explanations for various engine flags
FLAG_REASONS = {
    # URL Engine
    "ip_based_host": "The link hides its true destination using an IP address instead of a standard domain name.",
    "at_symbol_present": "The link uses an '@' character, a common trick to inject fake login credentials.",
    "high_hyphen_count": "The web address uses an unusually high number of hyphens.",
    "suspicious_tld": "The web address uses a suspicious top-level domain often associated with scams.",
    "url_shortener": "The link uses a URL shortener to mask its true destination.",
    "MALWARE": "Google Safe Browsing identified this URL as distributing malware.",
    "SOCIAL_ENGINEERING": "Google Safe Browsing identified this URL as a phishing or deceptive site.",
    "UNWANTED_SOFTWARE": "Google Safe Browsing identified this URL as distributing unwanted software.",
    
    # Malware Engine / File Preprocessing
    "extension_mismatch": "The actual file type (e.g. PDF/Image) does not match its file extension (.exe, .doc).",
    "vt_malicious": "VirusTotal databases detected this file as malicious.",
    "vt_suspicious": "VirusTotal databases flagged this file as suspicious.",
    "vt_not_found": "The file is completely unknown to threat intelligence databases.",
    
    # NLP Engine
    "nlp_urgency": "The message contains urgent language trying to force immediate action.",
    "nlp_credential_request": "The message asks for passwords, OTPs, or login verification.",
    "nlp_account_suspension": "The message threatens an account suspension or block.",
    "nlp_prize_lottery": "The message claims you won a prize or giveaway.",
    "nlp_unusual_payment": "The message asks for gift cards, cryptocurrency, or wire transfers.",
    
    # Sender Engine
    "first_time_sender": "This sender has never messaged you before.",
    "out_of_character_link": "This contact sent a link, which is out of character for them.",
    "out_of_character_file": "This contact sent a file, which is out of character for them."
}

# Recommended action per category
CATEGORY_ACTIONS = {
    "Safe": "No immediate action needed. Proceed normally.",
    "Suspicious": "Proceed with caution. Double check the sender's identity.",
    "Deceptive": "Do not click any links or download files. Reach out to the sender via a different trusted channel.",
    "Phishing": "Avoid the link. Block this sender and delete the message immediately.",
    "Malware": "Dangerous! Quarantine or delete the file immediately. Do not open or execute it."
}

def generate_fusion_score(module_results: list) -> dict:
    """Confidence-weighted average mapping to an Explainability Layer."""
    total_score = 0.0
    total_confidence = 0.0
    all_flags = []
    
    for result in module_results:
        if not result or "type" not in result:
            continue
            
        # Default confidences based on engine type/reliability
        confidence = 1.0 # default weight
        if result["type"] == "url":
            confidence = 0.8
        elif result["type"] == "file":
            confidence = 0.9
        elif result["type"] == "nlp":
            confidence = 0.65
        elif result["type"] == "sender":
            confidence = 0.5
            
        score = result.get("score", 0.0)
        flags = result.get("flags", [])
        
        all_flags.extend(flags)
        
        total_score += (score * confidence)
        total_confidence += confidence
        
    overall_score_float = (total_score / total_confidence) if total_confidence > 0 else 0.0
    # Scale from 0-1 to 0-100 integer
    score_100 = int(round(overall_score_float * 100))
    
    # Classify overall risk category
    category = "Safe"
    if score_100 >= CATEGORY_THRESHOLDS["Phishing"]:
        category = "Malware" if any(f in ["vt_malicious", "vt_suspicious", "extension_mismatch", "MALWARE"] for f in all_flags) else "Phishing"
    elif score_100 >= CATEGORY_THRESHOLDS["Deceptive"]:
        category = "Deceptive"
    elif score_100 >= CATEGORY_THRESHOLDS["Suspicious"]:
        category = "Suspicious"

    # Deduplicate flags and map to plain language reasons
    dedup_flags = list(set(all_flags))
    
    # Handle parameterized flags (e.g. high_hyphen_count(4))
    reasons = []
    for f in dedup_flags:
        base_flag = f.split('(')[0]
        if base_flag in FLAG_REASONS:
            reasons.append(FLAG_REASONS[base_flag])
        else:
            reasons.append(f"Triggered detection rule: {f}")
            
    # Default message if no specific reasons found but score is elevated
    if not reasons and score_100 > CATEGORY_THRESHOLDS["Safe"]:
        reasons.append("General heuristics detected unusual properties.")

    return {
        "final_score": score_100,
        "category": category,
        "reasons": reasons,
        "recommended_action": CATEGORY_ACTIONS.get(category, "Review carefully.")
    }
