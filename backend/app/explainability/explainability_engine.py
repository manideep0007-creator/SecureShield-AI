from app.models.risk_assessment import RiskAssessment, RiskClassification

class ExplainabilityEngine:
    FLAG_EXPLANATIONS = {
        "vt_malicious": "VirusTotal identified this content as malicious.",
        "vt_suspicious": "VirusTotal identified this content as suspicious.",
        "extension_mismatch": "The file extension does not match its true type.",
        "first_time_sender": "This is the first time receiving a message from this sender.",
        "out_of_character_link": "The sender included a link that is unusual for them.",
        "out_of_character_file": "The sender attached a file that is unusual for them.",
        "ip_based_host": "The URL uses an IP address instead of a standard domain name, which is often used in evasion tactics.",
        "at_symbol_present": "The URL contains an '@' symbol, which can hide the actual destination.",
        "suspicious_tld": "The URL uses a Top-Level Domain (TLD) commonly associated with spam or malicious activity.",
        "url_shortener": "The URL uses a shortening service, which hides the true destination.",
        "url_length_anomaly": "The URL is unusually long.",
        "path_length_anomaly": "The URL path is unusually complex or long.",
        "subdomain_depth_anomaly": "The URL contains an unusually high number of subdomains.",
        "suspicious_keywords": "Suspicious keywords were found in the URL.",
        "double_slash_redirect": "The URL contains a double slash redirect anomaly.",
        "http_without_https": "The URL uses insecure HTTP instead of HTTPS.",
        "non_standard_port": "The URL uses a non-standard network port.",
        "https_in_hostname": "The URL tries to appear secure by including 'https' in the domain itself.",
        "high_shannon_entropy": "The URL looks randomly generated.",
        "high_digit_ratio": "The URL contains a suspiciously high number of digits.",
        "special_char_overload": "The URL contains an unusual amount of special characters.",
        "base64_obfuscation": "The URL appears to contain Base64 encoded (hidden) data.",
        "newly_registered_domain": "The domain is newly registered, which is common for short-lived malicious sites.",
        "qr_code_detected": "A QR code was detected in the attached image.",
        "ocr_text_extracted": "Text was extracted from the image for analysis.",
        "visual_phishing_detected": "Visual analysis detected potential phishing markers.",
        "visual_credential_prompt": "The image contains elements that prompt for credentials or passwords.",
        "ATTACHMENT_TYPE_MISMATCH": "The attachment extension does not match its true detected file type.",
        "SUSPICIOUS_EXTENSION": "The attachment uses a high-risk or suspicious file extension.",
        "DOUBLE_EXTENSION": "The attachment uses a deceptive double file extension to conceal its true format.",
        "EXECUTABLE_ATTACHMENT": "The attachment is an executable binary or executable file format.",
        "SCRIPT_ATTACHMENT": "The attachment contains an executable script file capable of executing commands.",
        "MACRO_PRESENT": "The Office document attachment contains embedded VBA macros.",
        "EMBEDDED_SCRIPT": "The attachment contains embedded scripts or executable objects.",
        "NESTED_ARCHIVE": "The attachment archive contains one or more nested archives.",
        "SUSPICIOUS_ARCHIVE": "The attachment archive exhibits suspicious structural characteristics or payloads.",
        "ARCHIVE_DEPTH_ANOMALY": "The archive structure exceeds safe nesting depth limits.",
        "ARCHIVE_EXPANSION_ANOMALY": "The archive exhibits an unusually large compression expansion ratio.",
        "SUSPICIOUS_FILENAME": "The attachment filename matches deceptive phishing or malware lure patterns."
    }


    ACTION_MAPPING = {
        RiskClassification.SAFE: "Proceed with normal caution.",
        RiskClassification.SUSPICIOUS: "Exercise caution. Do not share sensitive information unless you are certain of the source.",
        RiskClassification.DECEPTIVE: "Do not trust this content. Avoid clicking links or downloading attachments.",
        RiskClassification.PHISHING: "Do not click any links or provide credentials. Report and delete this message.",
        RiskClassification.MALWARE: "Do not open or execute file/link. Isolate and permanently delete the content immediately."
    }

    @classmethod
    def explain(cls, assessment: RiskAssessment) -> RiskAssessment:
        reasons = []

        for flag in assessment.flags:
            if flag.startswith("nlp_"):
                category = flag.replace("nlp_", "").replace("_", " ")
                reasons.append(f"Natural language processing found signs of {category}.")
            elif flag.startswith("high_hyphen_count"):
                reasons.append("The URL contains an unusual number of hyphens, often used to spoof domains.")
            else:
                explanation = cls.FLAG_EXPLANATIONS.get(flag)
                if explanation:
                    reasons.append(explanation)

        for ev in assessment.evidence:
            if ev.description:
                reasons.append(ev.description)
            else:
                key_readable = ev.key.replace('_', ' ').capitalize()
                reasons.append(f"Evidence found - {key_readable}: {ev.value}.")

        unique_reasons = []
        for r in reasons:
            if r not in unique_reasons:
                unique_reasons.append(r)
        
        for w in getattr(assessment, "warnings", []):
            if w not in unique_reasons:
                unique_reasons.append(w)

        if "malware_engine" in assessment.ignored_engines:
            msg = "Malware scan unavailable: Anti-malware engine could not complete analysis."
            if not any("malware scan unavailable" in r.lower() for r in unique_reasons):
                unique_reasons.append(msg)

        if not unique_reasons:
            if assessment.classification == RiskClassification.SAFE:
                unique_reasons.append("No suspicious indicators were found.")
            else:
                unique_reasons.append("Assessed based on aggregate engine analysis without specific discrete flags.")

        if assessment.confidence < 0.5:
            unique_reasons.append("Note: The confidence of this scan is low due to missing or failed engine analyses.")

        if not assessment.contributing_engines:
            unique_reasons = ["No detection engines successfully analyzed this input."]
            
        assessment.reasons = unique_reasons

        default_action = cls.ACTION_MAPPING.get(
            assessment.classification, "Proceed with normal caution."
        )
        if assessment.classification == RiskClassification.SAFE and "malware_engine" in assessment.ignored_engines:
            default_action = "Proceed with caution. Malware scanning was unavailable for this file."
        assessment.recommended_action = default_action

        return assessment