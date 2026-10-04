from datetime import datetime, timezone
import time
from typing import Any

from app.engines.base_engine import BaseEngine
from app.engines.registry import engine_registry
from app.models.engine_result import EngineResult, EngineStatus, EvidenceItem
from app.models.scan_input import ScanInput

class HeaderAnalysisEngine(BaseEngine):
    @property
    def name(self) -> str:
        return "header_analysis_engine"

    def _extract_email(self, raw: str) -> str:
        if not raw:
            return ""
        # Simple extraction: if <email@domain.com> is present, extract it
        import re
        match = re.search(r'<([^>]+)>', str(raw))
        email = match.group(1) if match else str(raw)
        return email.strip().lower()

    def _extract_domain(self, email: str) -> str:
        if not email:
            return ""
        return email.split("@")[-1] if "@" in email else email

    async def analyze(self, input_data: ScanInput) -> EngineResult:
        metadata = input_data.metadata or {}
        headers = metadata.get("headers", {})
        
        # Fall back to flat metadata if headers dict not specifically used
        def get_header(keys):
            for k in keys:
                if k in headers:
                    return headers[k]
                if k in metadata:
                    return metadata[k]
            return None

        # Gather inputs
        from_header = get_header(["From", "from", "From-Address"]) or input_data.sender_id
        reply_to = get_header(["Reply-To", "reply_to", "reply-to"])
        return_path = get_header(["Return-Path", "return_path", "return-path"])
        message_id = get_header(["Message-ID", "message_id", "message-id"])
        date_str = get_header(["Date", "date"])
        auth_results = get_header(["Authentication-Results", "auth_results", "authentication-results"])
        spf_res = get_header(["spf", "SPF"])
        dkim_res = get_header(["dkim", "DKIM"])
        dmarc_res = get_header(["dmarc", "DMARC"])
        received = get_header(["Received", "received"])

        if not any([reply_to, return_path, message_id, date_str, auth_results, spf_res, dkim_res, dmarc_res, received]):
            return EngineResult.skipped(self.name, "No normalized header metadata found")

        flags = []
        evidence = []
        score_accumulator = 0.0
        
        from_email = self._extract_email(from_header or "")
        from_domain = self._extract_domain(from_email)

        # 1. REPLY_TO_MISMATCH
        if reply_to:
            reply_to_email = self._extract_email(reply_to)
            # If the reply_to email differs from the sender email
            if from_email and reply_to_email and reply_to_email != from_email:
                # If they belong to the same domain, give a partial score, or less. We will be deterministic.
                reply_to_domain = self._extract_domain(reply_to_email)
                if from_domain and reply_to_domain and reply_to_domain != from_domain:
                    flags.append("REPLY_TO_MISMATCH")
                    score_accumulator += 0.3
                    evidence.append(EvidenceItem(
                        key="reply_to_mismatch",
                        value=reply_to,
                        description=f"Reply-To domain ({reply_to_domain}) differs from From domain ({from_domain})"
                    ))
                else:
                    flags.append("REPLY_TO_MISMATCH")
                    score_accumulator += 0.1
                    evidence.append(EvidenceItem(
                        key="reply_to_mismatch",
                        value=reply_to,
                        description=f"Reply-To email ({reply_to_email}) differs from From email ({from_email})"
                    ))

        # 2. RETURN_PATH_MISMATCH
        if return_path:
            return_email = self._extract_email(return_path)
            return_domain = self._extract_domain(return_email)
            if from_domain and return_domain and return_domain != from_domain:
                flags.append("RETURN_PATH_MISMATCH")
                score_accumulator += 0.3
                evidence.append(EvidenceItem(
                    key="return_path_mismatch",
                    value=return_path,
                    description=f"Return-Path domain ({return_domain}) differs from From domain ({from_domain})"
                ))

        # 3. AUTHENTICATION FAILURES (SPF, DKIM, DMARC)
        auth_failures = []
        if str(spf_res).lower() in ["fail", "softfail", "hardfail"]:
            auth_failures.append("SPF")
            flags.append("SPF_FAILURE")
        if str(dkim_res).lower() in ["fail", "hardfail"]:
            auth_failures.append("DKIM")
            flags.append("DKIM_FAILURE")
        if str(dmarc_res).lower() in ["fail", "reject", "quarantine"]:
            auth_failures.append("DMARC")
            flags.append("DMARC_FAILURE")
            
        if auth_results and isinstance(auth_results, str):
            auth_lower = auth_results.lower()
            if "fail" in auth_lower and "spf" in auth_lower and "SPF" not in auth_failures:
                auth_failures.append("SPF")
                flags.append("SPF_FAILURE")
            if "fail" in auth_lower and "dkim" in auth_lower and "DKIM" not in auth_failures:
                auth_failures.append("DKIM")
                flags.append("DKIM_FAILURE")
            if "fail" in auth_lower and "dmarc" in auth_lower and "DMARC" not in auth_failures:
                auth_failures.append("DMARC")
                flags.append("DMARC_FAILURE")
            
        if auth_failures:
            flags.append("AUTHENTICATION_FAILURE")
            score_accumulator += 0.4
            evidence.append(EvidenceItem(
                key="authentication_failure",
                value=",".join(auth_failures),
                description=f"Authentication failed for: {', '.join(auth_failures)}"
            ))

        # 4. MESSAGE_ID_ANOMALY
        if message_id is not None:
             if not str(message_id).strip():
                 flags.append("MESSAGE_ID_ANOMALY")
                 score_accumulator += 0.1
                 evidence.append(EvidenceItem(
                     key="message_id_anomaly",
                     value="",
                     description="Message-ID header is missing or empty"
                 ))
             else:
                 msg_id_domain = self._extract_domain(self._extract_email(str(message_id)))
                 if from_domain and msg_id_domain and msg_id_domain != from_domain:
                     flags.append("MESSAGE_ID_ANOMALY")
                     score_accumulator += 0.1
                     evidence.append(EvidenceItem(
                         key="message_id_anomaly",
                         value=str(message_id),
                         description=f"Message-ID domain ({msg_id_domain}) does not match sender domain ({from_domain})"
                     ))
        else:
            # message_id missing anomaly
            flags.append("MESSAGE_ID_ANOMALY")
            score_accumulator += 0.1
            evidence.append(EvidenceItem(
                 key="message_id_anomaly",
                 value="",
                 description="Message-ID header is missing entirely"
            ))

        # 5. TIMESTAMP_ANOMALY
        reference_ts = metadata.get("timestamp")
        if reference_ts and isinstance(reference_ts, (int, float)):
            email_ts = None
            if date_str:
                import email.utils
                try:
                    parsed_dt = email.utils.parsedate_to_datetime(str(date_str))
                    email_ts = parsed_dt.timestamp()
                except (TypeError, ValueError, AttributeError):
                    email_ts = None
            
            if email_ts is not None:
                # 7 days difference
                if abs(reference_ts - email_ts) > 86400 * 7:
                    flags.append("TIMESTAMP_ANOMALY")
                    score_accumulator += 0.2
                    evidence.append(EvidenceItem(
                        key="timestamp_anomaly",
                        value=str(date_str),
                        description="Email Date header differs significantly from scan reference time"
                    ))

        # 6. RECEIVED_CHAIN_ANOMALY
        if received:
            if isinstance(received, list) and not received:
                pass
            elif isinstance(received, str) and "forged" in received.lower():
                 flags.append("RECEIVED_CHAIN_ANOMALY")
                 score_accumulator += 0.3
                 evidence.append(EvidenceItem(
                     key="received_chain_anomaly",
                     value="forged",
                     description="Received chain contains signs of forging"
                 ))
            elif isinstance(received, list) and any("forged" in str(r).lower() or "suspicious" in str(r).lower() for r in received):
                 flags.append("RECEIVED_CHAIN_ANOMALY")
                 score_accumulator += 0.3
                 evidence.append(EvidenceItem(
                     key="received_chain_anomaly",
                     value="suspicious",
                     description="Received chain indicates suspicious hops"
                 ))

        risk_score = min(score_accumulator, 0.9) # Hard cap so that it doesn't cross Malware threshold by itself merely from headers
        
        # Confidence calculation
        confidence = 0.8 if len(flags) > 0 else 1.0

        if not flags:
            return self._build_result(
                risk_score=0.0,
                confidence=1.0,
                flags=[],
                evidence=[],
                status=EngineStatus.SUCCESS
            )
            
        return self._build_result(
            risk_score=risk_score * 100.0,
            confidence=confidence,
            flags=flags,
            evidence=evidence,
            status=EngineStatus.SUCCESS,
            metadata={"anomalies_detected": len(flags)}
        )

# Register the engine exactly once
engine_registry.register(HeaderAnalysisEngine())
