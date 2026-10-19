import time
from typing import Optional, Dict
from .config import OutputFilterConfig, DEFAULT_CONFIG
from .models import OutputFilterResult, FilterAction
from .pii_detector import PIIDetector
from .pii_masker import PIIMasker
from .echo_detector import PromptEchoDetector
from .exfil_guard import ExfiltrationGuard


class OutputFilter:
    """Layer 5 deterministic output inspection and redaction."""

    def __init__(self, config: OutputFilterConfig = DEFAULT_CONFIG, use_ner: bool = False):
        self.cfg = config
        self.detector = PIIDetector(use_ner=use_ner)
        self.masker = PIIMasker(config)
        self.echo = PromptEchoDetector(config)
        self.exfil = ExfiltrationGuard(config)

    def filter(self, output: str, system_prompt: str = "", user_input: str = "") -> OutputFilterResult:
        start = time.perf_counter()
        output = "" if output is None else output
        original_length = len(output)
        warnings = []
        truncated = original_length > self.cfg.MAX_OUTPUT_LENGTH
        if truncated:
            output = output[: self.cfg.MAX_OUTPUT_LENGTH]
            warnings.append("output_truncated")

        pii_matches = self.detector.detect(output)
        filtered_text, pii_matches = self.masker.mask(output, pii_matches)
        pii_types: Dict[str, int] = {}
        for match in pii_matches:
            pii_types[match.pii_type] = pii_types.get(match.pii_type, 0) + 1

        echo_detected, echo_similarity = self.echo.detect(filtered_text, system_prompt)
        if echo_detected and self.cfg.REDACT_ON_ECHO:
            filtered_text = "[REDACTED: prompt echo detected]"
            warnings.append("prompt_echo_redacted")

        exfil_score, exfil_reasons, raw_blocked_urls = self.exfil.scan(filtered_text, user_input)
        for url in raw_blocked_urls:
            filtered_text = filtered_text.replace(url, "[BLOCKED_URL]")
        safe_blocked_urls = [self.exfil.safe_url(url) for url in raw_blocked_urls]

        if exfil_score >= 0.85 and self.cfg.REJECT_ON_EXFIL:
            action = FilterAction.BLOCKED
            filtered_text = ""
        elif pii_matches or echo_detected or exfil_reasons or truncated:
            action = FilterAction.REDACTED
        else:
            action = FilterAction.PASS

        return OutputFilterResult(
            filtered_text=filtered_text,
            action=action,
            pii_matches=pii_matches,
            pii_count=len(pii_matches),
            pii_types=pii_types,
            echo_detected=echo_detected,
            echo_similarity=round(echo_similarity, 4),
            exfil_risk_score=round(exfil_score, 4),
            exfil_reasons=exfil_reasons,
            blocked_urls=safe_blocked_urls,
            original_length=original_length,
            filtered_length=len(filtered_text),
            warnings=warnings,
            processing_time_ms=round((time.perf_counter() - start) * 1000, 3),
        )
