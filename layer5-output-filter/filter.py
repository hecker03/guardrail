# guardrail/layer5_output_filter/filter.py

import time
from typing import Optional, Dict
from .config import OutputFilterConfig, DEFAULT_CONFIG
from .models import OutputFilterResult, FilterAction, PIIMatch
from .pii_detector import PIIDetector
from .pii_masker import PIIMasker
from .echo_detector import PromptEchoDetector
from .exfil_guard import ExfiltrationGuard


class OutputFilter:
    """
    Layer 5 — GuardRail Output Filtering.

    Pipeline:
        1. Length guard
        2. PII detection + masking
        3. Prompt-echo detection
        4. Exfiltration guard (URLs, beacons, blobs)
        5. Action decision: PASS / REDACTED / BLOCKED
    """

    def __init__(
        self,
        config: OutputFilterConfig = DEFAULT_CONFIG,
        use_ner: bool = False,
    ):
        self.cfg = config
        self.detector = PIIDetector(use_ner=use_ner)
        self.masker = PIIMasker(config)
        self.echo = PromptEchoDetector(config)
        self.exfil = ExfiltrationGuard(config)

    # ------------------------------------------------------------------ #
    def filter(
        self,
        output: str,
        system_prompt: str = "",
        user_input: str = "",
    ) -> OutputFilterResult:
        start = time.perf_counter()

        if output is None:
            output = ""

        original_length = len(output)
        warnings = []

        # ---- 1) Length guard ----
        if original_length > self.cfg.MAX_OUTPUT_LENGTH:
            output = output[: self.cfg.MAX_OUTPUT_LENGTH]
            warnings.append("output_truncated")

        # ---- 2) PII ----
        pii_matches = self.detector.detect(output)
        filtered_text, pii_matches = self.masker.mask(output, pii_matches)
        pii_types: Dict[str, int] = {}
        for m in pii_matches:
            pii_types[m.pii_type] = pii_types.get(m.pii_type, 0) + 1

        # ---- 3) Echo ----
        echo_detected, echo_sim = self.echo.detect(filtered_text, system_prompt)
        if echo_detected and self.cfg.REDACT_ON_ECHO:
            filtered_text = "[REDACTED: prompt echo detected]"
            warnings.append("prompt_echo_redacted")

        # ---- 4) Exfiltration ----
        exfil_score, exfil_reasons, blocked_urls = self.exfil.scan(
            filtered_text, user_input
        )
        if blocked_urls:
            for u in blocked_urls:
                filtered_text = filtered_text.replace(u, "[BLOCKED_URL]")

        # ---- 5) Action ----
        if exfil_score >= 0.85 and self.cfg.REJECT_ON_EXFIL:
            action = FilterAction.BLOCKED
            filtered_text = ""
        elif pii_matches or echo_detected or exfil_reasons:
            action = FilterAction.REDACTED
        else:
            action = FilterAction.PASS

        elapsed_ms = (time.perf_counter() - start) * 1000

        return OutputFilterResult(
            filtered_text=filtered_text,
            action=action,
            pii_matches=pii_matches,
            pii_count=len(pii_matches),
            pii_types=pii_types,
            echo_detected=echo_detected,
            echo_similarity=round(echo_sim, 4),
            exfil_risk_score=round(exfil_score, 4),
            exfil_reasons=exfil_reasons,
            blocked_urls=blocked_urls,
            original_length=original_length,
            filtered_length=len(filtered_text),
            warnings=warnings,
            processing_time_ms=round(elapsed_ms, 3),
        )