# guardrail/layer1_sanitization/sanitizer.py

import time
from typing import Optional
from .config import SanitizationConfig, DEFAULT_CONFIG
from .models import SanitizationResult, SanitizationAction, ThreatLevel
from .unicode_stripper import UnicodeStripper
from .homoglyph_detector import HomoglyphDetector
from .encoding_normalizer import EncodingNormalizer
from .patterns import PatternMatcher


class InputSanitizer:
    """
    Layer 1 — GuardRail Input Sanitization.

    Pipeline:
        1. Length guard
        2. Encoding normalization (NFKC, null bytes)
        3. Unicode tag / zero-width / bidi stripping
        4. Homoglyph normalization
        5. Pattern-based injection detection
        6. Threat scoring & action decision
    """

    def __init__(self, config: SanitizationConfig = DEFAULT_CONFIG):
        self.cfg = config
        self.stripper = UnicodeStripper(config)
        self.homoglyphs = HomoglyphDetector(config)
        self.normalizer = EncodingNormalizer(apply_nfkc=config.NORMALIZE_UNICODE)
        self.patterns = PatternMatcher()

    # ------------------------------------------------------------------ #
    # Public entry point
    # ------------------------------------------------------------------ #
    def sanitize(self, raw_input: str) -> SanitizationResult:
        start = time.perf_counter()

        if raw_input is None:
            raw_input = ""

        original_length = len(raw_input)

        # ---- 1) Hard length cap --------------------------------------
        if original_length > self.cfg.MAX_INPUT_LENGTH:
            return self._reject(
                raw_input,
                original_length,
                reason="input_too_long",
                score=1.0,
            )

        # ---- 2) Encoding normalization -------------------------------
        text, enc_stats = self.normalizer.normalize(raw_input)

        # ---- 3) Unicode stripping ------------------------------------
        text, strip_stats = self.stripper.strip(text)

        # ---- 4) Homoglyph detection ----------------------------------
        text, homoglyph_map, homoglyph_ratio = self.homoglyphs.detect(text)

        # ---- 5) Pattern scan -----------------------------------------
        matched_patterns, pattern_score = self.patterns.scan(text)

        # ---- 6) Ratio-based heuristics -------------------------------
        warnings = []
        zero_width_ratio = (
            strip_stats["zero_width"] / original_length
            if original_length else 0.0
        )
        if zero_width_ratio > self.cfg.MAX_ZERO_WIDTH_RATIO:
            warnings.append(f"high_zero_width_ratio={zero_width_ratio:.2f}")

        if homoglyph_ratio > self.cfg.MAX_HOMOGLYPH_RATIO:
            warnings.append(f"high_homoglyph_ratio={homoglyph_ratio:.2f}")

        # ---- 7) Threat scoring ---------------------------------------
        threat_score = self._compute_score(
            pattern_score=pattern_score,
            zero_width_ratio=zero_width_ratio,
            homoglyph_ratio=homoglyph_ratio,
            removed_tags=strip_stats["unicode_tags"],
            removed_bidi=strip_stats["bidi_controls"],
        )

        threat_level = self._score_to_level(threat_score)
        action = (
            SanitizationAction.REJECTED
            if threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL)
            and self.cfg.STRIP_OR_FLAG == "reject"
            else SanitizationAction.SANITIZED
            if threat_score > 0.0 or self._was_modified(enc_stats, strip_stats, homoglyph_map)
            else SanitizationAction.PASS
        )

        elapsed_ms = (time.perf_counter() - start) * 1000

        return SanitizationResult(
            original_length=original_length,
            sanitized_text=text if action != SanitizationAction.REJECTED else "",
            action=action,
            threat_level=threat_level,
            threat_score=round(threat_score, 4),
            removed_unicode_tags=strip_stats["unicode_tags"],
            removed_zero_width=strip_stats["zero_width"],
            removed_bidi_controls=strip_stats["bidi_controls"],
            removed_control_chars=strip_stats["control_chars"],
            homoglyphs_detected=homoglyph_map,
            patterns_matched=matched_patterns,
            warnings=warnings,
            processing_time_ms=round(elapsed_ms, 3),
        )

    # ------------------------------------------------------------------ #
    # Scoring
    # ------------------------------------------------------------------ #
    @staticmethod
    def _compute_score(
        pattern_score: float,
        zero_width_ratio: float,
        homoglyph_ratio: float,
        removed_tags: int,
        removed_bidi: int,
    ) -> float:
        """Weighted combination → [0.0, 1.0]."""
        score = pattern_score  # patterns are the strongest signal

        # Hidden payload boost
        if removed_tags > 0:
            score = max(score, min(1.0, 0.5 + 0.05 * removed_tags))
        if removed_bidi > 0:
            score = max(score, 0.7)

        # Ratio-based boosts (capped)
        score = max(score, min(0.6, zero_width_ratio * 4))
        score = max(score, min(0.6, homoglyph_ratio * 3))

        return min(1.0, score)

    @staticmethod
    def _score_to_level(score: float) -> ThreatLevel:
        if score >= 0.85:
            return ThreatLevel.CRITICAL
        if score >= 0.65:
            return ThreatLevel.HIGH
        if score >= 0.35:
            return ThreatLevel.MEDIUM
        if score > 0.0:
            return ThreatLevel.LOW
        return ThreatLevel.CLEAN

    @staticmethod
    def _was_modified(enc_stats, strip_stats, homoglyph_map) -> bool:
        return (
            enc_stats.get("nfkc_changed", False)
            or enc_stats.get("null_bytes", 0) > 0
            or any(strip_stats.values())
            or bool(homoglyph_map)
        )

    def _reject(
        self, raw: str, length: int, reason: str, score: float
    ) -> SanitizationResult:
        return SanitizationResult(
            original_length=length,
            sanitized_text="",
            action=SanitizationAction.REJECTED,
            threat_level=ThreatLevel.CRITICAL,
            threat_score=score,
            warnings=[reason],
        )