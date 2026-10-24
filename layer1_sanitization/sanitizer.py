import hashlib
import time
from .config import SanitizationConfig, DEFAULT_CONFIG
from .models import SanitizationResult, SanitizationAction, ThreatLevel
from .unicode_stripper import UnicodeStripper
from .homoglyph_detector import HomoglyphDetector
from .encoding_normalizer import EncodingNormalizer
from .patterns import PatternMatcher
from .decoder_inspector import BoundedDecoderInspector
from .lexical_analyzer import LexicalAnalyzer


class InputSanitizer:
    """Layer 1: bounded canonicalisation, indicator detection, and audit metadata.

    Encoded material is decoded once into bounded inspection-only views. Decoded
    content is never executed, recursively decoded, or silently substituted.
    """

    def __init__(self, config: SanitizationConfig = DEFAULT_CONFIG):
        if config.STRIP_OR_FLAG not in {"sanitize", "reject"}:
            raise ValueError("STRIP_OR_FLAG must be 'sanitize' or 'reject'")
        self.cfg = config
        self.stripper = UnicodeStripper(config)
        self.homoglyphs = HomoglyphDetector(config)
        self.normalizer = EncodingNormalizer(apply_nfkc=config.NORMALIZE_UNICODE)
        self.patterns = PatternMatcher()
        self.decoder = BoundedDecoderInspector(
            max_source_chars=config.MAX_INPUT_LENGTH,
            max_candidates=config.MAX_DECODE_CANDIDATES,
            max_decoded_chars=config.MAX_DECODED_CHARS,
        )

    def sanitize(self, raw_input: str) -> SanitizationResult:
        start = time.perf_counter()
        raw_input = "" if raw_input is None else raw_input
        original_length = len(raw_input)
        original_hash = self._hash(raw_input)

        if original_length > self.cfg.MAX_INPUT_LENGTH:
            return self._reject(original_length, "input_too_long", 1.0, original_hash, start)

        text, enc_stats = self.normalizer.clean_encoding(raw_input)
        text, strip_stats = self.stripper.strip(text)
        text, homoglyph_map, homoglyph_ratio = self.homoglyphs.detect(text)
        text, nfkc_changed = self.normalizer.apply_nfkc_normalization(text)
        enc_stats["nfkc_changed"] = nfkc_changed

        matched_patterns, pattern_score = self.patterns.scan(text)
        decoded_views = []
        if self.cfg.INSPECT_ENCODINGS:
            for view in self.decoder.inspect(text):
                decoded_views.append(view.encoding)
                decoded_matches, decoded_score = self.patterns.scan(view.text)
                for name in decoded_matches:
                    marker = f"decoded_{view.encoding}:{name}"
                    if marker not in matched_patterns:
                        matched_patterns.append(marker)
                pattern_score = max(pattern_score, decoded_score)

        warnings = []
        zero_width_ratio = strip_stats["zero_width"] / original_length if original_length else 0.0
        if zero_width_ratio > self.cfg.MAX_ZERO_WIDTH_RATIO:
            warnings.append(f"high_zero_width_ratio={zero_width_ratio:.2f}")
        if homoglyph_ratio > self.cfg.MAX_HOMOGLYPH_RATIO:
            warnings.append(f"high_homoglyph_ratio={homoglyph_ratio:.2f}")
        if strip_stats["preserved_join_controls"]:
            warnings.append("language_joiners_preserved")

        threat_score = self._compute_score(
            pattern_score, zero_width_ratio, homoglyph_ratio,
            strip_stats["unicode_tags"], strip_stats["bidi_controls"],
        )
        threat_level = self._score_to_level(threat_score)
        modified = self._was_modified(enc_stats, strip_stats, homoglyph_map)
        if threat_level == ThreatLevel.CRITICAL or (
            threat_level == ThreatLevel.HIGH
            and (self.cfg.STRIP_OR_FLAG == "reject" or bool(matched_patterns))
        ):
            action = SanitizationAction.REJECTED
        elif threat_score > 0.0 or modified:
            action = SanitizationAction.SANITIZED
        else:
            action = SanitizationAction.PASS

        transformations = []
        if enc_stats.get("null_bytes"):
            transformations.append("removed_null_bytes")
        if strip_stats["unicode_tags"]:
            transformations.append("removed_unicode_tags_or_variation_selectors")
        if strip_stats["zero_width"]:
            transformations.append("removed_unsafe_invisible_characters")
        if strip_stats["bidi_controls"]:
            transformations.append("removed_bidi_controls")
        if strip_stats["control_chars"]:
            transformations.append("removed_control_characters")
        if homoglyph_map:
            transformations.append("mapped_curated_confusables")
        if nfkc_changed:
            transformations.append("applied_nfkc")

        elapsed_ms = (time.perf_counter() - start) * 1000
        visible_text = text if action != SanitizationAction.REJECTED else ""
        return SanitizationResult(
            original_length=original_length,
            sanitized_text=visible_text,
            action=action,
            threat_level=threat_level,
            threat_score=round(threat_score, 4),
            removed_unicode_tags=strip_stats["unicode_tags"],
            removed_zero_width=strip_stats["zero_width"],
            removed_bidi_controls=strip_stats["bidi_controls"],
            removed_control_chars=strip_stats["control_chars"],
            preserved_join_controls=strip_stats["preserved_join_controls"],
            homoglyphs_detected=homoglyph_map,
            patterns_matched=matched_patterns,
            decoded_views_scanned=sorted(set(decoded_views)),
            transformations=transformations,
            original_sha256=original_hash,
            sanitized_sha256=self._hash(text),
            warnings=warnings,
            processing_time_ms=round(elapsed_ms, 3),
        )

    @staticmethod
    def _compute_score(pattern_score, zero_width_ratio, homoglyph_ratio, removed_tags, removed_bidi):
        score = pattern_score
        if removed_tags > 0:
            score = max(score, min(1.0, 0.65 + 0.05 * removed_tags))
        if removed_bidi > 0:
            score = max(score, 0.7)
        score = max(score, min(0.6, zero_width_ratio * 4))
        score = max(score, min(0.6, homoglyph_ratio * 3))
        return min(1.0, score)

    @staticmethod
    def _score_to_level(score):
        if score >= 0.85:
            return ThreatLevel.CRITICAL
        if score >= 0.65:
            return ThreatLevel.HIGH
        if score >= 0.35:
            return ThreatLevel.MEDIUM
        return ThreatLevel.LOW if score > 0.0 else ThreatLevel.CLEAN

    @staticmethod
    def _was_modified(enc_stats, strip_stats, homoglyph_map):
        removed = any(strip_stats.get(k, 0) for k in (
            "unicode_tags", "zero_width", "bidi_controls", "control_chars"
        ))
        return bool(enc_stats.get("nfkc_changed") or enc_stats.get("null_bytes") or removed or homoglyph_map)

    @staticmethod
    def _hash(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()

    def _reject(self, length, reason, score, original_hash, start):
        return SanitizationResult(
            original_length=length,
            sanitized_text="",
            action=SanitizationAction.REJECTED,
            threat_level=ThreatLevel.CRITICAL,
            threat_score=score,
            original_sha256=original_hash,
            warnings=[reason],
            processing_time_ms=round((time.perf_counter() - start) * 1000, 3),
        )
