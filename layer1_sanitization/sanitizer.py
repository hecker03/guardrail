import hashlib
import time
from .config import SanitizationConfig, DEFAULT_CONFIG
from .models import (
    SanitizationResult, SanitizationAction, ThreatLevel, LexicalFindingResult,
)
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
        self.lexical_analyzer = LexicalAnalyzer()
        self.patterns = PatternMatcher(
            dictionary_path=config.SUSPICIOUS_TOKEN_DICTIONARY_PATH,
            lexical_analyzer=self.lexical_analyzer,
        )
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

        text, enc_stats, strip_stats, homoglyph_map, homoglyph_ratio, nfkc_changed = (
            self._canonicalize_view(raw_input)
        )

        # Build all bounded inspection views first. Stage 3 then applies the
        # same compiled token matcher and lexical analyzer to the normalized
        # primary text and to each separately normalized derived view.
        scan_views = [("normalized", text, None)]
        decoded_views = []
        inspection_views_scanned = ["normalized"]
        if self.cfg.INSPECT_ENCODINGS:
            for view in self.decoder.inspect(text):
                view_text, _, _, _, _, _ = self._canonicalize_view(view.text)
                if view.encoding == "leetspeak":
                    source_view = "leetspeak"
                    view_kind = "leetspeak"
                elif view.encoding.startswith("leetspeak:"):
                    encoding = view.encoding.split(":", 1)[1]
                    source_view = f"leetspeak:decoded:{encoding}"
                    view_kind = f"leetspeak:{encoding}"
                else:
                    source_view = f"decoded:{view.encoding}"
                    view_kind = view.encoding
                    decoded_views.append(view.encoding)
                scan_views.append((source_view, view_text, view_kind))
                inspection_views_scanned.append(source_view)

        matched_patterns = []
        pattern_score = 0.0
        lexical_findings = []
        for source_view, view_text, view_kind in scan_views:
            analysis = self.lexical_analyzer.analyze(view_text)
            view_matches, view_score = self.patterns.scan(view_text, analysis.tokens)
            pattern_score = max(pattern_score, view_score)
            for name in view_matches:
                if source_view == "normalized":
                    marker = name
                elif view_kind == "leetspeak" or view_kind.startswith("leetspeak:"):
                    marker = f"view_{view_kind}:{name}"
                else:
                    marker = f"decoded_{view_kind}:{name}"
                if marker not in matched_patterns:
                    matched_patterns.append(marker)
            lexical_findings.extend(
                self._serialize_lexical_analysis(analysis, source_view)
            )

        requires_context = bool(lexical_findings) or self.patterns.requires_context(matched_patterns)
        warnings = []
        if requires_context:
            warnings.append("candidate_requires_context")
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
        action = self._decide_action(
            threat_level=threat_level,
            matched_patterns=matched_patterns,
            requires_context=requires_context,
            threat_score=threat_score,
            modified=modified,
            strip_or_flag=self.cfg.STRIP_OR_FLAG,
        )

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
            inspection_views_scanned=inspection_views_scanned,
            lexical_findings=lexical_findings,
            requires_context=requires_context,
            transformations=transformations,
            original_sha256=original_hash,
            sanitized_sha256=self._hash(text),
            warnings=warnings,
            processing_time_ms=round(elapsed_ms, 3),
        )

    def _canonicalize_view(self, text: str):
        """Apply the same bounded Stage-2 cleanup to primary and derived views."""
        text, enc_stats = self.normalizer.clean_encoding(text)
        text, strip_stats = self.stripper.strip(text)
        text, homoglyph_map, homoglyph_ratio = self.homoglyphs.detect(text)
        text, nfkc_changed = self.normalizer.apply_nfkc_normalization(text)
        enc_stats["nfkc_changed"] = nfkc_changed
        return text, enc_stats, strip_stats, homoglyph_map, homoglyph_ratio, nfkc_changed

    @staticmethod
    def _serialize_lexical_analysis(analysis, source_view: str):
        """Serialize inspection-only candidates with offsets in their own view."""
        return [
            LexicalFindingResult(
                rule_id=finding.rule_id,
                start=finding.start,
                end=finding.end,
                token_start=finding.token_start,
                token_end=finding.token_end,
                match_basis=list(finding.match_basis),
                requires_context=finding.requires_context,
                source_view=source_view,
            )
            for finding in analysis.findings
        ]

    @staticmethod
    def _decide_action(
        *, threat_level, matched_patterns, requires_context,
        threat_score, modified, strip_or_flag,
    ):
        """Apply the Layer-1 PASS/SANITIZED/FLAGGED/REJECTED priority matrix."""
        if threat_level == ThreatLevel.CRITICAL or (
            threat_level == ThreatLevel.HIGH
            and (strip_or_flag == "reject" or bool(matched_patterns))
        ):
            return SanitizationAction.REJECTED
        if requires_context:
            return SanitizationAction.FLAGGED
        if threat_score > 0.0 or modified:
            return SanitizationAction.SANITIZED
        return SanitizationAction.PASS

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
