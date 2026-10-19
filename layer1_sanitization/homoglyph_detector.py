# guardrail/layer1_sanitization/homoglyph_detector.py

import unicodedata
from typing import Dict, List, Tuple
from .config import SanitizationConfig, DEFAULT_CONFIG


class HomoglyphDetector:
    """
    Detects homoglyphs / confusables — visually identical characters from
    different scripts used to smuggle payloads past keyword filters.

    Example:
        'аdmin'  (Cyrillic 'а' U+0430) looks identical to 'admin'
    """

    def __init__(self, config: SanitizationConfig = DEFAULT_CONFIG):
        self.cfg = config
        # Build a lightweight confusable map from Unicode NFKC skeleton
        self._confusable_cache: Dict[str, str] = {}

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def detect(self, text: str) -> Tuple[str, Dict[str, str], float]:
        """
        Identify homoglyphs and normalize them to ASCII canonical form.

        Returns:
            (normalized_text, {original_char: replacement}, homoglyph_ratio)
        """
        if not text:
            return "", {}, 0.0

        out_chars: List[str] = []
        replacements: Dict[str, str] = {}
        homoglyph_count = 0
        total_alpha = 0

        for ch in text:
            if not ch.isalpha():
                out_chars.append(ch)
                continue

            total_alpha += 1
            canonical = self._to_ascii_confusable(ch)

            if canonical and canonical != ch:
                homoglyph_count += 1
                replacements[ch] = canonical
                out_chars.append(canonical)
            else:
                out_chars.append(ch)

        ratio = (homoglyph_count / total_alpha) if total_alpha else 0.0
        return "".join(out_chars), replacements, ratio

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #
    def _to_ascii_confusable(self, ch: str) -> str:
        """
        Map a character to its ASCII confusable using NFKC normalization
        combined with a curated mapping for known attack characters.
        """
        # Cache hit
        if ch in self._confusable_cache:
            return self._confusable_cache[ch]

        # 1) NFKC first — resolves many compatibility forms
        normalized = unicodedata.normalize("NFKC", ch)

        # 2) If NFKC already yields ASCII, we're done
        if len(normalized) == 1 and normalized.isascii():
            self._confusable_cache[ch] = normalized
            return normalized

        # 3) Curated high-risk Cyrillic / Greek → Latin mappings
        curated = self._curated_map()
        result = curated.get(ch, "")

        self._confusable_cache[ch] = result
        return result

    @staticmethod
    def _curated_map() -> Dict[str, str]:
        """Common homoglyph attack pairs (Cyrillic/Greek → Latin)."""
        return {
            # Cyrillic
            "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
            "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
            "У": "Y", "Х": "X",
            "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
            "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
            # Greek
            "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
            "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
            "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
            "ο": "o", "ρ": "p", "ν": "v",
            # Fullwidth Latin (NFKC handles most, but be explicit)
            "Ａ": "A", "ａ": "a",
        }