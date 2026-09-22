# guardrail/layer1_sanitization/unicode_stripper.py

import unicodedata
from typing import Tuple, List, Set
from .config import SanitizationConfig, DEFAULT_CONFIG


class UnicodeStripper:
    """
    Strips invisible Unicode payloads used to bypass string filters.

    Key attack vectors covered:
      - Unicode Tag block (U+E0000–U+E007F)  → hidden ASCII smuggling
      - Variation Selectors Supplement       → covert channels
      - Zero-width characters                → tokenizer bypass
      - Bidi controls                        → visual spoofing
      - Other Cc/Cf control characters       → injection markers
    """

    def __init__(self, config: SanitizationConfig = DEFAULT_CONFIG):
        self.cfg = config

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def strip(self, text: str) -> Tuple[str, dict]:
        """
        Remove all invisible / non-rendering payloads.

        Returns:
            (cleaned_text, stats_dict)
        """
        if not text:
            return "", self._empty_stats()

        # Precompute: fast-set of zero-width chars for O(1) lookup
        zw_set: Set[str] = set(self.cfg.ZERO_WIDTH_CHARS)
        bidi_set: Set[str] = set(self.cfg.BIDI_CONTROLS)

        out_chars: List[str] = []
        stats = self._empty_stats()

        for ch in text:
            cp = ord(ch)

            # 1) Unicode Tag block (U+E0000–U+E007F)
            if self.cfg.UNICODE_TAG_START <= cp <= self.cfg.UNICODE_TAG_END:
                stats["unicode_tags"] += 1
                continue

            # 2) Variation Selectors Supplement
            if self.cfg.VS_SUPPLEMENT_START <= cp <= self.cfg.VS_SUPPLEMENT_END:
                stats["unicode_tags"] += 1
                continue

            # 3) Zero-width / invisible
            if ch in zw_set:
                stats["zero_width"] += 1
                continue

            # 4) Bidi controls
            if ch in bidi_set:
                stats["bidi_controls"] += 1
                continue

            # 5) Other control characters (except \t, \n, \r)
            cat = unicodedata.category(ch)
            if cat in ("Cc", "Cf") and ch not in ("\t", "\n", "\r"):
                stats["control_chars"] += 1
                continue

            out_chars.append(ch)

        cleaned = "".join(out_chars)
        return cleaned, stats

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _empty_stats() -> dict:
        return {
            "unicode_tags": 0,
            "zero_width": 0,
            "bidi_controls": 0,
            "control_chars": 0,
        }

    # ------------------------------------------------------------------ #
    # Diagnostics
    # ------------------------------------------------------------------ #
    @staticmethod
    def find_unicode_tags(text: str) -> List[int]:
        """Return positions of every Unicode tag character (for forensics)."""
        return [
            i for i, ch in enumerate(text)
            if 0xE0000 <= ord(ch) <= 0xE007F
            or 0xE0100 <= ord(ch) <= 0xE01EF
        ]