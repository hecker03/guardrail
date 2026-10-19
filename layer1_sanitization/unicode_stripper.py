import unicodedata
from typing import Tuple, List, Set
from .config import SanitizationConfig, DEFAULT_CONFIG


class UnicodeStripper:
    """Remove high-risk invisible controls while preserving legitimate joiners."""

    def __init__(self, config: SanitizationConfig = DEFAULT_CONFIG):
        self.cfg = config

    def strip(self, text: str) -> Tuple[str, dict]:
        if not text:
            return "", self._empty_stats()

        zw_set: Set[str] = set(self.cfg.ZERO_WIDTH_CHARS)
        joiners: Set[str] = set(self.cfg.LANGUAGE_JOINERS)
        bidi_set: Set[str] = set(self.cfg.BIDI_CONTROLS)
        out_chars: List[str] = []
        stats = self._empty_stats()

        for index, ch in enumerate(text):
            cp = ord(ch)
            if self.cfg.UNICODE_TAG_START <= cp <= self.cfg.UNICODE_TAG_END:
                stats["unicode_tags"] += 1
                continue
            if self.cfg.VS_SUPPLEMENT_START <= cp <= self.cfg.VS_SUPPLEMENT_END:
                stats["unicode_tags"] += 1
                continue
            if ch in zw_set:
                stats["zero_width"] += 1
                continue
            if ch in joiners:
                # Joiners inside ASCII tokens are a common keyword-splitting bypass.
                # Outside ASCII tokens they are preserved for multilingual correctness.
                prev_ch = text[index - 1] if index else ""
                next_ch = text[index + 1] if index + 1 < len(text) else ""
                if self._ascii_word(prev_ch) or self._ascii_word(next_ch):
                    stats["zero_width"] += 1
                    continue
                stats["preserved_join_controls"] += 1
                out_chars.append(ch)
                continue
            if ch in bidi_set:
                stats["bidi_controls"] += 1
                continue
            category = unicodedata.category(ch)
            if category in ("Cc", "Cf") and ch not in ("\t", "\n", "\r"):
                stats["control_chars"] += 1
                continue
            out_chars.append(ch)

        return "".join(out_chars), stats

    @staticmethod
    def _ascii_word(ch: str) -> bool:
        return bool(ch) and ch.isascii() and ch.isalnum()

    @staticmethod
    def _empty_stats() -> dict:
        return {
            "unicode_tags": 0,
            "zero_width": 0,
            "bidi_controls": 0,
            "control_chars": 0,
            "preserved_join_controls": 0,
        }

    @staticmethod
    def find_unicode_tags(text: str) -> List[int]:
        return [
            i for i, ch in enumerate(text)
            if 0xE0000 <= ord(ch) <= 0xE007F
            or 0xE0100 <= ord(ch) <= 0xE01EF
        ]
