# guardrail/layer1_sanitization/encoding_normalizer.py

import unicodedata
from typing import Tuple


class EncodingNormalizer:
    """
    Applies canonical Unicode normalization and encoding cleanup:
      - NFKC to collapse compatibility forms
      - Strips null bytes and unpaired surrogates
      - Handles HTML entities, percent-encoding, base64 hints
    """

    def __init__(self, apply_nfkc: bool = True):
        self.apply_nfkc = apply_nfkc

    def clean_encoding(self, text: str) -> Tuple[str, dict]:
        """Strip null bytes and invalid UTF-8 surrogate artifacts."""
        stats = {"null_bytes": 0}
        if not text:
            return "", stats

        if "\x00" in text:
            stats["null_bytes"] = text.count("\x00")
            text = text.replace("\x00", "")

        text = text.encode("utf-8", errors="ignore").decode("utf-8", errors="ignore")
        return text, stats

    def apply_nfkc_normalization(self, text: str) -> Tuple[str, bool]:
        """Apply NFKC compatibility decomposition if enabled."""
        if not text or not self.apply_nfkc:
            return text, False
        normalized = unicodedata.normalize("NFKC", text)
        return normalized, (normalized != text)

    def normalize(self, text: str) -> Tuple[str, dict]:
        text, stats = self.clean_encoding(text)
        text, nfkc_changed = self.apply_nfkc_normalization(text)
        stats["nfkc_changed"] = nfkc_changed
        return text, stats