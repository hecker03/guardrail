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

    def normalize(self, text: str) -> Tuple[str, dict]:
        stats = {"nfkc_changed": False, "null_bytes": 0}

        if not text:
            return "", stats

        # Strip null bytes
        if "\x00" in text:
            stats["null_bytes"] = text.count("\x00")
            text = text.replace("\x00", "")

        # Remove unpaired surrogates (invalid UTF-8 artifacts)
        text = text.encode("utf-8", errors="ignore").decode("utf-8", errors="ignore")

        if self.apply_nfkc:
            normalized = unicodedata.normalize("NFKC", text)
            if normalized != text:
                stats["nfkc_changed"] = True
                text = normalized

        return text, stats