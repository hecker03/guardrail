# guardrail/layer5_output_filter/pii_masker.py

import hashlib
from typing import List, Tuple
from .config import OutputFilterConfig, DEFAULT_CONFIG
from .models import PIIMatch


class PIIMasker:
    """Masks detected PII using configurable strategies."""

    def __init__(self, config: OutputFilterConfig = DEFAULT_CONFIG):
        self.cfg = config

    def mask(self, text: str, matches: List[PIIMatch]) -> Tuple[str, List[PIIMatch]]:
        """
        Returns (masked_text, matches_with_masked_field).
        Applies from right to left to preserve indices.
        """
        if not matches:
            return text, []

        updated: List[PIIMatch] = []
        result = text
        for m in sorted(matches, key=lambda x: x.start, reverse=True):
            masked = self._mask_value(m.snippet, m.pii_type)
            result = result[:m.start] + masked + result[m.end:]
            m.masked = masked
            updated.append(m)

        updated.reverse()
        return result, updated

    def _mask_value(self, value: str, pii_type: str) -> str:
        style = self.cfg.MASK_STYLE

        if style == "full":
            return self.cfg.MASK_CHAR * len(value)

        if style == "hash":
            h = hashlib.sha256(
                (self.cfg.HASH_SALT + value).encode()
            ).hexdigest()[:12]
            return f"<{pii_type}:{h}>"

        # partial (default)
        keep = self.cfg.MASK_KEEP_LAST
        if len(value) <= keep:
            return self.cfg.MASK_CHAR * len(value)
        return (
            self.cfg.MASK_CHAR * (len(value) - keep)
            + value[-keep:]
        )