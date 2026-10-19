import hashlib
import hmac
import os
from typing import List, Tuple
from .config import OutputFilterConfig, DEFAULT_CONFIG
from .models import PIIMatch


class PIIMasker:
    """Mask PII and erase raw snippets before returning forensic metadata."""

    def __init__(self, config: OutputFilterConfig = DEFAULT_CONFIG):
        self.cfg = config
        self._fingerprint_key = os.getenv("GUARDRAIL_PII_HASH_KEY", config.HASH_SALT).encode()

    def mask(self, text: str, matches: List[PIIMatch]) -> Tuple[str, List[PIIMatch]]:
        if not matches:
            return text, []
        updated: List[PIIMatch] = []
        result = text
        for match in sorted(matches, key=lambda item: item.start, reverse=True):
            raw = match.snippet
            masked = self._mask_value(raw, match.pii_type)
            result = result[:match.start] + masked + result[match.end:]
            match.masked = masked
            match.fingerprint = self._fingerprint(raw)
            match.snippet = f"[REDACTED:{match.pii_type}]"
            updated.append(match)
        updated.reverse()
        return result, updated

    def _mask_value(self, value: str, pii_type: str) -> str:
        if self.cfg.MASK_STYLE == "full":
            return self.cfg.MASK_CHAR * len(value)
        if self.cfg.MASK_STYLE == "hash":
            return f"<{pii_type}:{self._fingerprint(value)[:12]}>"
        keep = max(0, self.cfg.MASK_KEEP_LAST)
        if len(value) <= keep:
            return self.cfg.MASK_CHAR * len(value)
        return self.cfg.MASK_CHAR * (len(value) - keep) + value[-keep:]

    def _fingerprint(self, value: str) -> str:
        # A keyed digest allows correlation without storing the secret itself.
        return hmac.new(self._fingerprint_key, value.encode("utf-8"), hashlib.sha256).hexdigest()
