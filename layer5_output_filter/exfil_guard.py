import re
from typing import List, Tuple
from urllib.parse import urlsplit, urlunsplit
from .config import OutputFilterConfig, DEFAULT_CONFIG


class ExfiltrationGuard:
    """Detect textual exfiltration indicators; this is not a network firewall."""

    URL_RE = re.compile(r"https?://[^\s)\]\"'>]+", re.IGNORECASE)
    MD_IMAGE_RE = re.compile(r"!\[[^\]]*\]\((https?://[^)]+)\)", re.IGNORECASE)
    DATA_URI_RE = re.compile(r"data:[a-z]+/[a-z0-9.+-]+;base64,", re.IGNORECASE)
    B64_BLOB_RE = re.compile(r"\b[A-Za-z0-9+/]{200,}={0,2}\b")
    HEX_BLOB_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}){100,}\b")

    def __init__(self, config: OutputFilterConfig = DEFAULT_CONFIG):
        self.cfg = config
        self.allowlist = {host.lower().rstrip(".") for host in config.EXFIL_URL_ALLOWLIST}

    def scan(self, output: str, user_input: str = "") -> Tuple[float, List[str], List[str]]:
        if not output:
            return 0.0, [], []
        score = 0.0
        reasons: List[str] = []
        blocked: List[str] = []

        if self.cfg.BLOCK_MARKDOWN_IMAGES:
            for match in self.MD_IMAGE_RE.finditer(output):
                url = match.group(1)
                if not self._is_allowed(url):
                    reasons.append("markdown_image_beacon")
                    blocked.append(url)
                    score = max(score, 0.9)

        if self.cfg.BLOCK_DATA_URIS and self.DATA_URI_RE.search(output):
            reasons.append("data_uri")
            score = max(score, 0.9)

        for match in self.URL_RE.finditer(output):
            url = match.group(0)
            if self._is_allowed(url):
                continue
            blocked.append(url)
            if re.search(r"[?&](data|token|key|secret|pii)=", url, re.I):
                reasons.append("url_with_sensitive_parameter")
                score = max(score, 0.95)
            else:
                reasons.append("untrusted_outbound_url")
                score = max(score, 0.4)

        if self.B64_BLOB_RE.search(output):
            reasons.append("large_base64_blob")
            score = max(score, 0.7)
        if self.HEX_BLOB_RE.search(output):
            reasons.append("large_hex_blob")
            score = max(score, 0.7)

        if user_input:
            for match in self.URL_RE.finditer(output):
                url = match.group(0)
                if url in user_input and not self._is_allowed(url):
                    reasons.append("user_supplied_url_in_output")
                    score = max(score, 0.85)

        return score, sorted(set(reasons)), list(dict.fromkeys(blocked))

    def _is_allowed(self, url: str) -> bool:
        try:
            parts = urlsplit(url)
            host = (parts.hostname or "").lower().rstrip(".")
            if parts.scheme.lower() not in {"http", "https"} or not host:
                return False
            return any(host == allowed or host.endswith("." + allowed) for allowed in self.allowlist)
        except ValueError:
            return False

    @staticmethod
    def safe_url(url: str) -> str:
        """Retain origin/path for audit while removing query values and fragments."""
        try:
            parts = urlsplit(url)
            query = "[REDACTED]" if parts.query else ""
            return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))
        except ValueError:
            return "[MALFORMED_URL]"
