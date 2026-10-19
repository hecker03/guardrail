# guardrail/layer2_isolation/config.py

from dataclasses import dataclass, field
from typing import Dict, FrozenSet


@dataclass(frozen=True)
class IsolationConfig:
    """Configuration for Layer 2 Context Isolation."""

    # ---- HMAC ----
    HMAC_ALGORITHM: str = "sha256"
    HMAC_KEY_BYTES: int = 32                    # 256-bit key
    HMAC_SIGNATURE_LENGTH: int = 64             # hex chars (sha256 = 32 bytes)
    HMAC_NONCE_BYTES: int = 16                  # per-request nonce
    HMAC_TIMESTAMP_TOLERANCE_SEC: int = 300     # 5-min replay window

    # ---- Prompt hashing ----
    PROMPT_HASH_ALGO: str = "sha256"
    INCLUDE_NONCE_IN_HASH: bool = True
    INCLUDE_TIMESTAMP_IN_HASH: bool = True

    # ---- XML role delimiters ----
    ROLE_TAG_PREFIX: str = "guardrail"
    ROLE_TAG_SUFFIX: str = "guardrail"
    ESCAPE_XML_CONTENT: bool = True
    STRIP_NESTED_ROLE_TAGS: bool = True         # prevent delimiter injection

    # ---- Allowed roles ----
    ALLOWED_ROLES: FrozenSet[str] = field(default_factory=lambda: frozenset({
        "system",
        "user",
        "assistant",
        "tool",
        "retrieved_context",
    }))

    # ---- Privilege levels (higher = more trusted) ----
    ROLE_PRIVILEGE: Dict[str, int] = field(default_factory=lambda: {
        "system": 100,
        "assistant": 80,
        "tool": 50,
        "retrieved_context": 20,
        "user": 10,
    })

    # ---- Behavior ----
    REJECT_ON_HMAC_MISMATCH: bool = True
    REJECT_ON_UNKNOWN_ROLE: bool = True
    MAX_ROLE_BLOCKS: int = 50
    MAX_SYSTEM_PROMPT_LENGTH: int = 20_000


DEFAULT_CONFIG = IsolationConfig()