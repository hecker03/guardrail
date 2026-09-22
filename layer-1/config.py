# guardrail/layer1_sanitization/config.py

from dataclasses import dataclass, field
from typing import FrozenSet


@dataclass(frozen=True)
class SanitizationConfig:
    """Configuration for Layer 1 Input Sanitization."""

    # ---- Unicode ranges to strip ----
    # Unicode Tag block: used to hide invisible instructions
    UNICODE_TAG_START: int = 0xE0000
    UNICODE_TAG_END: int = 0xE007F

    # Variation Selectors Supplement (can encode hidden data)
    VS_SUPPLEMENT_START: int = 0xE0100
    VS_SUPPLEMENT_END: int = 0xE01EF

    # ---- Zero-width / invisible characters ----
    ZERO_WIDTH_CHARS: FrozenSet[str] = field(default_factory=lambda: frozenset({
        "\u200B",  # Zero Width Space
        "\u200C",  # Zero Width Non-Joiner
        "\u200D",  # Zero Width Joiner
        "\u2060",  # Word Joiner
        "\uFEFF",  # Byte Order Mark / Zero Width No-Break Space
        "\u00AD",  # Soft Hyphen
        "\u180E",  # Mongolian Vowel Separator
        "\u2061",  # Function Application
        "\u2062",  # Invisible Times
        "\u2063",  # Invisible Separator
        "\u2064",  # Invisible Plus
    }))

    # ---- Bidi control characters (used in spoofing attacks) ----
    BIDI_CONTROLS: FrozenSet[str] = field(default_factory=lambda: frozenset({
        "\u202A", "\u202B", "\u202C", "\u202D", "\u202E",  # LRE RLE PDF LRO RLO
        "\u2066", "\u2067", "\u2068", "\u2069",            # LRI RLI FSI PDI
    }))

    # ---- Thresholds ----
    MAX_INPUT_LENGTH: int = 32_000          # hard cap before processing
    MAX_ZERO_WIDTH_RATIO: float = 0.05      # >5% zero-width → suspicious
    MAX_NON_ASCII_RATIO: float = 0.40       # >40% non-ASCII → flag
    MAX_HOMOGLYPH_RATIO: float = 0.15       # >15% confusables → flag

    # ---- Behavior flags ----
    STRIP_OR_FLAG: str = "sanitize"         # "sanitize" | "reject"
    NORMALIZE_UNICODE: bool = True          # Apply NFKC
    LOG_SANITIZED_CONTENT: bool = False     # Never log raw PII in prod


DEFAULT_CONFIG = SanitizationConfig()