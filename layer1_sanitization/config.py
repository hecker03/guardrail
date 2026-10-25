from dataclasses import dataclass, field
from typing import FrozenSet, Optional


@dataclass(frozen=True)
class SanitizationConfig:
    """Configuration for bounded Layer 1 canonicalisation and inspection."""

    UNICODE_TAG_START: int = 0xE0000
    UNICODE_TAG_END: int = 0xE007F
    VS_SUPPLEMENT_START: int = 0xE0100
    VS_SUPPLEMENT_END: int = 0xE01EF

    # Always unsafe/invisible formatting characters. ZWJ/ZWNJ are handled
    # contextually because they are meaningful in Indic and other scripts.
    ZERO_WIDTH_CHARS: FrozenSet[str] = field(default_factory=lambda: frozenset({
        "\u200B", "\u2060", "\uFEFF", "\u00AD", "\u180E",
        "\u2061", "\u2062", "\u2063", "\u2064",
    }))
    LANGUAGE_JOINERS: FrozenSet[str] = field(default_factory=lambda: frozenset({
        "\u200C", "\u200D",
    }))
    BIDI_CONTROLS: FrozenSet[str] = field(default_factory=lambda: frozenset({
        "\u202A", "\u202B", "\u202C", "\u202D", "\u202E",
        "\u2066", "\u2067", "\u2068", "\u2069",
    }))

    MAX_INPUT_LENGTH: int = 32_000
    MAX_ZERO_WIDTH_RATIO: float = 0.05
    MAX_HOMOGLYPH_RATIO: float = 0.15
    MAX_DECODE_CANDIDATES: int = 8
    MAX_DECODED_CHARS: int = 4_096

    STRIP_OR_FLAG: str = "sanitize"       # sanitize | reject
    NORMALIZE_UNICODE: bool = True
    INSPECT_ENCODINGS: bool = True
    SUSPICIOUS_TOKEN_DICTIONARY_PATH: Optional[str] = None
    LOG_SANITIZED_CONTENT: bool = False


DEFAULT_CONFIG = SanitizationConfig()
