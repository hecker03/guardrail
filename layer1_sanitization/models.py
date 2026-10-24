from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class ThreatLevel(str, Enum):
    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SanitizationAction(str, Enum):
    PASS = "pass"
    SANITIZED = "sanitized"
    FLAGGED = "flagged"          # candidate requires contextual review
    REJECTED = "rejected"        # hard reject; do not continue processing


class LexicalFindingResult(BaseModel):
    """Serializable lexical candidate, not a maliciousness verdict.

    ``start``/``end`` and token indexes are relative to ``source_view``. For
    decoded views they are not offsets into the raw user prompt.
    """

    rule_id: str
    start: int
    end: int
    token_start: int
    token_end: int
    match_basis: List[str] = Field(default_factory=list)
    requires_context: bool = True
    source_view: str = "normalized"


class SanitizationResult(BaseModel):
    original_length: int
    sanitized_text: str
    action: SanitizationAction
    threat_level: ThreatLevel
    threat_score: float = Field(ge=0.0, le=1.0)

    removed_unicode_tags: int = 0
    removed_zero_width: int = 0
    removed_bidi_controls: int = 0
    removed_control_chars: int = 0
    preserved_join_controls: int = 0
    homoglyphs_detected: Dict[str, str] = Field(default_factory=dict)
    patterns_matched: List[str] = Field(default_factory=list)
    decoded_views_scanned: List[str] = Field(default_factory=list)
    lexical_findings: List[LexicalFindingResult] = Field(default_factory=list)
    requires_context: bool = False
    transformations: List[str] = Field(default_factory=list)
    original_sha256: str = ""
    sanitized_sha256: str = ""
    warnings: List[str] = Field(default_factory=list)
    processing_time_ms: Optional[float] = None
