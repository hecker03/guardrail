from enum import Enum
from typing import List, Dict, Optional
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
    REJECTED = "rejected"


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
    transformations: List[str] = Field(default_factory=list)
    original_sha256: str = ""
    sanitized_sha256: str = ""
    warnings: List[str] = Field(default_factory=list)
    processing_time_ms: Optional[float] = None
