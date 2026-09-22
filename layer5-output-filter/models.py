# guardrail/layer5_output_filter/models.py

from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class FilterAction(str, Enum):
    PASS = "pass"
    REDACTED = "redacted"
    BLOCKED = "blocked"


class PIIMatch(BaseModel):
    pii_type: str
    start: int
    end: int
    snippet: str
    masked: str


class OutputFilterResult(BaseModel):
    filtered_text: str
    action: FilterAction

    # PII
    pii_matches: List[PIIMatch] = Field(default_factory=list)
    pii_count: int = 0
    pii_types: Dict[str, int] = Field(default_factory=dict)

    # Echo
    echo_detected: bool = False
    echo_similarity: float = 0.0

    # Exfiltration
    exfil_risk_score: float = 0.0
    exfil_reasons: List[str] = Field(default_factory=list)
    blocked_urls: List[str] = Field(default_factory=list)

    # Forensic
    original_length: int = 0
    filtered_length: int = 0
    warnings: List[str] = Field(default_factory=list)
    processing_time_ms: Optional[float] = None