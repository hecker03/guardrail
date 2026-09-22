# guardrail/layer4_classifier/models.py

from typing import Dict, List, Optional, Tuple
from pydantic import BaseModel, Field


class XAIExplanation(BaseModel):
    predicted_label: str
    confidence: float
    token_attributions: List[Tuple[str, float]] = Field(default_factory=list)


class ClassificationResult(BaseModel):
    label: str                          # S0–S4
    confidence: float = Field(ge=0.0, le=1.0)
    severity: float = Field(ge=0.0, le=1.0)
    all_probabilities: Dict[str, float] = Field(default_factory=dict)
    xai: Optional[XAIExplanation] = None
    processing_time_ms: Optional[float] = None