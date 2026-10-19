# guardrail/layer4_classifier/__init__.py

from .inference import GuardRailClassifier
from .model import DeBERTaGuardRail
from .taxonomy import AttackLabel, LABEL2ID, ID2LABEL, LABEL_SEVERITY
from .models import ClassificationResult, XAIExplanation
from .config import ClassifierConfig, DEFAULT_CONFIG

__all__ = [
    "GuardRailClassifier",
    "DeBERTaGuardRail",
    "AttackLabel",
    "LABEL2ID",
    "ID2LABEL",
    "LABEL_SEVERITY",
    "ClassificationResult",
    "XAIExplanation",
    "ClassifierConfig",
    "DEFAULT_CONFIG",
]