# guardrail/layer4_classifier/taxonomy.py

from enum import Enum
from typing import Dict, List


class AttackLabel(str, Enum):
    """
    GuardRail S1–S4 prompt-injection taxonomy.

    S0 = Benign (no attack)
    S1 = Direct Instruction Override
    S2 = Role / Persona Hijack
    S3 = Context / Data Injection (RAG poisoning, delimiter smuggling)
    S4 = Exfiltration / Tool Abuse (data theft, unauthorized tool calls)
    """
    S0_BENIGN = "S0"
    S1_OVERRIDE = "S1"
    S2_ROLE_HIJACK = "S2"
    S3_CONTEXT_INJECTION = "S3"
    S4_EXFILTRATION = "S4"


LABEL2ID: Dict[str, int] = {
    AttackLabel.S0_BENIGN.value: 0,
    AttackLabel.S1_OVERRIDE.value: 1,
    AttackLabel.S2_ROLE_HIJACK.value: 2,
    AttackLabel.S3_CONTEXT_INJECTION.value: 3,
    AttackLabel.S4_EXFILTRATION.value: 4,
}

ID2LABEL: Dict[int, str] = {v: k for k, v in LABEL2ID.items()}

NUM_LABELS: int = len(LABEL2ID)

LABEL_DESCRIPTIONS: Dict[str, str] = {
    "S0": "Benign input — no malicious intent detected.",
    "S1": "Direct instruction override — 'ignore previous instructions', DAN, jailbreak.",
    "S2": "Role/persona hijack — 'you are now X', impersonation, authority spoofing.",
    "S3": "Context/data injection — RAG poisoning, delimiter smuggling, hidden Unicode.",
    "S4": "Exfiltration/tool abuse — API-key theft, unauthorized tool invocation.",
}

# Severity mapping (used by downstream layers)
LABEL_SEVERITY: Dict[str, float] = {
    "S0": 0.0,
    "S1": 0.6,
    "S2": 0.7,
    "S3": 0.85,
    "S4": 1.0,
}