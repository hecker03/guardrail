# guardrail/layer2_isolation/models.py

from enum import Enum
from typing import List, Dict, Optional
from pydantic import BaseModel, Field


class IsolationAction(str, Enum):
    PASS = "pass"
    ISOLATED = "isolated"
    REJECTED = "rejected"


class IntegrityStatus(str, Enum):
    VERIFIED = "verified"
    MISMATCH = "mismatch"
    EXPIRED = "expired"
    MISSING = "missing"
    INVALID_FORMAT = "invalid_format"


class RoleBlock(BaseModel):
    """A single role-delimited block in the isolated prompt."""

    role: str
    content: str
    privilege: int
    hmac_signature: Optional[str] = None
    token_estimate: int = 0


class IsolationResult(BaseModel):
    """Output of Layer 2 context isolation."""

    isolated_prompt: str
    action: IsolationAction
    integrity_status: IntegrityStatus
    system_prompt_hash: str
    signature: str
    nonce: str
    timestamp: int

    # Metadata
    role_blocks: List[RoleBlock] = Field(default_factory=list)
    total_tokens_estimate: int = 0
    boundaries_enforced: int = 0

    # Forensic
    warnings: List[str] = Field(default_factory=list)
    rejected_reason: Optional[str] = None
    processing_time_ms: Optional[float] = None