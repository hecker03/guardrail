from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class IsolationAction(str, Enum):
    PASS = "pass"
    ISOLATED = "isolated"
    REJECTED = "rejected"


class IntegrityStatus(str, Enum):
    GENERATED = "generated"          # locally signed, not an inbound verification
    VERIFIED = "verified"
    MISMATCH = "mismatch"
    EXPIRED = "expired"
    REPLAYED = "replayed"
    MISSING = "missing"
    INVALID_FORMAT = "invalid_format"


class RoleBlock(BaseModel):
    role: str
    content: str
    privilege: int
    source: str = "unknown"
    trust_tier: str = "untrusted"
    hmac_signature: Optional[str] = None
    token_estimate: int = 0


class IsolationResult(BaseModel):
    isolated_prompt: str
    action: IsolationAction
    integrity_status: IntegrityStatus
    system_prompt_hash: str
    envelope_hash: str = ""
    signature: str
    nonce: str
    timestamp: int
    envelope_version: str = "1.0"
    request_id: str = ""
    session_id: str = ""
    policy_version: str = "phase1-v1"
    capability_scope: List[str] = Field(default_factory=list)

    role_blocks: List[RoleBlock] = Field(default_factory=list)
    total_tokens_estimate: int = 0
    boundaries_enforced: int = 0
    warnings: List[str] = Field(default_factory=list)
    rejected_reason: Optional[str] = None
    processing_time_ms: Optional[float] = None
