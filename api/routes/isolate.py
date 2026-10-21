from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional
from guardrail.api.runtime import isolator
from guardrail.layer2_isolation import RoleBlock, IsolationAction
from guardrail.api.monitoring import monitoring_store

router = APIRouter(prefix="/v1/isolate", tags=["layer2"])


class RoleBlockIn(BaseModel):
    role: str
    content: str


class IsolateRequest(BaseModel):
    blocks: List[RoleBlockIn] = Field(min_length=1, max_length=50)
    signature: Optional[str] = None
    nonce: Optional[str] = None
    timestamp: Optional[int] = None
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    capability_scope: List[str] = Field(default_factory=list, max_length=50)
    policy_version: str = Field(default="phase1-v1", max_length=100)


@router.post("")
async def isolate_endpoint(req: IsolateRequest):
    blocks = [RoleBlock(
        role=block.role,
        content=block.content,
        privilege=isolator.roles.privilege_of(block.role),
        source="api_client",
        trust_tier="untrusted",
    ) for block in req.blocks]
    result = isolator.isolate(
        blocks,
        inbound_signature=req.signature,
        inbound_nonce=req.nonce,
        inbound_timestamp=req.timestamp,
        request_id=req.request_id,
        session_id=req.session_id,
        capability_scope=req.capability_scope,
        policy_version=req.policy_version,
    )
    await monitoring_store.record(
        request_id=result.request_id or req.request_id or "unknown",
        layer="L2",
        label=result.integrity_status.value,
        score=(
            1.0
            if result.action == IsolationAction.REJECTED
            else 0.0
        ),
        latency_ms=result.processing_time_ms or 0.0,
        action=result.action.value,
        payload={
            "integrity_status": result.integrity_status.value,
            "warnings": result.warnings,
            "boundaries_enforced": result.boundaries_enforced,
            "policy_version": result.policy_version,
        },
    )
    if result.action == IsolationAction.REJECTED:
        raise HTTPException(status_code=400, detail={
            "error": "context_rejected",
            "reason": result.rejected_reason,
            "integrity_status": result.integrity_status.value,
            "warnings": result.warnings,
        })
    return result.model_dump()