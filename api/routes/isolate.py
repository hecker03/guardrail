# guardrail/api/routes/isolate.py

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from guardrail.layer2_isolation import (
    ContextIsolator, RoleBlock, IsolationAction,
)

router = APIRouter(prefix="/v1/isolate", tags=["layer2"])
_isolator = ContextIsolator()   # Load secret_key from env/KMS in prod


class RoleBlockIn(BaseModel):
    role: str
    content: str


class IsolateRequest(BaseModel):
    blocks: List[RoleBlockIn]
    signature: Optional[str] = None
    nonce: Optional[str] = None
    timestamp: Optional[int] = None


@router.post("")
async def isolate_endpoint(req: IsolateRequest):
    blocks = [
        RoleBlock(
            role=b.role,
            content=b.content,
            privilege=_isolator.roles.privilege_of(b.role),
        )
        for b in req.blocks
    ]

    result = _isolator.isolate(
        blocks,
        inbound_signature=req.signature,
        inbound_nonce=req.nonce,
        inbound_timestamp=req.timestamp,
    )

    if result.action == IsolationAction.REJECTED:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "context_rejected",
                "reason": result.rejected_reason,
                "warnings": result.warnings,
            },
        )

    return result.model_dump()
