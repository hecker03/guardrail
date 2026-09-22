# guardrail/api/routes/pipeline.py

import time
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional

from guardrail.layer1_sanitization import InputSanitizer, SanitizationAction
from guardrail.layer2_isolation import (
    ContextIsolator, RoleBlock, IsolationAction,
)
from guardrail.layer4_classifier import GuardRailClassifier
from guardrail.layer5_output_filter import OutputFilter, FilterAction

router = APIRouter(prefix="/v1/pipeline", tags=["pipeline"])

_sanitizer = InputSanitizer()
_isolator = ContextIsolator()
_classifier = GuardRailClassifier()
_output_filter = OutputFilter()


class PipelineRequest(BaseModel):
    system_prompt: str
    user_message: str
    model_output: Optional[str] = None   # if you already called the LLM


class PipelineResponse(BaseModel):
    request_id: str
    action: str
    sanitization: dict
    isolation: dict
    classification: dict
    output_filter: Optional[dict] = None
    total_latency_ms: float


@router.post("", response_model=PipelineResponse)
async def run_pipeline(req: PipelineRequest):
    t0 = time.perf_counter()
    import uuid
    req_id = str(uuid.uuid4())

    # ---- L1: Sanitize ----
    s1 = _sanitizer.sanitize(req.user_message)
    if s1.action == SanitizationAction.REJECTED:
        raise HTTPException(400, detail={
            "request_id": req_id,
            "layer": "L1",
            "reason": "sanitization_rejected",
            "score": s1.threat_score,
        })

    # ---- L2: Isolate ----
    s2 = _isolator.quick_isolate(
        system_prompt=req.system_prompt,
        user_message=s1.sanitized_text,
    )
    if s2.action == IsolationAction.REJECTED:
        raise HTTPException(400, detail={
            "request_id": req_id,
            "layer": "L2",
            "reason": s2.rejected_reason,
        })

    # ---- L4: Classify ----
    s4 = _classifier.classify(s1.sanitized_text, explain=True)
    if s4.label != "S0" and s4.confidence > 0.85:
        raise HTTPException(400, detail={
            "request_id": req_id,
            "layer": "L4",
            "label": s4.label,
            "confidence": s4.confidence,
            "xai": s4.xai.model_dump() if s4.xai else None,
        })

    # ---- L5: Filter output (if provided) ----
    s5 = None
    if req.model_output:
        s5 = _output_filter.filter(
            output=req.model_output,
            system_prompt=req.system_prompt,
            user_input=s1.sanitized_text,
        )
        if s5.action == FilterAction.BLOCKED:
            raise HTTPException(400, detail={
                "request_id": req_id,
                "layer": "L5",
                "reason": "exfiltration_blocked",
                "exfil_reasons": s5.exfil_reasons,
            })

    return PipelineResponse(
        request_id=req_id,
        action="allowed",
        sanitization=s1.model_dump(),
        isolation=s2.model_dump(),
        classification=s4.model_dump(),
        output_filter=s5.model_dump() if s5 else None,
        total_latency_ms=round((time.perf_counter() - t0) * 1000, 3),
    )