import time
import uuid
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from typing import List, Optional

from guardrail.api.monitoring import record_layer_result
from guardrail.api.runtime import (
    sanitizer, isolator, output_filter, TRUSTED_SYSTEM_PROMPT,
    ALLOW_CLIENT_SYSTEM_PROMPT,
)
from guardrail.layer1_sanitization import SanitizationAction
from guardrail.layer2_isolation import IsolationAction
from guardrail.layer5_output_filter import FilterAction

router = APIRouter(prefix="/v1/pipeline", tags=["pipeline"])
_classifier = None


def get_classifier():
    # Lazy loading keeps verified L1/L2/L5 endpoints usable independently.
    # Layer 4 itself is intentionally unchanged in this hardening pass.
    global _classifier
    if _classifier is None:
        from guardrail.layer4_classifier import GuardRailClassifier
        _classifier = GuardRailClassifier()
    return _classifier


class PipelineRequest(BaseModel):
    user_message: str = Field(max_length=32_001)
    model_output: Optional[str] = Field(default=None, max_length=100_000)
    system_prompt: Optional[str] = Field(default=None, max_length=20_000)
    session_id: Optional[str] = Field(default=None, max_length=200)
    capability_scope: List[str] = Field(default_factory=list, max_length=50)


class PipelineResponse(BaseModel):
    request_id: str
    action: str
    sanitization: dict
    isolation: dict
    classification: dict
    output_filter: Optional[dict] = None
    total_latency_ms: float


@router.post("", response_model=PipelineResponse)
async def run_pipeline(req: PipelineRequest, request: Request):
    started = time.perf_counter()
    request_id = getattr(request.state, "guardrail_request_id", None) or str(uuid.uuid4())

    if req.system_prompt is not None and not ALLOW_CLIENT_SYSTEM_PROMPT:
        record_layer_result(
            request, layer="L2", action="rejected",
            labels=["client_system_prompt_not_allowed"],
        )
        raise HTTPException(400, detail={
            "request_id": request_id,
            "layer": "L2",
            "reason": "client_system_prompt_not_allowed",
        })
    system_prompt = req.system_prompt if ALLOW_CLIENT_SYSTEM_PROMPT and req.system_prompt else TRUSTED_SYSTEM_PROMPT

    s1 = sanitizer.sanitize(req.user_message)
    record_layer_result(
        request,
        layer="L1",
        action=s1.action.value,
        score=s1.threat_score,
        labels=s1.patterns_matched,
    )
    if s1.action == SanitizationAction.REJECTED:
        raise HTTPException(400, detail={
            "request_id": request_id, "layer": "L1",
            "reason": "sanitization_rejected", "score": s1.threat_score,
            "patterns": s1.patterns_matched,
        })

    # The Layer-3 contextual decision stage is not configured on this route.
    # Hold any candidate before isolation/classification or a model-facing path.
    if s1.action == SanitizationAction.FLAGGED or s1.requires_context:
        raise HTTPException(409, detail={
            "request_id": request_id,
            "layer": "L1",
            "reason": "lexical_candidate_requires_context",
            "patterns": s1.patterns_matched,
            "lexical_findings": [finding.model_dump() for finding in s1.lexical_findings],
        })

    s2 = isolator.quick_isolate(
        system_prompt=system_prompt,
        user_message=s1.sanitized_text,
        request_id=request_id,
        session_id=req.session_id,
        capability_scope=req.capability_scope,
    )
    record_layer_result(
        request,
        layer="L2",
        action=s2.action.value,
        labels=[s2.integrity_status.value],
    )
    if s2.action == IsolationAction.REJECTED:
        raise HTTPException(400, detail={
            "request_id": request_id, "layer": "L2", "reason": s2.rejected_reason,
        })

    # Existing Layer 4 integration retained; expensive LIME is not run on the
    # normal synchronous path. No Layer-4 model/training claims are added here.
    s4 = get_classifier().classify(s1.sanitized_text, explain=False)
    record_layer_result(
        request,
        layer="L4",
        action="classified",
        score=s4.confidence,
        labels=[s4.label],
    )
    if s4.label != "S0" and s4.confidence > 0.85:
        raise HTTPException(400, detail={
            "request_id": request_id, "layer": "L4",
            "label": s4.label, "confidence": s4.confidence,
        })

    s5 = None
    if req.model_output is not None:
        s5 = output_filter.filter(req.model_output, system_prompt, s1.sanitized_text)
        record_layer_result(
            request,
            layer="L5",
            action=s5.action.value,
            score=s5.exfil_risk_score,
            labels=s5.exfil_reasons,
        )
        if s5.action == FilterAction.BLOCKED:
            raise HTTPException(400, detail={
                "request_id": request_id, "layer": "L5",
                "reason": "textual_exfiltration_indicator_blocked",
                "exfil_reasons": s5.exfil_reasons,
            })

    return PipelineResponse(
        request_id=request_id,
        action="allowed",
        sanitization=s1.model_dump(),
        isolation=s2.model_dump(),
        classification=s4.model_dump(),
        output_filter=s5.model_dump() if s5 else None,
        total_latency_ms=round((time.perf_counter() - started) * 1000, 3),
    )
