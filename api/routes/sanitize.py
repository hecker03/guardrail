from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from guardrail.api.runtime import sanitizer
from guardrail.layer1_sanitization import SanitizationAction
import uuid
from guardrail.api.monitoring import monitoring_store

router = APIRouter(prefix="/v1/sanitize", tags=["layer1"])


class SanitizeRequest(BaseModel):
    text: str = Field(max_length=32_001)


@router.post("")
async def sanitize_endpoint(req: SanitizeRequest):
    result = sanitizer.sanitize(req.text)
    request_id = str(uuid.uuid4())

    await monitoring_store.record(
        request_id=request_id,
        layer="L1",
        label=(
            result.patterns_matched[0]
            if result.patterns_matched
            else result.action.value
        ),
        score=result.threat_score,
        latency_ms=result.processing_time_ms or 0.0,
        action=result.action.value,
        payload={
            "patterns": result.patterns_matched,
            "transformations": result.transformations,
            "removed_unicode_tags": result.removed_unicode_tags,
            "removed_zero_width": result.removed_zero_width,
        },
    )

    if result.action == SanitizationAction.REJECTED:
        raise HTTPException(status_code=400, detail={
            "error": "input_rejected",
            "threat_level": result.threat_level.value,
            "score": result.threat_score,
            "patterns": result.patterns_matched,
            "original_sha256": result.original_sha256,
        })
    return result.model_dump()
