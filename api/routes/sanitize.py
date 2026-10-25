from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from guardrail.api.monitoring import record_layer_result
from guardrail.api.runtime import sanitizer
from guardrail.layer1_sanitization import SanitizationAction

router = APIRouter(prefix="/v1/sanitize", tags=["layer1"])


class SanitizeRequest(BaseModel):
    text: str = Field(max_length=32_001)


@router.post("")
async def sanitize_endpoint(req: SanitizeRequest, request: Request):
    result = sanitizer.sanitize(req.text)
    record_layer_result(
        request,
        layer="L1",
        action=result.action.value,
        score=result.threat_score,
        labels=result.patterns_matched,
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
