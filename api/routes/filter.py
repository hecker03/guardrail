from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from guardrail.api.runtime import output_filter
from guardrail.layer5_output_filter import FilterAction
import uuid
from guardrail.api.monitoring import monitoring_store

router = APIRouter(prefix="/v1/filter", tags=["layer5"])


class FilterRequest(BaseModel):
    output: str = Field(max_length=100_000)
    # Prompt is accepted here only for standalone Layer-5 testing. In the
    # integrated pipeline it comes from protected server configuration.
    system_prompt: str = Field(default="", max_length=20_000)
    user_input: str = Field(default="", max_length=32_000)


@router.post("")
async def filter_endpoint(req: FilterRequest):
    result = output_filter.filter(req.output, req.system_prompt, req.user_input)

    request_id = str(uuid.uuid4())
    await monitoring_store.record(
        request_id=request_id,
        layer="L5",
        label=(
            result.exfil_reasons[0]
            if result.exfil_reasons
            else "pii_redaction"
            if result.pii_count
            else result.action.value
        ),
        score=result.exfil_risk_score,
        latency_ms=result.processing_time_ms or 0.0,
        action=result.action.value,
        payload={
            "pii_count": result.pii_count,
            "pii_types": result.pii_types,
            "echo_detected": result.echo_detected,
            "exfil_reasons": result.exfil_reasons,
        },
    )

    if result.action == FilterAction.BLOCKED:
        raise HTTPException(status_code=400, detail={
            "error": "output_blocked",
            "exfil_reasons": result.exfil_reasons,
            "blocked_urls": result.blocked_urls,
        })
    return result.model_dump()