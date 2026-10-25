from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from guardrail.api.monitoring import record_layer_result
from guardrail.api.runtime import output_filter
from guardrail.layer5_output_filter import FilterAction

router = APIRouter(prefix="/v1/filter", tags=["layer5"])


class FilterRequest(BaseModel):
    output: str = Field(max_length=100_000)
    # Prompt is accepted here only for standalone Layer-5 testing. In the
    # integrated pipeline it comes from protected server configuration.
    system_prompt: str = Field(default="", max_length=20_000)
    user_input: str = Field(default="", max_length=32_000)


@router.post("")
async def filter_endpoint(req: FilterRequest, request: Request):
    result = output_filter.filter(req.output, req.system_prompt, req.user_input)
    record_layer_result(
        request,
        layer="L5",
        action=result.action.value,
        score=result.exfil_risk_score,
        labels=result.exfil_reasons,
    )
    if result.action == FilterAction.BLOCKED:
        raise HTTPException(status_code=400, detail={
            "error": "output_blocked",
            "exfil_reasons": result.exfil_reasons,
            "blocked_urls": result.blocked_urls,
        })
    return result.model_dump()
