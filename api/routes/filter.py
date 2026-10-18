# guardrail/api/routes/filter.py

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from guardrail.layer5_output_filter import OutputFilter, FilterAction

router = APIRouter(prefix="/v1/filter", tags=["layer5"])
_filter = OutputFilter()


class FilterRequest(BaseModel):
    output: str
    system_prompt: Optional[str] = ""
    user_input: Optional[str] = ""


@router.post("")
async def filter_endpoint(req: FilterRequest):
    result = _filter.filter(
        output=req.output,
        system_prompt=req.system_prompt or "",
        user_input=req.user_input or "",
    )

    if result.action == FilterAction.BLOCKED:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "output_blocked",
                "exfil_reasons": result.exfil_reasons,
                "blocked_urls": result.blocked_urls,
            },
        )

    return result.model_dump()
