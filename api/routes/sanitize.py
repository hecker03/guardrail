# guardrail/api/routes/sanitize.py

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from guardrail.layer1_sanitization import InputSanitizer, SanitizationAction

router = APIRouter(prefix="/v1/sanitize", tags=["layer1"])
_sanitizer = InputSanitizer()


class SanitizeRequest(BaseModel):
    text: str


@router.post("")
async def sanitize_endpoint(req: SanitizeRequest):
    result = _sanitizer.sanitize(req.text)

    if result.action == SanitizationAction.REJECTED:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "input_rejected",
                "threat_level": result.threat_level.value,
                "score": result.threat_score,
                "patterns": result.patterns_matched,
            },
        )

    return result.model_dump()
