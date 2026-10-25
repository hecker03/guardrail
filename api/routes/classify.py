from fastapi import APIRouter, Request
from pydantic import BaseModel, Field
from guardrail.api.monitoring import record_layer_result

router = APIRouter(prefix="/v1/classify", tags=["layer4"])
_classifier = None


def get_classifier():
    global _classifier
    if _classifier is None:
        from guardrail.layer4_classifier import GuardRailClassifier
        _classifier = GuardRailClassifier()
    return _classifier


class ClassifyRequest(BaseModel):
    text: str = Field(max_length=32_000)
    explain: bool = False


@router.post("")
async def classify_endpoint(req: ClassifyRequest, request: Request):
    result = get_classifier().classify(req.text, explain=req.explain)
    record_layer_result(
        request,
        layer="L4",
        action="classified",
        score=result.confidence,
        labels=[result.label],
    )
    return result.model_dump()
