# guardrail/api/routes/classify.py

from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from guardrail.layer4_classifier import GuardRailClassifier

router = APIRouter(prefix="/v1/classify", tags=["layer4"])
_classifier = None


def get_classifier():
    global _classifier
    if _classifier is None:
        _classifier = GuardRailClassifier()
    return _classifier


class ClassifyRequest(BaseModel):
    text: str
    explain: bool = False


@router.post("")
async def classify_endpoint(req: ClassifyRequest):
    classifier = get_classifier()
    result = classifier.classify(req.text, explain=req.explain)
    return result.model_dump()
