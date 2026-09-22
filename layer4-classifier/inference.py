# guardrail/layer4_classifier/inference.py

import os
import time
import torch
from typing import Optional, Dict, List
from transformers import AutoTokenizer

from .config import DEFAULT_CONFIG
from .model import DeBERTaGuardRail
from .taxonomy import ID2LABEL, LABEL_SEVERITY
from .lime_explainer import LIMETokenExplainer
from .models import ClassificationResult, XAIExplanation


class GuardRailClassifier:
    """
    Layer 4 — Production inference wrapper.

    Loads fine-tuned DeBERTa from checkpoint, classifies input into S0–S4,
    and optionally generates LIME token-level explanations.
    """

    def __init__(
        self,
        checkpoint_dir: Optional[str] = None,
        config=DEFAULT_CONFIG,
        enable_xai: bool = True,
    ):
        self.cfg = config
        self.ckpt = checkpoint_dir or config.CHECKPOINT_DIR
        self.device = torch.device(
            config.DEVICE if torch.cuda.is_available() else "cpu"
        )

        # ---- Load tokenizer + encoder ----
        self.tokenizer = AutoTokenizer.from_pretrained(self.ckpt)
        self.model = DeBERTaGuardRail(config).to(self.device)

        head_path = os.path.join(self.ckpt, "head.pt")
        if os.path.exists(head_path):
            self.model.load_state_dict(torch.load(head_path, map_location=self.device))
        else:
            print("[classifier] WARNING: no head.pt found — using random head")

        self.model.eval()

        # ---- XAI ----
        self.enable_xai = enable_xai
        self.lime = (
            LIMETokenExplainer(self.model, self.tokenizer, config, self.device)
            if enable_xai else None
        )

    # ------------------------------------------------------------------ #
    # Inference
    # ------------------------------------------------------------------ #
    @torch.no_grad()
    def classify(
        self,
        text: str,
        explain: bool = False,
    ) -> ClassificationResult:
        start = time.perf_counter()

        enc = self.tokenizer(
            text,
            truncation=True,
            padding=True,
            max_length=self.cfg.MAX_LENGTH,
            return_tensors="pt",
        ).to(self.device)

        logits = self.model(enc["input_ids"], enc["attention_mask"])["logits"]
        probs = torch.softmax(logits, dim=-1).cpu().numpy()[0]

        pred_id = int(probs.argmax())
        confidence = float(probs[pred_id])
        label = ID2LABEL[pred_id]

        # Confidence threshold → fallback to S0
        if confidence < self.cfg.CONFIDENCE_THRESHOLD:
            label = "S0"
            pred_id = 0
            confidence = float(probs[0])

        severity = LABEL_SEVERITY.get(label, 0.0)

        # ---- LIME (optional, expensive) ----
        xai: Optional[XAIExplanation] = None
        if explain and self.lime:
            lime_out = self.lime.explain(text)
            xai = XAIExplanation(
                predicted_label=lime_out["predicted_label"],
                confidence=lime_out["confidence"],
                token_attributions=lime_out["explanations"].get(label, []),
            )

        elapsed_ms = (time.perf_counter() - start) * 1000

        return ClassificationResult(
            label=label,
            confidence=round(confidence, 4),
            severity=severity,
            all_probabilities={
                ID2LABEL[i]: round(float(probs[i]), 4)
                for i in range(len(probs))
            },
            xai=xai,
            processing_time_ms=round(elapsed_ms, 3),
        )

    # ------------------------------------------------------------------ #
    # Batch inference
    # ------------------------------------------------------------------ #
    @torch.no_grad()
    def classify_batch(self, texts: List[str]) -> List[ClassificationResult]:
        return [self.classify(t) for t in texts]